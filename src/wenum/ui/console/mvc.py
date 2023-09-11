import datetime
import shutil
import sys
import time
from collections import defaultdict
import threading
from wenum.factories.fuzzresfactory import resfactory

from itertools import zip_longest

from wenum.fuzzobjects import FuzzWordType, FuzzResult, FuzzStats

from .term import Term
from wenum import __version__ as version
from wenum.plugin_api.urlutils import parse_url
import wenum.ui.console.kbhit as kbhit
from .output import wrap_always_list
from ...myqueues import FuzzQueue

usage = """\r\n
Interactive keyboard commands:\r\n
h: Show this help

p: Pause
s: Show stats
d: Show debug stats
r: Show all seeds/recursions that have been queued
"""


class SimpleEventDispatcher:
    def __init__(self):
        self.publisher = defaultdict(list)

    def create_event(self, msg):
        self.publisher[msg] = []

    def subscribe(self, func, msg, dynamic=False):
        if msg not in self.publisher and not dynamic:
            raise KeyError("subscribe. No such event: %s" % msg)
        else:
            self.publisher[msg].append(func)

    def notify(self, msg, **event):
        if msg not in self.publisher:
            raise KeyError("notify. Event not subscribed: %s" % msg)
        else:
            for functor in self.publisher[msg]:
                functor(**event)


class KeyPress(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.inkey = kbhit.KBHit()
        self.name = "KeyPress"

        self.dispatcher = SimpleEventDispatcher()
        self.dispatcher.create_event("h")
        self.dispatcher.create_event("p")
        self.dispatcher.create_event("s")
        self.dispatcher.create_event("r")
        self.dispatcher.create_event("d")

        self.do_job = True

    def cancel_job(self):
        self.do_job = False

    def run(self):
        while self.do_job:
            if self.inkey.kbhit():
                pressed_char = self.inkey.getch()
                if pressed_char == "p":
                    self.dispatcher.notify("p", key="p")
                elif pressed_char == "s":
                    self.dispatcher.notify("s", key="s")
                elif pressed_char == "h":
                    self.dispatcher.notify("h", key="h")
                elif pressed_char == "r":
                    self.dispatcher.notify("r", key="r")
                elif pressed_char == "d":
                    self.dispatcher.notify("d", key="d")


class Controller:
    def __init__(self, fuzzer, view: KeyPress):
        self.fuzzer = fuzzer
        self.printer_queue: FuzzQueue = self.fuzzer.qmanager["printer_cli"]
        self.view = view
        self.__paused = False
        self.stats: FuzzStats = fuzzer.session.compiled_stats

        self.view.dispatcher.subscribe(self.on_help, "h")
        self.view.dispatcher.subscribe(self.on_pause, "p")
        self.view.dispatcher.subscribe(self.on_stats, "s")
        self.view.dispatcher.subscribe(self.on_seeds, "r")
        self.view.dispatcher.subscribe(self.on_debug, "d")
        self.term = Term(fuzzer.session)

    def on_help(self, **event):
        message_fuzzresult: FuzzResult = resfactory.create("fuzzres_from_message", usage)
        self.printer_queue.put_important(message_fuzzresult)

    def on_pause(self, **event):
        self.__paused = not self.__paused
        if self.__paused:
            self.fuzzer.pause_job()
            print()
            message = self.term.color_string(self.term.fgYellow, "\nPausing requests. Already enqueued requests "
                                                                  "may still get printed out during pause.")
            message += "\nType h to see all options."
            message_fuzzresult: FuzzResult = resfactory.create("fuzzres_from_message", message)
            self.printer_queue.put_important(message_fuzzresult)
        else:
            message = self.term.color_string(self.term.fgGreen, "Resuming execution...")
            message_fuzzresult: FuzzResult = resfactory.create("fuzzres_from_message", message)
            self.printer_queue.put_important(message_fuzzresult)
            self.fuzzer.resume_job()

    def on_stats(self, **event):
        message = self.generate_stats()
        message_fuzzresult: FuzzResult = resfactory.create("fuzzres_from_message", message)
        self.printer_queue.put_important(message_fuzzresult)

    def on_debug(self, **event):
        message = self.generate_debug_stats()
        message_fuzzresult: FuzzResult = resfactory.create("fuzzres_from_message", message)
        self.printer_queue.put_important(message_fuzzresult)

    def on_seeds(self, **event):
        message_fuzzresult: FuzzResult = resfactory.create("fuzzres_from_message", self.generate_seed_message())
        self.printer_queue.put_important(message_fuzzresult)

    def generate_debug_stats(self):
        message = "\n=============== Debug ===================\n"
        stats = self.fuzzer.stats()
        for k, v in list(stats.items()):
            message += f"{k}: {v}\n"
        message += "\n=========================================\n"
        return message

    def generate_stats(self):
        pending_requests = self.stats.total_req - self.stats.processed()
        pending_seeds = self.stats.pending_seeds()
        stats = self.stats
        message = f"""\nRequests Per Seed: {str(stats.wordlist_req)}
Pending Requests: {str(pending_requests)}
Pending Seeds: {str(pending_seeds)}\n"""

        if stats.backfeed() > 0:
            message += f"""Total Backfed/Plugin Requests: {stats.backfeed()}
Processed Requests: {(str(stats.processed())[:8])}
Filtered Requests: {(str(stats.filtered())[:8])}\n"""
        totaltime = time.time() - stats.starttime
        req_sec = (stats.processed() / totaltime if totaltime > 0 else 0)
        totaltime_formatted = datetime.timedelta(seconds=int(totaltime))
        message += f"Total Time: {str(totaltime_formatted)}\n"
        if req_sec > 0:
            message += f"Requests/Sec.: {str(req_sec)[:8]}\n"
            eta = pending_requests / req_sec
            if eta > 60:
                message += f"ET Left Min.: {str(eta / 60)[:8]}\n"
            else:
                message += f"ET Left Sec.: {str(eta)[:8]}\n"
        return message

    def generate_seed_message(self):
        """Print information about currently queued seeds"""
        seed_list_len = str(len(self.stats.seed_list))
        colored_length = self.term.color_string(self.term.fgYellow, seed_list_len)
        seed_message = f"In total, {colored_length} seeds have been generated. List of seeds:\n"
        colored_url_list = "[ "
        parsed_initial_url = parse_url(self.stats.url)
        for seed_url in self.stats.seed_list:
            parsed_seed_url = parse_url(seed_url)
            seed_url = seed_url
            scheme = parsed_seed_url.scheme
            netloc = parsed_seed_url.netloc
            # Only color the scheme and netloc if they are different from the initial ones
            if scheme != parsed_initial_url.scheme:
                colored_scheme = self.term.color_string(self.term.fgYellow, scheme)
                seed_url.replace(parsed_seed_url.scheme, colored_scheme)
            if netloc != parsed_initial_url.netloc:
                colored_netloc = self.term.color_string(self.term.fgYellow, netloc)
                seed_url.replace(parsed_seed_url.netloc, colored_netloc)
            colored_path = self.term.color_string(self.term.fgYellow, parsed_seed_url.path)
            seed_url = seed_url.replace(parsed_seed_url.path, colored_path)
            # Imitating the look of a list when printed out. Reason for not simply using a list is because the terminal
            # does not properly handle the Colour codes when using lists
            colored_url_list += "'" + seed_url + "', "

        colored_url_list += "]"
        seed_message += colored_url_list
        return seed_message


class View:
    """
    Class handling the CLI output
    """
    # Result number, status code, lines, words, chars, method, url
    result_row_widths = [10, 8, 6, 8, 10, 6, shutil.get_terminal_size(fallback=(80, 25))[0] - 66]
    verbose_result_row_widths = [10, 10, 8, 8, 6, 9, 30, 30, shutil.get_terminal_size(fallback=(80, 25))[0] - 145]

    def __init__(self, session):
        self.last_discarded_result = None
        self.verbose = session.options.verbose
        self.term = Term(session)
        # Keeps track of the line count of the print for discarded responses (to then overwrite these lines with the
        # next print)
        self.printed_temp_lines = 0

    def _print_result_verbose(self, fuzz_result: FuzzResult, print_nres=True):
        txt_color = self.term.noColour

        if fuzz_result.history.redirect_header:
            location = fuzz_result.history.full_redirect_url
            url_output = f"{fuzz_result.url} -> {location}"
        else:
            url_output = fuzz_result.url
            location = ""

        server = ""
        if "Server" in fuzz_result.history.headers.response:
            server = fuzz_result.history.headers.response["Server"]

        columns = [
            ("%09d:" % fuzz_result.result_number if print_nres else " |_", txt_color),
            ("%.3fs" % fuzz_result.timer, txt_color),
            (
                "%s" % str(fuzz_result.code) if not fuzz_result.exception else "XXX",
                self.term.get_color(fuzz_result.code),
            ),
            ("%d L" % fuzz_result.lines, txt_color),
            ("%d W" % fuzz_result.words, txt_color),
            ("%d Ch" % fuzz_result.chars, txt_color),
            (server, txt_color),
            (location, txt_color),
            (f'"{url_output}"' if not fuzz_result.exception else f'"{fuzz_result.url}"', txt_color),
        ]

        self.term.set_color(txt_color)
        printed_lines = self._print_line(columns, self.verbose_result_row_widths)
        if fuzz_result.discarded:
            self.printed_temp_lines += printed_lines

    def _print_header(self, columns, max_widths):
        print("=" * (3 * len(max_widths) + sum(max_widths[:-1]) + 10))
        self._print_line(columns, max_widths)
        print("=" * (3 * len(max_widths) + sum(max_widths[:-1]) + 10))
        print("")

    def _print_line(self, columns: list[tuple[str, str]], max_widths: list[int]) -> int:
        """
        Takes columns, which are tuples of message(0) and color_code(1), and a list of respective widths for
        the columns, prints them and returns the amount of lines printed.
        Function suitable any time there is a column separated line to be printed out. color_code(1) will
        color the entire column.
        Manually inserting ANSI color codes within message(0) will instead cause buggy behavior.
        """

        def wrap_columns(columns: list[tuple[str, str]], max_widths: list[int]) -> list[list[str]]:
            """Takes all columns and wraps them depending on their respective max_width value. Returns a list
            containing a list of the columns, whereas each inner list represents a full line.
            E.g. simplified, if one row was [ ('123456', ''), ('abc', '') ], the max_widths [ 3, 3 ] may wrap it
            to [ [ '123', 'abc' ], [ '456', '' ] ]"""
            wrapped_columns = [
                wrap_always_list(item[0], width) for item, width in zip(columns, max_widths)
            ]
            return [[substr or "" for substr in item] for item in zip_longest(*wrapped_columns)]

        def print_columns(column: list[str], columns: list[tuple[str, str]]):
            """Prints a line consisting of columns with the entries separated by a few whitespaces. Needs the
            columns object to access the color code attributed to the column to be printed out"""
            sys.stdout.write(
                "   ".join(
                    [
                        color + str.ljust(str(item), width) + self.term.reset
                        for (item, width, color) in zip(
                            column, max_widths, [color[1] for color in columns]
                        )
                    ]
                )
            )

        wrapped_columns = wrap_columns(columns, max_widths)

        for line in wrapped_columns:
            print_columns(line, columns)
            sys.stdout.write("\r\n")

        sys.stdout.flush()
        return len(wrapped_columns)

    def _print_result(self, fuzz_result: FuzzResult, print_nres=True):
        """
        Function to print out the result by taking a FuzzResult. print_nres is a bool that indicates whether the
        result number should be added to the row.
        """
        if fuzz_result.history.redirect_header:
            location = fuzz_result.history.full_redirect_url
            url_output = f"{fuzz_result.url} -> {location}"
        else:
            url_output = fuzz_result.url
        txt_color = self.term.noColour

        # Each column consists of a tuple storing both the string and the associated color of the column
        columns = [
            ("%09d:" % fuzz_result.result_number if print_nres else " |_", txt_color),
            ("%s" % str(fuzz_result.code) if not fuzz_result.exception else "XXX",
             self.term.get_color(fuzz_result.code)),
            ("%d L" % fuzz_result.lines, txt_color),
            ("%d W" % fuzz_result.words, txt_color),
            ("%d Ch" % fuzz_result.chars, txt_color),
            ('%s' % fuzz_result.history.method, txt_color),
            (f'"{url_output}"' if not fuzz_result.exception
             else f'"{fuzz_result.url}"', txt_color),
        ]

        self.term.set_color(txt_color)
        printed_lines = self._print_line(columns, self.result_row_widths)
        if fuzz_result.discarded:
            self.printed_temp_lines += printed_lines

    def header(self, summary):
        """Prints the wenum header"""
        exec_banner = """********************************************************\r
* wenum {version} - A Web Fuzzer {align: <{width1}}*\r
********************************************************\r\n""".format(
            version=version, align=" ", width1=22 - len(version)
        )
        print(exec_banner)
        if summary:
            print("Target: %s\r" % summary.url)
            if summary.wordlist_req > 0:
                print("Total requests: %d\r\n" % summary.wordlist_req)
            else:
                print("Total requests: <<unknown>>\r\n")

        uncolored = self.term.noColour

        if self.verbose:
            columns = [
                ("ID", uncolored),
                ("C.Time", uncolored),
                ("Response", uncolored),
                ("Lines", uncolored),
                ("Word", uncolored),
                ("Chars", uncolored),
                ("Server", uncolored),
                ("Redirect", uncolored),
                ("URL", uncolored),
            ]

            widths = self.verbose_result_row_widths
        else:
            columns = [
                ("ID", uncolored),
                ("Response", uncolored),
                ("Lines", uncolored),
                ("Word", uncolored),
                ("Chars", uncolored),
                ("Method", uncolored),
                ("URL", uncolored),
            ]

            widths = self.result_row_widths

        self._print_header(columns, widths)

    def remove_temp_lines(self):
        """Remove the footer from the CLI."""
        if self.printed_temp_lines:
            self.term.erase_lines(self.printed_temp_lines)

    def append_temp_lines(self, stats):
        """Append the footer, which is a separator with the last discarded line"""
        terminal_size = shutil.get_terminal_size(fallback=(80, 25))
        print(f"")
        green_processed = self.term.color_string(self.term.fgGreen, str(stats.processed()))
        yellow_total = self.term.color_string(self.term.fgYellow, str(stats.total_req))
        # Careful with this print! For this to work as it does right now, the code simply assumes
        # this line will not be longer than a single line, statically setting the total printed temp lines.
        # It currently is short enough to guarantee that in any reasonable terminal size.
        # Should the message ever be made longer, some logic should dynamically
        # calculate how many lines the message will really occupy.
        print(f"Processed {green_processed}/{yellow_total} requests")
        self.printed_temp_lines = 3
        # If there is no discarded result yet, just return, otherwise print it as well
        if not self.last_discarded_result:
            return
        if self.verbose:
            self.verbose_result_row_widths = [10, 10, 8, 8, 6, 9, 30, 30, terminal_size[0] - 145]
            self._print_result_verbose(self.last_discarded_result)
        else:
            self.result_row_widths = [10, 8, 6, 8, 10, 6, terminal_size[0] - 66]
            self._print_result(self.last_discarded_result)

    def print_result(self, fuzz_result: FuzzResult):
        """Print the result to CLI"""
        if not fuzz_result.discarded:

            # Print result
            if self.verbose:
                self.verbose_result_row_widths = [10, 10, 8, 8, 6, 9, 30, 30,
                                                  shutil.get_terminal_size(fallback=(80, 25))[0] - 145]
                self._print_result_verbose(fuzz_result)
            else:
                self.result_row_widths = [10, 8, 6, 8, 10, 6, shutil.get_terminal_size(fallback=(80, 25))[0] - 66]
                self._print_result(fuzz_result)

            # Print plugin results
            if fuzz_result.plugins_res:
                for plugin_res in fuzz_result.plugins_res:
                    if not plugin_res.is_visible() and not self.verbose:
                        continue
                    print(f" |_  {plugin_res.message}")

            if fuzz_result.exception:
                print(f" |_ ERROR: {fuzz_result.exception}")
        else:
            self.last_discarded_result = fuzz_result

    @staticmethod
    def footer(summary):
        """Function called when ending the runtime, prints a summary"""
        sys.stdout.write("\n\r")

        print(summary)
