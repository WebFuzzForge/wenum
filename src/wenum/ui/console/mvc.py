import datetime
import time
from collections import defaultdict
import threading

import rich.console
from rich.columns import Columns
from rich.text import Text

from wenum.factories.fuzzresfactory import resfactory

from wenum.fuzzobjects import FuzzWordType, FuzzResponse, FuzzStats
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table, Column
from rich.console import Console

from wenum import __version__ as version
from wenum.plugin_api.urlutils import parse_url
import wenum.ui.console.kbhit as kbhit
from ...myqueues import FuzzQueue

usage = """Interactive keyboard commands:\r\n
h: Show this help

p: Pause
s: Show stats
d: Show debug stats
r: Show all seeds/recursions that have been queued"""


class SimpleEventDispatcher:
    """
    Class responsible for listening for an event (e.g. keypress)
    """

    def __init__(self):
        self.publisher = defaultdict(list)

    def create_event(self, msg):
        """
        Create a listener for the provided keypress
        """
        self.publisher[msg] = []

    def subscribe(self, func, msg, dynamic=False):
        """
        Bind the execution of a method (func) to the provided keypress (msg)
        """
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
    """
    Class responsible for catching keyboard inputs during runtime
    """

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
    """
    Class responsible for converting caught keyboard inputs into execution of methods
    """

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

    def on_help(self, **event):
        self.fuzzer.session.console.rule("Usage", style="yellow")
        self.fuzzer.session.console.print(usage)
        self.fuzzer.session.console.rule(style="yellow")

    def on_pause(self, **event):
        self.__paused = not self.__paused
        if self.__paused:
            self.fuzzer.pause_job()
            self.fuzzer.session.console.rule("'P' pressed - pausing requests.", style="yellow")
        else:
            self.fuzzer.session.console.rule("Resuming execution...", style="yellow")
            self.fuzzer.resume_job()

    def on_stats(self, **event):
        pending_requests = self.stats.total_req - self.stats.processed()
        pending_seeds = self.stats.pending_seeds()
        stats = self.stats
        message = f"""Requests Per Seed: {str(stats.wordlist_req)}
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
                message += f"ET Left Min.: {str(eta / 60)[:8]}"
            else:
                message += f"ET Left Sec.: {str(eta)[:8]}"

        self.fuzzer.session.console.rule("Runtime stats", style="yellow")
        self.fuzzer.session.console.print(message)
        self.fuzzer.session.console.rule(style="yellow")

    def on_debug(self, **event):
        """
        Print some debug information
        """
        message = ""
        stats = self.fuzzer.stats()
        for key, value in list(stats.items()):
            message += f"{key}: {value}\n"
        message = message.rstrip("\n")
        self.fuzzer.session.console.rule("Debug stats", style="yellow")
        self.fuzzer.session.console.print(message)
        self.fuzzer.session.console.rule(style="yellow")

    def on_seeds(self, **event):
        """Print information about currently queued seeds"""
        seed_list_len = str(len(self.stats.seed_list))
        seed_message = f"In total, {seed_list_len} seeds have been generated. List of seeds:\n"
        colored_url_list = "[ "
        parsed_initial_url = parse_url(self.stats.url)
        for seed_url in self.stats.seed_list:
            parsed_seed_url = parse_url(seed_url)
            seed_url = seed_url
            scheme = parsed_seed_url.scheme
            netloc = parsed_seed_url.netloc
            # Only color the scheme and netloc if they are different from the initial ones
            if scheme != parsed_initial_url.scheme:
                colored_scheme = "[yellow]" + scheme + "[/yellow]"
                seed_url.replace(parsed_seed_url.scheme, colored_scheme)
            if netloc != parsed_initial_url.netloc:
                colored_netloc = "[yellow]" + netloc + "[/yellow]"
                seed_url.replace(parsed_seed_url.netloc, colored_netloc)
            colored_path = "[yellow]" + parsed_seed_url.path + "[/yellow]"
            seed_url = seed_url.replace(parsed_seed_url.path, colored_path)
            # Imitating the look of a list when printed out. Reason for not simply using a list is because the terminal
            # does not properly handle the Colour codes when using lists
            colored_url_list += "'" + seed_url + "', "

        colored_url_list += "]"
        seed_message += colored_url_list
        self.fuzzer.session.console.rule("Seed stats", style="yellow")
        self.fuzzer.session.console.print(seed_message)
        self.fuzzer.session.console.rule(style="yellow")


class View:
    """
    Class handling the CLI output
    """

    # Static column lengths
    fuzzresult_row_widths: dict = {
        "response_time": 5,
        "server": 12,
        "http_code": 4,
        "lines": 7,
        "words": 8,
        "size": 10,
        "http_method": 7,
    }

    def __init__(self, session):
        self.verbose = session.options.verbose
        self.console: Console = session.console

        # Progress bar
        self.next_task = self._get_next_task()
        if not session.options.quiet:
            # Processed responses
            self.overall_progress: Progress = Progress(
                SpinnerColumn(table_column=Column(justify="left", ratio=1)),
                TextColumn("{task.fields[processed]}", justify="center", table_column=Column(justify="left", ratio=2)),
                TextColumn("/", justify="center", table_column=Column(justify="center", ratio=1)),
                TextColumn("{task.fields[total_req]}", justify="center", table_column=Column(justify="right", ratio=2)),
                transient=True
            )
            filtered_columns = (TextColumn("{task.fields[http_code]}",
                                           table_column=Column(min_width=self.fuzzresult_row_widths["http_code"],
                                                               max_width=self.fuzzresult_row_widths["http_code"],
                                                               no_wrap=True)),
                                TextColumn("{task.fields[words]}",
                                           table_column=Column(min_width=self.fuzzresult_row_widths["words"],
                                                               max_width=self.fuzzresult_row_widths["words"],
                                                               no_wrap=True)),
                                TextColumn("{task.fields[lines]}",
                                           table_column=Column(min_width=self.fuzzresult_row_widths["lines"],
                                                               max_width=self.fuzzresult_row_widths["lines"],
                                                               no_wrap=True)),
                                TextColumn("{task.fields[size]}",
                                           table_column=Column(min_width=self.fuzzresult_row_widths["size"],
                                                               max_width=self.fuzzresult_row_widths["size"],
                                                               no_wrap=True)),
                                TextColumn("{task.fields[http_method]}",
                                           table_column=Column(min_width=self.fuzzresult_row_widths["http_method"],
                                                               max_width=self.fuzzresult_row_widths["http_method"],
                                                               no_wrap=True)),
                                TextColumn("{task.fields[endpoint]}",
                                           table_column=Column(no_wrap=False, overflow="ellipsis")))
            verbose_filtered_columns = (TextColumn("{task.fields[response_time]}",
                                                   table_column=Column(
                                                       min_width=self.fuzzresult_row_widths["response_time"],
                                                       max_width=self.fuzzresult_row_widths["response_time"],
                                                       no_wrap=True, overflow="crop")),
                                        TextColumn("{task.fields[server]}",
                                                   table_column=Column(
                                                       min_width=self.fuzzresult_row_widths["server"],
                                                       max_width=self.fuzzresult_row_widths["server"],
                                                       no_wrap=True))
                                        )
            # Filtered responses
            self.filtered_progress: Progress = Progress()
            self.filtered_progress.columns = verbose_filtered_columns + filtered_columns if self.verbose \
                else filtered_columns
            self.overall_task = self.overall_progress.add_task("Processed", processed=0, total_req=0)
            self.oldest_filtered_task = self.filtered_progress.add_task("oldest", http_code="", words="",
                                                                        lines="", size="", http_method="", endpoint="")
            self.middle_filtered_task = self.filtered_progress.add_task("middle", http_code="", words="",
                                                                        lines="", size="", http_method="", endpoint="")
            self.recent_filtered_task = self.filtered_progress.add_task("recent", http_code="", words="",
                                                                        lines="", size="", http_method="", endpoint="")

            progress_table = Table.grid()
            if session.options.noninteractive:
                subtitle = ""
            else:
                subtitle = "Press h for help"
            progress_table.add_row(
                Panel(
                    self.overall_progress, title="Processed", border_style="green", padding=(1, 1), expand=True,
                    subtitle=subtitle
                ),
                Panel(
                    self.filtered_progress, title="Filtered responses", border_style="red", padding=(0, 1), expand=True,
                )
            )
            progress_table.expand = True
            progress_table.columns[0].ratio = 5
            progress_table.columns[1].ratio = 20
            self.live = Live(progress_table, auto_refresh=True, console=self.console)

    def update_status(self, stats):
        """
        Updates the progress bar's values
        """
        self.overall_progress.update(self.overall_task, total_req=stats.total_req, processed=stats.processed())

    def update_filtered(self, fuzz_result: FuzzResponse):
        """
        Update the filtered bar's values with the provided discarded FuzzResult
        """
        server = ""
        if "Server" in fuzz_result.history.headers.response:
            server = fuzz_result.history.headers.response["Server"]

        self.filtered_progress.update(next(self.next_task), response_time=fuzz_result.timer, server=server,
                                      http_code=str(fuzz_result.code),
                                      lines=str(fuzz_result.lines) + " L",
                                      words=str(fuzz_result.words) + " W", size=str(fuzz_result.chars) + " B",
                                      http_method=fuzz_result.history.method, endpoint=fuzz_result.url)

    def _get_next_task(self):
        """
        Infinitely loops through the 3 tasks that display filtered results.
        """
        index = 0
        while True:
            if index == 0:
                yield self.recent_filtered_task
            elif index == 1:
                yield self.middle_filtered_task
            elif index == 2:
                yield self.oldest_filtered_task
            index += 1
            index = index % 3

    @staticmethod
    def get_opt_value(opt_value):
        """Returns the opt value if it exists, and the string None if not."""
        if opt_value:
            return Text(f"{opt_value}", overflow="fold", style="green")
        else:
            return Text("None", overflow="fold", style="dim")

    #        return Text(opt_value if opt_value else "None", overflow="fold")

    def header(self, stats: FuzzStats, session):
        """
        Prints the wenum header
        """
        self.console.rule(f"wenum {version} - A Web Fuzzer")

        option_panels = []
        for option_tuple in session.options.get_all_opts():
            option_panels.append(Panel(self.get_opt_value(option_tuple[1]),
                                       expand=True, width=30, title=option_tuple[0]))

        self.console.print(Columns(option_panels, title="Startup options", expand=True, equal=True),
                           overflow="crop", no_wrap=False)

        grid = self.create_response_grid("white")

        if self.verbose:
            grid.add_row("Timer", "Server",
                         "Code", "Lines", "Words", "Size", "Method", "URL")
        else:
            grid.add_row("Code", "Lines", "Words", "Size", "Method", "URL")

        self.console.print(grid)

    def print_result(self, fuzz_result: FuzzResponse) -> None:
        """
        Prints the FuzzResult in its designated grid format
        """

        if fuzz_result.history.redirect_header:
            location = fuzz_result.history.full_redirect_url
            url_output = f"[link={fuzz_result.url}]{fuzz_result.url}[/link] :right_arrow: [link={location}]{location}[/link]"
        else:
            url_output = f"[link={fuzz_result.url}]{fuzz_result.url}[/link]"

        server = ""
        if "Server" in fuzz_result.history.headers.response:
            server = fuzz_result.history.headers.response["Server"]

        if fuzz_result.exception:
            response_code = "XXX"
            response_code_color = "purple"
        else:
            response_code = fuzz_result.code
            response_code_color = self.get_response_code_color(response_code)

        grid = self.create_response_grid(response_code_color)

        # Add fuzz_result contents
        if self.verbose:
            grid.add_row(str(fuzz_result.timer), str(server),
                         str(response_code), str(fuzz_result.lines) + " L", str(fuzz_result.words) + " W",
                         str(fuzz_result.chars) + " B", fuzz_result.history.method, url_output)
        else:
            grid.add_row(str(response_code), str(fuzz_result.lines) + " L", str(fuzz_result.words) + " W",
                         str(fuzz_result.chars) + " B", fuzz_result.history.method, url_output)

        # Add plugin results
        if fuzz_result.plugins_res:
            plugin_grid = Table.grid(pad_edge=True, padding=(0, 1), collapse_padding=False)
            plugin_grid.add_column("name", min_width=20, max_width=20, no_wrap=False, overflow="fold")
            plugin_grid.add_column("message", no_wrap=False, overflow="fold")
            # Plugin rows should iterate colors for easier visual distinction
            color = True
            for plugin_res in fuzz_result.plugins_res:
                if not plugin_res.is_visible() and not self.verbose:
                    continue
                plugin_grid.add_row(f"[i]{plugin_res.name}[/i]:", plugin_res.message,
                                    style="orange3" if color else "deep_pink3")
                color = not color

            self.console.rule(f"[dim]Response number {fuzz_result.id}:[/dim]", style="dim green")
            self.console.print(grid, plugin_grid, soft_wrap=True)
        else:
            self.console.rule(f"[dim]Response number {fuzz_result.id}:[/dim]", style="dim green")
            self.console.print(grid, soft_wrap=True)

        # Add exception information
        if fuzz_result.exception:
            self.console.print(f" [b]ERROR[/b]: {fuzz_result.exception}")

    def create_response_grid(self, response_code_color: str) -> rich.table.Table:
        """
        Creates the grid format with which to print the response metrics
        """
        grid = Table.grid(pad_edge=True, padding=(0, 1), collapse_padding=False)

        if self.verbose:
            grid.add_column("Response Time", min_width=self.fuzzresult_row_widths["response_time"],
                            max_width=self.fuzzresult_row_widths["response_time"], no_wrap=False, overflow="crop")
            grid.add_column("Server", min_width=self.fuzzresult_row_widths["server"],
                            max_width=self.fuzzresult_row_widths["server"], no_wrap=False, overflow="fold")

        grid.add_column("HTTP Code", min_width=self.fuzzresult_row_widths["http_code"],
                        max_width=self.fuzzresult_row_widths["http_code"], no_wrap=False, overflow="fold")
        grid.add_column("Lines", min_width=self.fuzzresult_row_widths["lines"],
                        max_width=self.fuzzresult_row_widths["lines"], no_wrap=False, overflow="fold", justify="right")
        grid.add_column("Words", min_width=self.fuzzresult_row_widths["words"],
                        max_width=self.fuzzresult_row_widths["words"], no_wrap=False, overflow="fold", justify="right")
        grid.add_column("Size", min_width=self.fuzzresult_row_widths["size"],
                        max_width=self.fuzzresult_row_widths["size"], no_wrap=False, overflow="fold", justify="right")
        grid.add_column("HTTP Method", min_width=self.fuzzresult_row_widths["http_method"],
                        max_width=self.fuzzresult_row_widths["http_method"], no_wrap=False, overflow="fold")
        grid.add_column("URL", no_wrap=False, overflow="fold")

        # Set colors
        code_column_index = 0
        if self.verbose:
            grid.columns[0].style = "pale_green1"
            grid.columns[1].style = "sky_blue2"
            code_column_index = 2
        grid.columns[code_column_index].style = response_code_color
        grid.columns[code_column_index + 1].style = "magenta"
        grid.columns[code_column_index + 2].style = "cyan"
        grid.columns[code_column_index + 3].style = "yellow"
        grid.columns[code_column_index + 4].style = "slate_blue1"

        return grid

    @staticmethod
    def get_response_code_color(code: int):
        """
        Takes an HTTP response code (e.g. 302) and returns the color that it should be printed with on the CLI
        """
        # informational until 200, successful until 300
        if 100 <= code < 300:
            color = "green"
        # redirects
        elif 300 <= code < 400:
            color = "blue"
        # client errors until 500, server errors until 600
        elif 400 <= code < 600:
            color = "red"
        # undefined otherwise
        else:
            color = "white"

        return color

    def footer(self, summary):
        """Function called when ending the runtime, prints a summary"""
        self.console.print("")

        self.console.print(summary)
