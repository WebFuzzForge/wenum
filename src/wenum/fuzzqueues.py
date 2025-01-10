from __future__ import annotations

import logging
import pathlib
import warnings
from typing import TYPE_CHECKING

from urllib.parse import urljoin
from wenum.plugin_api.urlutils import parse_url
from os.path import basename
from .plugin_api.static_data import head_extensions

if TYPE_CHECKING:
    from wenum.runtime_session import FuzzSession
    from wenum.plugin_api.base import BasePlugin
    from wenum.printers import BasePrinter
    from wenum.externals.reqresp.cache import HttpCache
from threading import Thread, Event, Condition
from queue import Queue
from wenum.externals.reqresp.Response import get_encoding_from_headers

from .factories.fuzzresfactory import resfactory
from .factories.plugin_factory import plugin_factory
from .helpers.obj_dic import FixSizeOrderedDict
from .fuzzobjects import FuzzType, FuzzItem, FuzzWord, FuzzWordType, FuzzResult, FuzzPlugin
from .myqueues import FuzzQueue, FuzzListQueue
from .exception import (
    FuzzExceptInternalError,
    FuzzExceptBadOptions,
    FuzzExceptPluginLoadError,
)
from .filters.base_filter import BaseFilter
from .filters.complexfilter import FuzzResFilter
from .facade import Facade, ERROR_CODE
from .ui.console.mvc import View
import requests
import re


class SeedQueue(FuzzQueue):
    """
    Queue used by default, handles reading payloads from wordlists
    """

    def __init__(self, session: FuzzSession, extensions: list[str]):
        super().__init__(session)

        self.extensions = []

        for extension in extensions:
            ext = extension.split(",")
            for e in ext:
                self.extensions.append(e.strip())

    def get_name(self):
        return "SeedQueue"

    def items_to_process(self):
        return [FuzzType.STARTSEED, FuzzType.SEED]

    def send(self, item):
        if item and item.discarded:
            self.queue_discard.put(item)
        else:
            if self.queue_out.qsize() > (self.session.options.threads * 5):
                self.queue_out.receive_seed_queue.clear()
            self.queue_out.receive_seed_queue.wait()
            self.queue_out.put(item)

    def restart(self, seed: FuzzResult):
        """
        Assign the next seed that should be currently processed
        """
        self.session.compiled_seed = seed
        self.session.compile_iterator()

    def process(self, fuzz_item: FuzzItem):
        # STARTSEED used by the first item when wenum starts
        if fuzz_item.item_type == FuzzType.STARTSEED:
            self.add_initial_recursion_to_cache()
            self.stats.new_seed()
        elif fuzz_item.item_type == FuzzType.SEED:
            self.restart(fuzz_item)
        else:
            raise FuzzExceptInternalError("SeedQueue: Unknown item type in queue!")

        if self.session.options.limit_requests:
            if not self.session.http_pool.queued_requests > self.session.options.limit_requests:
                self.send_dictionary()
            else:
                self.end_seed()
        else:
            self.send_dictionary()

    def get_fuzz_res(self, dictio_item: tuple) -> FuzzResult:
        """
        Create FuzzResult object from FuzzWord
        """
        return resfactory.create(
            "fuzzres_from_options_and_dict", self.session, dictio_item
        )

    def add_initial_recursion_to_cache(self):
        """
        Since on startup there is always a recursion on the base FUZZ dir, it needs to be added to the cache
        to avoid e.g. plugins to enqueue a second recursion on it
        """
        key = self.session.options.url.replace("FUZZ", "")
        self.session.cache.check_cache(url_key=key, cache_type="recursion")

    def send_dictionary(self):
        """
        Send the requests of the wordlist
        """
        # Ensure that a request is sent to the base of the FUZZ path
        fuzz_word = (FuzzWord("", FuzzWordType.WORD),)
        fuzz_result = self.get_fuzz_res(fuzz_word)
        if not self.session.cache.check_cache(fuzz_result.url):
            self.stats.pending_fuzz.inc()
            self.send(fuzz_result)

        # Check if the payload dictionary is empty to begin with
        try:
            fuzz_word = next(self.session.compiled_iterator)
        except StopIteration:
            raise FuzzExceptBadOptions("Empty dictionary! Please check payload or filter.")

        # Enqueue requests
        try:
            while fuzz_word:
                if self.session.compiled_stats.cancelled:
                    break
                fuzz_result = self.get_fuzz_res(fuzz_word)
                # Only send out if it's not already in the cache
                if not self.session.cache.check_cache(fuzz_result.url):
                    self.stats.pending_fuzz.inc()
                    self.send(fuzz_result)

                # generate additional requests for the extensions
                for extension in self.extensions:
                    fuzz_word_ext = (FuzzWord(fuzz_word[0][0] + extension, FuzzWordType.WORD),)
                    fuzz_res_ext = self.get_fuzz_res(fuzz_word_ext)

                    if not self.session.cache.check_cache(fuzz_res_ext.url):
                        self.stats.pending_fuzz.inc()
                        self.send(fuzz_res_ext)

                fuzz_word = next(self.session.compiled_iterator)
        except StopIteration:
            pass

        self.end_seed()

    def end_seed(self):
        endseed_item = FuzzItem(item_type=FuzzType.ENDSEED)
        endseed_item.priority = self.session.compiled_seed.priority
        self.send_unimportant(endseed_item)


class CLIPrinterQueue(FuzzQueue):
    """
    Queue responsible for the outputs of the results. This queue will be active for "default" ways of using wenum to
    print to the CLI
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)
        # Listening for keypress to pause execution
        self.pause = Event()
        self.pause.set()

        self.cli = View(self.session)
        # Processes discarded results to print them to the progress bar
        self.process_discarded = True

    def pre_start(self):
        self.cli.header(self.stats, self.session)
        if not self.session.options.quiet:
            self.cli.live.start()

    def items_to_process(self):
        return [FuzzType.RESULT, FuzzType.MESSAGE]

    def get_name(self):
        return "CLIPrinterQueue"

    def cancel(self):
        self.cli.footer(self.stats)
        if not self.session.options.quiet:
            self.cli.live.stop()

    def process(self, fuzz_result: FuzzResult):
        self.pause.wait()
        if fuzz_result.item_type == FuzzType.MESSAGE:
            self.session.console.print(fuzz_result.rlevel_desc)
        elif not fuzz_result.discarded:
            self.cli.print_result(fuzz_result)

        # Progress bar
        if not self.session.options.quiet:
            self.cli.update_status(self.session.compiled_stats)
            if fuzz_result.discarded:
                self.cli.update_filtered(fuzz_result)

        self.send(fuzz_result)


class FilePrinterQueue(FuzzQueue):
    """
    Queue designed to print to files.
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)

        self.printer_list: list[BasePrinter] = session.compiled_printer_list
        for printer in self.printer_list:
            printer.header(self.stats)
        # Counter to reduce unnecessary amounts of writes. Write every x requests
        self.counter = 0
        self.process_discarded = True

    def get_name(self):
        return "FilePrinterQueue"

    def cancel(self):
        for printer in self.printer_list:
            printer.print_to_file()

    def process(self, fuzz_result: FuzzResult):
        if not fuzz_result.discarded:
            for printer in self.printer_list:
                printer.update_results(fuzz_result, self.stats)
            # It's not necessary to write to file every request. This counter reduces the frequency
            if self.counter > 100:
                self.counter = 0
                for printer in self.printer_list:
                    printer.print_to_file()

        self.counter += 1
        self.send(fuzz_result)


class RoutingQueue(FuzzQueue):
    """
    Queue active when recursion of some sort is possible (effectively either -R or --script (plugins) activated)
    Responsible for sending SEED and BACKFEED types of results to their corresponding queues.
    """

    def __init__(self, session: FuzzSession, routes):
        super().__init__(session)
        self.routes = routes

    def get_name(self):
        return "RoutingQueue"

    def items_to_process(self):
        return [FuzzType.SEED, FuzzType.BACKFEED]

    def process(self, fuzz_result: FuzzResult):
        if fuzz_result.item_type == FuzzType.SEED:
            priority_level = self.session.assign_next_priority_level()
            # New seeds get less priority. This way an order of execution is maintained, whereas
            # processing items from the seed before is preferred. Goes in steps of 10 to additionally
            # allow for fine-grained prioritization within the same seed
            fuzz_result.priority = priority_level
            self.stats.new_seed()
            self.session.compiled_stats.seed_list.append(fuzz_result.url)
            self.routes[FuzzType.SEED].put(fuzz_result)
        elif fuzz_result.item_type == FuzzType.BACKFEED:
            self.stats.new_backfeed()
            self.routes[FuzzType.BACKFEED].put(fuzz_result)
        else:
            self.send(fuzz_result)


class FilterQueue(FuzzQueue):
    """
    Queue designed to filter out unwanted requests
    """

    def __init__(self, session: FuzzSession, ffilter: BaseFilter):
        super().__init__(session)

        # ffilter either FuzzResFilter or FuzzResSimpleFilter, depending on what has been specified on cli
        self.ffilter: BaseFilter = ffilter

    def get_name(self):
        return "FilterQueue"

    def process(self, fuzz_result: FuzzResult):

        if self.ffilter.is_filtered(fuzz_result):
            self.discard(fuzz_result)
        else:
            self.send(fuzz_result)


class AutofilterQueue(FuzzQueue):
    """
    Queue activated with the autofilter option. During runtime, it will keep track of the most
    recent kinds of results within a path, and if they repeat too often, will discard those if they occur in that dir.
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)

        # The filter that gets adjusted during runtime
        self.filter = FuzzResFilter()
        # Tracks 15 identifiers from responses in total. If more are found, the oldest one gets removed by expiry (FIFO)
        self.response_tracker_dict = FixSizeOrderedDict(maximum_length=15)

    def get_name(self):
        return "AutofilterQueue"

    def process(self, fuzz_result: FuzzResult):

        # Successful HEAD requests should not be subject to getting autofiltered, and neither should errored requests
        if (fuzz_result.history.method == "HEAD" and fuzz_result.code == 200) or fuzz_result.code == ERROR_CODE:
            self.send(fuzz_result)
            return

        # Only process if there isn't a filter (yet) or isn't filtered out by the path's filter
        if not self.filter.filter_string or not self.filter.is_filtered(fuzz_result):
            self.update_response_tracker(fuzz_result)
            self.send(fuzz_result)
        else:
            self.discard(fuzz_result)

    def update_response_tracker(self, fuzz_result: FuzzResult):
        """
        Update the path's dict of how often a response has been seen
        """
        # The identifier is supposed to identify duplicate responses
        response_identifier = f"c={fuzz_result.code} and l={fuzz_result.lines} and w={fuzz_result.words}"
        try:
            self.response_tracker_dict[response_identifier] += 1
            # If it's been detected 10 times, it should be added to the filter
            if self.response_tracker_dict[response_identifier] >= 10:
                self.update_filter(fuzz_result, response_identifier)
                # Tracking a filtered response type is not necessary, therefore gets popped
                self.response_tracker_dict.pop(response_identifier)
            else:
                # When a hit is found, it should be moved to the beginning,
                # preventing it from getting popped right after
                self.response_tracker_dict.move_to_end(response_identifier)
        # If the identifier is not in the dict, simply set the counter to 1. Uncritical exception
        except KeyError:
            self.response_tracker_dict[response_identifier] = 1

    def update_filter(self, fuzz_result: FuzzResult, identifier: str):
        """
        Update the filter with the identifier of the response
        """
        filter_string = f"not ({identifier})"
        # If a filter already exists, add the next identifier as an additional filter condition.
        # Duplicate conditions should have no chance of occurring, as responses that already are added once
        # to the filter should start to get discarded from the beginning
        if not self.filter.filter_string:
            self.filter.filter_string = filter_string
        else:
            self.filter.filter_string = f"{self.filter.filter_string} and {filter_string}"
        if 300 <= fuzz_result.code < 400:
            redirect_string = ". Redirects will still be followed in the background."
        else:
            redirect_string = ""
        fuzz_result.plugins_res.append(
            plugin_factory.create("plugin_from_finding", self.get_name(),
                                  f"Recurring response detected. Filtering out "
                                  f"'[u]{identifier}[/u]'{redirect_string}", FuzzPlugin.INFO))


class PluginQueue(FuzzListQueue):
    """
    Queue responsible for handling plugins
    """

    def __init__(self, session: FuzzSession):
        # Check active plugins
        if not [plugin(session) for plugin in Facade().scripts.get_plugins(session.options.plugins_list)]:
            raise FuzzExceptBadOptions(
                "No plugin selected, check the --plugins option."
            )

        concurrent = session.options.plugin_threads
        # Creating several PluginExecutors to enable several requests to be processed by plugins simultaneously. Dynamically instantiating the plugins to ensure that each PluginExecutor receives its unique objects and avoid any concurrency issues 
        super().__init__(session, [PluginExecutor(session, [plugin(session) for plugin in Facade().scripts.get_plugins(session.options.plugins_list)]) for i in range(concurrent)])

    def get_name(self):
        return "PluginQueue"

    def process(self, fuzz_result: FuzzResult):
        self.send_to_any(fuzz_result)


class PluginExecutor(FuzzQueue):
    """
    Queue dedicated to handle the execution of plugins. Usually, several instances are created by PluginQueue.
    """

    def __init__(self, session: FuzzSession, active_plugins: list[BasePlugin]):
        super().__init__(session, maxsize=30)
        self.active_plugins: list[BasePlugin] = active_plugins
        self.cache: HttpCache = session.cache
        self.max_rlevel = session.options.recursion
        self.max_plugin_rlevel = session.options.plugin_recursion
        self.interrupt = Event()
        self.condition = Condition()

    def get_name(self) -> str:
        return "PluginExecutor"

    def cancel(self):
        """
        The main thread sets the interrupt. This will stop the PluginExecutor from waiting for all plugins to finish.
        Otherwise, stopping the runtime can take longer than necessary.
        """
        self.interrupt.set()
        with self.condition:
            self.condition.notify()

    def process(self, fuzz_result: FuzzResult) -> None:
        """
        Executes all the selected plugins for the fuzz result
        """
        if fuzz_result.exception:
            self.send(fuzz_result)
            return

        # Queue for storing the results of each plugin
        plugins_res_queue = Queue()
        # Keeps track of the amount of requests queued by each plugin for the request
        queued_dict: dict[dict[str, int]] = {}
        # Keeps track of all the plugins signal for completion
        plugin_signal_dict: dict = {}
        for plugin in self.active_plugins:
            plugin_finished = Event()
            if plugin.disabled or not plugin.validate(fuzz_result):
                continue
            # If plugin qualifies to run, add it to the dict to keep track of when it will finish
            plugin_signal_dict[plugin.name] = plugin_finished
            # If run_once is set, disable the plugin for remaining runs
            if plugin.run_once:
                plugin.disabled = True
            queued_dict[plugin.name] = {}
            queued_dict[plugin.name]["queued_requests"] = 0
            queued_dict[plugin.name]["queued_seeds"] = 0
            try:
                # Runs all the plugins, stores results in results_queue, and signals completion through
                # control queue
                thread = Thread(target=plugin.run, kwargs={"fuzz_result": fuzz_result,
                                                           "plugin_finished": plugin_finished,
                                                           "condition": self.condition,
                                                           "interrupt_signal": self.interrupt,
                                                           "results_queue": plugins_res_queue, }, )
                thread.daemon = True
            except Exception as e:
                raise FuzzExceptPluginLoadError(f"Error initialising plugin {plugin.name}: {str(e)}")
            thread.start()
        with self.condition:
            while True:
                # On interrupt, empty the plugin_res and close it
                if self.interrupt.is_set():
                    while not plugins_res_queue.empty():
                        plugins_res_queue.get()
                        plugins_res_queue.task_done()
                    plugins_res_queue.join()
                    break
                elif self.check_all_plugins_done(plugin_signal_dict):
                    self.process_results(fuzz_result, plugins_res_queue, queued_dict)
                    break
                else:
                    self.condition.wait()

        self.send(fuzz_result)

    @staticmethod
    def check_all_plugins_done(plugin_signal_dict: dict):
        """
        Simply method to check if all the plugins have signalled completion.
        Returns True if all are finished, and False if not all have finished.
        """
        for plugin_name, plugin_signal in plugin_signal_dict.items():
            if not plugin_signal.is_set():
                return False
        else:
            return True

    def process_results(self, fuzz_result: FuzzResult, plugins_res_queue: Queue,
                        queued_dict: dict) -> None:
        """
        Plugin results are polled from plugins_res_queue. Every plugin gets processed. Information gets appended
        to the fuzzresult on which the plugins ran, backfeed and seed objects are created if appropriate
        """
        # A URL could theoretically cause further backfeeds to be created indefinitely. Taking 15 as an arbitrary
        # value to avoid infinite backfeeds
        requeue_limit = 15
        # dict containing the plugin names and lists of urls that they wanted to generate which exceeded the limit
        limit_exceeded_urls: dict[str, list[str]] = {}

        # Every loop processes a single output of the plugins. One plugin can therefore trigger n loops by creating
        # n outputs, e.g. messages or new requests
        while not plugins_res_queue.empty():
            plugin: FuzzPlugin = plugins_res_queue.get()
            if plugin.exception:
                if self.session.options.stop_error:
                    self._throw(plugin.exception)

                fuzz_result.plugins_res.append(plugin)
            # If it's a message type simply append to the results
            elif plugin.message and plugin.is_visible():
                fuzz_result.plugins_res.append(plugin)
            # If it has a seed (BACKFEED/SEED) and goes over http
            elif plugin.seed and not self.session.options.dry_run:
                in_scope = fuzz_result.history.check_in_scope(plugin.seed.history.url, self.session.options.domain_scope)
                if not in_scope:
                    continue
                if plugin.seed.item_type == FuzzType.BACKFEED:
                    cache_type = "processed"
                    cached = self.cache.check_cache(plugin.seed.url, cache_type=cache_type, update=False)
                    if cached:
                        continue
                    if plugin.seed.backfeed_level >= requeue_limit:
                        limit_exceeded_urls.setdefault(plugin.name, []).append(
                            f"[link={plugin.seed.url}]{plugin.seed.url}[/link]")
                        continue

                    queued_dict[plugin.name]["queued_requests"] += 1
                elif plugin.seed.item_type == FuzzType.SEED:
                    cache_type = "recursion"
                    cached = self.cache.check_cache(plugin.seed.url, cache_type=cache_type, update=False)
                    if cached:
                        continue
                    # For SEED Plugin objects, the rlevel needs to be checked as well
                    if fuzz_result.plugin_rlevel >= self.max_plugin_rlevel:
                        continue
                    # If the URL is deemed a false positive, don't throw a recursion
                    elif RecursiveQueue.false_positive_hit(seed=plugin.seed, session=self.session, logger=self.logger):
                        continue
                    queued_dict[plugin.name]["queued_seeds"] += 1
                else:
                    warnings.warn(f"Invalid seed type detected: {plugin.seed.item_type}")
                    continue
                # Debugging information, prints out individual requests enqueued by each plugin
                # fuzz_result.plugins_res.append(plugin_factory.create(
                #    "plugin_from_finding", name=plugin.name,
                #    message=f"Plugin {plugin.name}: Enqueued {plugin.seed.url}",
                #    severity=FuzzPlugin.INFO))

                # Double-checking the cache. The previous cache checks help avoid extensive checks if it is
                # in the cache already, but a cache check right before sending the seed is necessary
                # to reduce race conditions (to fully prevent, cache needs to have threadlocks).
                if not self.cache.check_cache(plugin.seed.history.url, cache_type=cache_type, update=True):
                    self.send(plugin.seed)
            plugins_res_queue.task_done()
        # After all the individual results have been processed, print the amount of requests queued by each plugin
        for plugin_name, plugin_dict in queued_dict.items():
            # Only if the plugin queued a request at all
            if plugin_dict["queued_requests"]:
                multiple = "s" if plugin_dict["queued_requests"] > 1 else ""
                fuzz_result.plugins_res.append(plugin_factory.create(
                    "plugin_from_finding", name=plugin_name,
                    message=f"Enqueued [u]{plugin_dict['queued_requests']} request{multiple}[/u]",
                    severity=FuzzPlugin.INFO))
            # Only if the plugin queued a seed at all
            if plugin_dict["queued_seeds"]:
                multiple = "s" if plugin_dict["queued_seeds"] > 1 else ""
                fuzz_result.plugins_res.append(plugin_factory.create(
                    "plugin_from_finding", name=plugin_name,
                    message=f"Enqueued [u]{plugin_dict['queued_seeds']} seed{multiple}[/u]",
                    severity=FuzzPlugin.INFO))
        # Print the URLs that have not been requeued due to the limit
        if limit_exceeded_urls:
            output_string = ""
            for plugin_name, url_list in limit_exceeded_urls.items():
                output_string += f"{plugin_name}:" + "\n" + str(url_list)

            fuzz_result.plugins_res.append(plugin_factory.create(
                "plugin_from_finding", name=self.name,
                message=f"The following plugins intended to queue URLs that exceed the limit of 15 in a chain. "
                        f"To avoid infinite re-queueing, the listed URLs have not been queued again.\n"
                        f"{output_string}",
                severity=FuzzPlugin.INFO))


class RedirectQueue(FuzzQueue):
    """
    Queue designed to follow redirect URLs
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)

        self.cache = session.cache
        self.regex_header = [
            ("Link", re.compile(r"<(.*)>;")),
            ("Location", re.compile(r"(.*)")),
        ]

    def get_name(self):
        return "RedirectQueue"

    def process(self, fuzz_result: FuzzResult):
        if not 300 <= fuzz_result.code < 400:
            self.send(fuzz_result)
            return
        for header, regex in self.regex_header:
            if header in fuzz_result.history.headers.response:
                link = fuzz_result.history.headers.response[header]
                if link:
                    self.enqueue_link(fuzz_result, link)
        self.send(fuzz_result)

    def enqueue_link(self, fuzz_result, link_url):
        parsed_link = parse_url(link_url)

        filename = basename(parsed_link.path)
        extension = pathlib.Path(filename).suffix

        # Join both URLs. If it's relative, will append to the base URL. Otherwise, will use link_url's netloc
        target_url = urljoin(fuzz_result.url, link_url)

        in_scope = fuzz_result.history.check_in_scope(target_url, domain_based=self.session.options.domain_scope)
        if not in_scope:
            fuzz_result.plugins_res.append(plugin_factory.create(
                "plugin_from_finding", name=self.get_name(),
                message=f"Redirect URL is out of scope and will not be followed", severity=FuzzPlugin.INFO))
            return
        if not self.cache.check_cache(target_url):
            from_plugin = False
            if extension in head_extensions:
                method = "HEAD"
            else:
                method = "GET"
            backfeed: FuzzResult = resfactory.create("fuzzres_from_fuzzres", fuzz_result,
                                                     target_url, method, from_plugin)
            fuzz_result.plugins_res.append(plugin_factory.create(
                "plugin_from_finding", name=self.get_name(),
                message=f"Added a request to [u]follow redirection[/u]", severity=FuzzPlugin.INFO))
            self.send(backfeed)


class RecursiveQueue(FuzzQueue):
    """
    This queue is used when the recursive parameter is used (-R). The queue checks whether URLs should be handled
    in a recursive way, creating a new wave of requests for
    another directory (e.g. /FUZZ -> /admin/FUZZ). It's important to note that it will only do so if, by evaluation,
    it looks like an endpoint was found which acts as a directory.
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)

        self.cache = session.cache
        self.max_rlevel = session.options.recursion
        self.max_plugin_rlevel = session.options.plugin_recursion

    def get_name(self):
        return "RecursiveQueue"

    def process(self, fuzz_result: FuzzResult):
        # If it is not a directory, no recursion will be queued
        if not fuzz_result.history.request_found_directory():
            self.send(fuzz_result)
            return
        recursion_url = fuzz_result.history.parse_recursion_url()
        max_recursion_condition = self.max_recursion_condition(fuzz_result)

        seed: FuzzResult = resfactory.create("seed_from_recursion", fuzz_result)

        # If it's cached already, don't throw it. No reason to log it, may spam the output too much,
        # and another seed was thrown anyway.
        if self.cache.check_cache(recursion_url, cache_type="recursion", update=False):
            pass
        # Don't recurse if request limiting is active and threshold is reached
        elif self.session.options.limit_requests and self.session.http_pool.queued_requests > \
                self.session.options.limit_requests:
            fuzz_result.plugins_res.append(
                plugin_factory.create("plugin_from_finding", self.get_name(),
                                      f"Skipped recursion - limiting requests as per argument for "
                                      f"{recursion_url}", FuzzPlugin.INFO))
        # Or if recursion limit is reached
        elif max_recursion_condition:
            fuzz_result.plugins_res.append(
                plugin_factory.create("plugin_from_finding", self.get_name(),
                                      f"Skipped recursion - " + max_recursion_condition +
                                      f" for {recursion_url}", FuzzPlugin.INFO))
        # Or if the recursion URL is deemed a false positive. This check should be the last, as it is the costliest.
        elif self.false_positive_hit(seed, self.session, self.logger):
            fuzz_result.plugins_res.append(
                plugin_factory.create("plugin_from_finding", self.get_name(),
                                      f"Permanent redirect detected for "
                                      f"{recursion_url} - skipped recursion", FuzzPlugin.INFO))
        # Double-checking the cache. The previous cache checks help avoid extensive checks if it is
        # in the cache already, but a cache check right before sending the seed is necessary
        # to reduce race conditions.
        elif not self.cache.check_cache(recursion_url, cache_type="recursion", update=True):
            # Send the seed
            self.send(seed)
            fuzz_result.plugins_res.append(plugin_factory.create(
                "plugin_from_finding", name=self.get_name(),
                message=f"Enqueued path {recursion_url} for [u]recursion[/u] "
                        f"(rlevel={seed.rlevel}, plugin_rlevel={seed.plugin_rlevel})", severity=FuzzPlugin.INFO))
        # Sends the current request into the next queue
        self.send(fuzz_result)

    def max_recursion_condition(self, fuzz_result: FuzzResult) -> str:
        """
        Method to check whether max recursions are reached. If it is a backfed object (hence coming from a plugin), it
        should be checked against its plugin_rlevel. If it comes from the core, the ordinary rlevel should be checked.

        Returns strings accordingly, and an empty one if the max recursion has not been reached
        """
        if fuzz_result.from_plugin and fuzz_result.plugin_rlevel >= self.max_plugin_rlevel:
            return f"max_plugin_rlevel {self.max_plugin_rlevel} reached: {fuzz_result.plugin_rlevel}"
        elif not fuzz_result.from_plugin and fuzz_result.rlevel >= self.max_rlevel:
            return f"max_rlevel {self.max_rlevel} reached: {fuzz_result.rlevel}"
        else:
            return ""

    @staticmethod
    def false_positive_hit(seed: FuzzResult, session: FuzzSession, logger: logging.Logger) -> bool:
        """
        Checks whether server responds with something that looks like a hit an endpoint that does not exist,
        based on the URL of the FuzzResult
        Returns True if it is a false positive, False if it is legitimate
        """
        if session.options.proxy_list:
            proxy_string = session.options.proxy_list[0]
            proxy_dict = {"http": proxy_string,
                          "https": proxy_string}
        else:
            proxy_dict = ""
        if session.options.header_dict():
            headers_dict = session.options.header_dict()
        else:
            headers_dict = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
            }
        check_string = "thisdoesnotexist123"
        recursion_url = seed.history.url
        check_url = recursion_url.replace("FUZZ", check_string)
        try:
            junk_response_tuple = RecursiveQueue._get_response_tuple(check_url, headers_dict, proxy_dict)
        except Exception as e:
            logger.exception(f"Exception in false_positive_hit during first junk response")
            return False
        # If the status code and word count of the junk response is identical, it's pretty much guaranteed to be
        # a false positive
        if junk_response_tuple[0] == seed.code and junk_response_tuple[1] == seed.words:
            return True
        # If even the status code is different, the initial request was a real hit
        elif junk_response_tuple[0] != seed.code:
            return False
        # Lastly, if the word count is different, but the status code is the same, a third request should be compared
        # as things are hard to determine (dynamic response content may play a part):
        check_string = "thisalsodoesnotexist123"
        check_url = recursion_url.replace("FUZZ", check_string)
        try:
            second_junk_response_tuple = RecursiveQueue._get_response_tuple(check_url, headers_dict, proxy_dict)
        except Exception as e:
            logger.exception(f"Exception in false_positive_hit during second junk response")
            return False
        # If both junk responses are identical, whereas it has been established prior that the word count differs to the
        # original request, the original one was unique and therefore not a false positive
        if second_junk_response_tuple[0] == junk_response_tuple[0] and \
                second_junk_response_tuple[1] == junk_response_tuple[1]:
            return False
        # In every other case left, the original response is not unique and
        # therefore treated as a false positive
        return True

    @staticmethod
    def _get_response_tuple(check_url, headers_dict, proxy_dict) -> tuple[int, int]:
        """
        Send out the request, parse the response and return it in a tuple, where the first entry is the
        response status code, and the second entry is the word length
        """
        try:
            junk_response = requests.get(check_url, verify=False,
                                         headers=headers_dict, allow_redirects=False, proxies=proxy_dict)
        except Exception as e:
            raise Exception
        encoding = get_encoding_from_headers(junk_response.headers)
        # fallback to default encoding
        if encoding is None:
            encoding = "utf-8"
        junk_string_content = junk_response.content.decode(encoding, errors="replace")
        # No line comparison as of right now
        # junk_lines = string_content.count("\n")
        junk_words = len(re.findall(r"\S+", junk_string_content))
        return junk_response.status_code, junk_words


class DryRunQueue(FuzzQueue):
    """
    Queue used as transport_queue when 'dryrun' option is used. Sends no requests, does nothing, simply passes
    the item.
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)
        self.pause = Event()

    def get_name(self):
        return "DryRunQueue"

    def process(self, fuzz_result: FuzzResult):
        self.send(fuzz_result)


class HttpQueue(FuzzQueue):
    """
    Queue Responsible for sending and receiving requests.
    Accepts items from SeedQueue and RoutingQueue. RoutingQueue might handle a lot of BACKFEED-objects, which take
    precedence over items coming from the SeedQueue. There is no maxsize, as the RoutingQueue would get blocked and
    compete with SeedQueue over putting items (ultimately preventing the prioritization of items). Therefore, it
    accepts items without a maxsize, and SeedQueue manually makes sure not to put into HttpQueue if it's qsize() is
    already big.
    """

    def __init__(self, session: FuzzSession):
        super().__init__(session)

        self.http_pool = session.http_pool

        # Listening for keypress to pause execution
        self.pause = Event()
        self.pause.set()

        # Event signal dedicated to throttling the SeedQueue. This helps avoid the SeedQueue to run rampant and
        # create excessive amounts of objects before they can be processed. They occupy lots of RAM otherwise.
        self.receive_seed_queue = Event()
        self.receive_seed_queue.set()
        self.thread = None
        # This event gets cleared once the thread is supposed to stop. After successfully stopping, it sets it again
        # to signal that it registered and processed the stop instruction.
        self.thread_cancelled = Event()
        self.thread_cancelled.set()

    def cancel(self):
        # Explicitly allow SeedQueue to put more while cancelling. This avoids the SeedQueue to hang indefinitely
        # because the HttpQueue was both "too full" to receive items and simultaneously stopped processing them.
        # In practice, when HttpQueue cancels, SeedQueue will be about to stop as well. This means the SeedQueue
        # will put another item into the HttpQueue, and then start its own stopping routine.
        self.receive_seed_queue.set()

        # Putting a stop tuple with the highest priority
        self.http_pool.result_queue.put((0, None, None))
        self.thread_cancelled.clear()
        self.thread_cancelled.wait()

        self.http_pool.thread_cancelled.clear()
        self.http_pool.thread_cancelled.wait()

        self.thread.join()
        self.http_pool.join_threads()

    def pre_start(self):
        self.http_pool.initialize()

        self.thread = Thread(target=self.__read_http_results)
        self.thread.daemon = True
        self.thread.name = "__read_http_results"
        self.thread.start()

    def get_name(self):
        return "HttpQueue"

    def items_to_process(self):
        return [FuzzType.RESULT, FuzzType.BACKFEED]

    def process(self, fuzz_result: FuzzResult):
        # Don't process as long as pause Event is set
        self.pause.wait()
        # SeedQueue clears the event and waits for unblock if it sees too many items in HttpQueue queued.
        # If there aren't too many items already waiting, then allow SeedQueue to send more again.
        if self.qsize() <= (self.session.options.threads * 5):
            self.receive_seed_queue.set()
        self.http_pool.enqueue(fuzz_result)

    def __read_http_results(self):
        """
        Function running in thread to continuously monitor http request results. It practically behaves like a queue
        which gets items that have been put in and processes them.
        """
        while True:
            fuzz_result, requeue = next(self.http_pool.iter_results())
            if not fuzz_result:
                break
            if requeue:
                self.http_pool.enqueue(fuzz_result)
            else:
                if fuzz_result.exception and self.session.options.stop_error:
                    self._throw(fuzz_result.exception)
                else:
                    self.send(fuzz_result)
        self.logger.debug("__read_http_results stopped")
        self.thread_cancelled.set()

