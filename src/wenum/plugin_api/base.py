from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from wenum.runtime_session import FuzzSession
    from queue import Queue
from wenum.fuzzobjects import FuzzPlugin, FuzzResponse
from wenum.exception import (
    FuzzExceptBadOptions,
    FuzzExceptPluginError,
)
from wenum.factories.plugin_factory import plugin_factory
from wenum.externals.reqresp.cache import HttpCache

from abc import abstractmethod
from distutils import util
from threading import Event, Condition


class BasePlugin:
    """
    Base class for all other plugins that exist
    """

    def __init__(self, session: FuzzSession):
        # Setting disabled to true will cause it not to execute for future requests anymore
        self.disabled = False
        # The results queue is the queue receiving all the plugin output. PluginExecutor will later read it
        self.results_queue: Optional[Queue] = None
        # Bool indicating whether plugin should only be run once. PluginExecutor will disable after first execution
        self.run_once = False
        # Plugins might adjust the FuzzResult object passed into them. This contains the original state
        self.base_fuzz_res: Optional[FuzzResponse] = None
        self.cache = HttpCache()
        self.interrupt: Optional[Event] = None
        self.session: FuzzSession = session
        self.logger = logging.getLogger("debug_log")

        # check mandatory params, assign default values
        for name, default_value, required, description in self.parameters:
            param_name = f"{self.name}.{name}"

            if required and param_name not in list(self.kbase.keys()):
                raise FuzzExceptBadOptions(
                    "Plugins, missing parameter %s!" % (param_name,)
                )

            if param_name not in list(self.kbase.keys()):
                self.kbase[param_name] = default_value

    def run(self, fuzz_result: FuzzResponse, plugin_finished: Event, condition: Condition, interrupt_signal: Event, results_queue: Queue) -> None:
        """
        Will be triggered by PluginExecutor
        """
        try:
            self.interrupt = interrupt_signal
            self.results_queue = results_queue
            self.base_fuzz_res = fuzz_result
            self.process(fuzz_result)
        except Exception as e:
            self.logger.exception(f"An exception occured while running the plugin {self.name}")
            exception_plugin = plugin_factory.create("plugin_from_error", self.name, e)
            results_queue.put(exception_plugin)
        finally:
            # Signal back completion of execution
            plugin_finished.set()
            with condition:
                condition.notify()
            return

    @abstractmethod
    def process(self, fuzz_result: FuzzResponse) -> None:
        """
        This is where the plugin processing is done. Any wenum plugin must implement this method

        A kbase (get_kbase, has_kbase, add_kbase) is shared between all plugins. this can be used to store and
        retrieve relevant "collaborative" information.
        """
        raise NotImplementedError

    @abstractmethod
    def validate(self, fuzz_result: FuzzResponse) -> bool:
        """
        Function to poll whether the plugin should be executed for the current result.
        PluginExecutor skips the plugin if it does not validate
        """
        raise FuzzExceptPluginError("Method count not implemented")

    def add_information(self, message: str, severity=FuzzPlugin.INFO) -> None:
        """
        Add some information to the result queue. It will be printed out for the user to see.
        Optionally specify severity
        """
        self.put_if_okay(plugin_factory.create("plugin_from_finding", self.name, message, severity))

    def add_exception_information(self, exception: str) -> None:
        """
        Add some exception information to the result queue. It will be printed out for the user to see
        """
        self.logger.warning(f"The plugin {self.name} has added exception information: {exception}")
        self.put_if_okay(plugin_factory.create("plugin_from_error", self.name, exception))

    def queue_url(self, url: str, method: str = "GET") -> None:
        """
        Enqueue a new full URL. It will be processed by PluginExecutor, and if it is valid
        (not already in cache + in scope) will be queued to be sent by wenum
        """
        self.put_if_okay(plugin_factory.create(
                "backfeed_plugin", self.name, self.base_fuzz_res, url, method))

    def queue_seed(self, seeding_url):
        """
        Enqueue a new SEED (full recursion). It will be processed by PluginExecutor, and if
        it is valid will be queued to be sent by wenum
        Optionally takes seeding_url. Can be arbitrarily specified to use as a new FUZZ
        """
        # Stop queueing seeds if the limit is reached already
        if self.session.options.limit_requests and self.session.http_pool.queued_requests > \
                self.session.options.limit_requests:
            return
        self.put_if_okay(plugin_factory.create(
                "seed_plugin", self.name, self.base_fuzz_res, seeding_url))

    def put_if_okay(self, fuzz_plugin) -> None:
        """
        Checks for the interrupt signal for plugins. If the interrupt is set, nothing will be put into
        the result queue. Otherwise, it will simply do so.
        """
        if self.interrupt.is_set():
            return
        else:
            self.results_queue.put(fuzz_plugin)

    @staticmethod
    def _bool(value) -> bool:
        return bool(util.strtobool(value))


