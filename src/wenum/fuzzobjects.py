from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from wenum.fuzzrequest import FuzzRequest
import time
import hashlib
import re
import itertools
from enum import Enum

from threading import Lock
from collections import defaultdict, namedtuple

from .filters.complexfilter import FuzzResFilter
from .facade import ERROR_CODE
from .helpers.str_func import convert_to_unicode
from .helpers.utils import MyCounter

FuzzWord = namedtuple("FuzzWord", ["content", "type"])


class FuzzWordType(Enum):
    WORD, FUZZRES = range(2)


class FuzzType(Enum):
    (SEED, BACKFEED, RESULT, ERROR, STARTSEED, ENDSEED, PLUGIN, MESSAGE, STOP) = range(9)


class FuzzItem:
    newid = itertools.count(0)

    def __init__(self, item_type: FuzzType):
        self.item_id = next(FuzzItem.newid)
        self.item_type = item_type
        self.rlevel = 0
        self.plugin_rlevel = 0
        # The default priority the item should be handled by the queues
        self.priority = 10
        # Set to True by e.g. FilterQ in case the result should be filtered out
        self.discarded = False

    def __str__(self):
        return "FuzzItem, type: {}".format(self.item_type.name)

    def __lt__(self, other):
        return self.item_id < other.item_id

    def __le__(self, other):
        return self.item_id <= other.item_id

    def __gt__(self, other):
        return self.item_id > other.item_id

    def __ge__(self, other):
        return self.item_id >= other.item_id

    def __eq__(self, other):
        return self.item_id == other.item_id

    def __ne__(self, other):
        return self.item_id != other.item_id


class FuzzStats:
    """
    Class designed to carry diagnostic runtime information
    """
    def __init__(self):
        self.mutex = Lock()

        # Will be set to initial Fuzzing URL
        self.url = ""
        self.seed = None

        # Variable containing the amount of requests read from the wordlist
        self.wordlist_req = 0
        # Variable containing the total amount of requests that will be sent
        # (can be higher than wordlist_req due to recursions)
        self.total_req = 0
        # Counter for total amount of requests to be processed. Increased once SeedQ has readied the request.
        # Once 0 with seeds, wenum enters the ending routine
        self.pending_fuzz = MyCounter()
        # Counter for total amount of seeds to be processed. Once 0 fuzzes, wenum enters the ending routine
        self.pending_seeds = MyCounter()
        # Counter for total amount of fully processed requests
        self.processed = MyCounter()
        # Counter for total amount of backfeed requests
        self.backfeed = MyCounter()
        # Counter for total amount of filtered requests
        self.filtered = MyCounter()

        # List containing all the seed URLs that have been thrown.
        # Tracking URLs instead of only paths is better, as schemes, ports, or domains may change
        self.seed_list = []

        # Tracks how many hits have been found in a subdir.
        self.subdir_hits = {}

        self.totaltime = 0
        self.starttime: float = 0

        self._cancelled = False

    @staticmethod
    def from_options(session):
        tmp_stats = FuzzStats()

        tmp_stats.url = session.compiled_seed.history.url
        tmp_stats.wordlist_req = session.compiled_iterator.count()
        tmp_stats.seed = session.compiled_seed

        return tmp_stats

    def get_runtime_stats(self):
        """Return stats of current runtime as dict.
        Data included is tailored towards being used during the runtime, not at the end of it"""
        return {
            "URL": self.url,
            "Total": self.total_req,
            "Backfed": self.backfeed(),
            "Processed": self.processed(),
            "Pending": self.pending_fuzz(),
            "Filtered": self.filtered(),
            "Pending seeds": self.pending_seeds(),
            "Total time": time.time() - self.starttime,
        }

    def update_subdirectory_hits(self, fuzz_result: FuzzResponse) -> None:
        """Update the amount of times a valid response has been found within a subdirectory.
        E.g. /admin/scripts/login.html will trigger a hitcount for /admin/ and /admin/scripts/"""
        request_path = fuzz_result.history.path
        # Strip the last slash for paths that end with a slash
        if fuzz_result.history.path.endswith("/"):
            request_path = request_path[:-1]

        split_path = request_path.split("/")
        # Filtering to avoid empty strings caused by e.g. trailing/leading slashes/multiple slashes in a row
        split_path = (list(filter(None, split_path)))
        # If the length is only one, it's a request in the root. We are not interested in tracking them.
        if len(split_path) <= 1:
            return
        for i in range(len(split_path[:-1])):
            subdir = "/" + "/".join(split_path[:i + 1]) + "/FUZZ"
            try:
                self.subdir_hits[subdir] += 1
            except KeyError:
                self.subdir_hits[subdir] = 1

    def mark_start(self):
        """
        Sets the starttime
        """
        with self.mutex:
            self.starttime = time.time()

    @property
    def cancelled(self):
        with self.mutex:
            return self._cancelled

    @cancelled.setter
    def cancelled(self, v):
        with self.mutex:
            self._cancelled = v

    def __str__(self):
        string = ""
        totaltime = time.time() - self.starttime
        totaltime_formatted = datetime.timedelta(seconds=int(totaltime))
        string += "Total time: %s\n" % str(totaltime_formatted)

        if self.backfeed() > 0:
            string += "Total Backfed/Plugin Requests: %s\n" % (str(self.backfeed())[:8])
        string += "Processed Requests: %s\n" % (str(self.processed())[:8])
        string += "Filtered Requests: %s\n" % (str(self.filtered())[:8])
        string += (
            "Requests/s: %s\n"
            % str(int(self.processed() / totaltime) if totaltime > 0 else 0)[:8]
        )

        return string

    def update(self, fuzzstats2: FuzzStats):
        self.url = fuzzstats2.url
        self.wordlist_req = fuzzstats2.wordlist_req
        self.total_req = fuzzstats2.total_req

        self.backfeed._operation(fuzzstats2.backfeed())
        self.processed._operation(fuzzstats2.processed())
        self.pending_fuzz._operation(fuzzstats2.pending_fuzz())
        self.filtered._operation(fuzzstats2.filtered())
        self.pending_seeds._operation(fuzzstats2.pending_seeds())

    def new_seed(self):
        """
        Called to execute relevant stat updates when a new seed is created
        """
        self.pending_seeds.inc()
        self.total_req += self.wordlist_req

    def new_backfeed(self):
        """
        Called to execute relevant stat updates when a new backfeed is created
        """
        self.backfeed.inc()
        self.pending_fuzz.inc()
        self.total_req += 1


class FuzzPayload:
    def __init__(self):
        self.marker = None
        self.word = None
        self.index = None
        self.content = None
        self.type = None

    @property
    def value(self):
        if self.content is None:
            return None
        return self.content

    def description(self):
        if self.marker is None:
            return ""

        # return default value
        if isinstance(self.content, FuzzResponse):
            return self.content.url

        return self.value

    def __str__(self):
        return "type: {} index: {} marker: {} content: {} value: {}".format(
            self.type,
            self.index,
            self.marker,
            self.content.__class__,
            self.value,
        )


class FPayloadManager:
    """#TODO What does this manage?"""
    def __init__(self):
        self.payloads = defaultdict(list)

    def add(self, payload_dict, fuzzword=None):
        """
        Add a payload to the manager
        """
        fp = FuzzPayload()
        fp.marker = payload_dict["full_marker"]
        fp.word = payload_dict["word"]
        fp.index = (
            int(payload_dict["index"]) if payload_dict["index"] is not None else 1
        )
        fp.content = fuzzword.content if fuzzword else None
        fp.type = fuzzword.type if fuzzword else None

        self.payloads[fp.index].append(fp)

    def update_from_dictio(self, dictio_item):
        for index, dictio_payload in enumerate(dictio_item, 1):
            fuzz_payload = None
            for fuzz_payload in self.payloads[index]:
                fuzz_payload.content = dictio_payload.content
                fuzz_payload.type = dictio_payload.type

            # payload generated not used in seed but in filters
            if fuzz_payload is None:
                self.add(
                    {"full_marker": None, "word": None, "index": index, "field": None},
                    dictio_item[index - 1],
                )

    def get_fuzz_words(self) -> list[str]:
        return [payload.word for payload in self.get_payloads()]

    def get_payload(self, index):
        return self.payloads[index]

    def get_payload_type(self, index):
        return self.get_payload(index)[0].type

    def get_payload_content(self, index):
        return self.get_payload(index)[0].content

    def get_payloads(self) -> list[FuzzPayload]:
        for index, elem_list in sorted(self.payloads.items()):
            for elem in elem_list:
                yield elem

    def description(self):
        payl_descriptions = [payload.description() for payload in self.get_payloads()]
        ret_str = " - ".join([p_des for p_des in payl_descriptions if p_des])

        return ret_str

    def __str__(self):
        return "\n".join([str(payload) for payload in self.get_payloads()])


class FuzzError(FuzzItem):
    def __init__(self, exception):
        FuzzItem.__init__(self, FuzzType.ERROR)
        self.exception = exception


class FuzzResponse(FuzzItem):
    """
    Class tracking meta-information about the HTTP Response
    (e.g. post processing information)
    """
    #TODO FuzzItems have a counter too and since no chronology is upheld with the IDs, this can be phased out and
    # every object can access the FuzzItem ID instead
    newid = itertools.count(0)

    def __init__(self, history=None, exception=None):
        FuzzItem.__init__(self, FuzzType.RESULT)
        self.history: FuzzRequest = history

        self.exception = exception
        self.rlevel_desc: str = ""
        self.id: int = next(FuzzResponse.newid)

        self.chars: int = 0
        self.lines: int = 0
        self.words: int = 0

        self.update()

        # List containing the (potential) results of plugins that are run for each request
        self.plugins_res: list[FuzzPlugin] = []

        self.payload_man: Optional[FPayloadManager] = None

        # Bool indicating whether this object is initialized by a plugin.
        self.from_plugin: bool = False

        # Variable to keep track of how often a specific object has been parsed for a new URL and requeued.
        # In case a plugin interaction with an applications runs into an endless re-queuing-chain, this will help
        # stop after a limit is reached.
        self.backfeed_level = 0

    def update(self, exception=None):
        self.item_type = FuzzType.RESULT
        if exception:
            self.exception = exception

        if self.history and self.history.content:
            m = hashlib.md5()
            m.update(convert_to_unicode(self.history.content))

            self.chars = len(self.history.content)
            self.lines = self.history.content.count("\n")
            self.words = len(re.findall(r"\S+", self.history.content))
        # Explicitly resetting these. As recursive requests are copies from the prior FuzzResult object,
        # this otherwise may retain the data from the previous result
        else:
            self.chars = 0
            self.lines = 0
            self.words = 0

        return self

    def __str__(self):
        fuzz_result = '%05d:  C=%03d   %4d L\t   %5d W\t  %5d Ch\t  "%s"\t "%s"' % (
            self.id,
            self.code,
            self.lines,
            self.words,
            self.chars,
            self.url,
            # Description often contains the payload from the wordlist
            self.description,
        )
        for plugin in self.plugins_res:
            if plugin.is_visible():
                fuzz_result += "\n  |_ %s" % plugin.message

        return fuzz_result

    @property
    def description(self):
        res_description = self.payload_man.description() if self.payload_man else None

        ret_str = res_description

        if self.exception:
            return ret_str + "! " + str(self.exception)

        if self.rlevel_desc:
            if ret_str:
                return self.rlevel_desc + " - " + ret_str
            else:
                return self.rlevel_desc

        return ret_str

    # parameters in common with fuzzrequest
    @property
    def content(self):
        return self.history.content if self.history else ""

    @property
    def url(self):
        """
        Reference to self.history.url
        """
        return self.history.url if self.history else ""

    @property
    def code(self):
        """
        Return HTTP status code
        """
        if self.history and self.history.code >= 0 and not self.exception:
            return int(self.history.code)
        else:
            return ERROR_CODE

    @property
    def timer(self):
        return self.history.reqtime if self.history and self.history.reqtime else 0


class FuzzPlugin(FuzzItem):
    """
    FuzzPlugins usually store result information of script plugins (which inherit from BasePlugin).
    Therefore, they are created by plugins, rather than representing the plugins themselves
    """
    NONE, INFO, LOW, MEDIUM, HIGH, CRITICAL = range(6)
    MIN_VERBOSE = INFO

    def __init__(self):
        FuzzItem.__init__(self, FuzzType.PLUGIN)
        self.name = ""
        self.severity = self.INFO
        self.message = ""
        self.exception = None
        self.seed: Optional[FuzzResponse] = None

    def is_visible(self) -> bool:
        """
        Return True if severe enough
        """
        if self.severity >= self.MIN_VERBOSE:
            return True
        else:
            return False
