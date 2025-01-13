import copy
import datetime
import json
import os
from collections import defaultdict
from datetime import timedelta
from typing import Optional, List

import dateutil.parser

from wenum.externals.reqresp.CachedResponse import CachedResponse
from wenum.fuzzobjects import FuzzResult, FuzzType


class HttpCache:
    """
    The cache keeps track of all the requests that have already been enqueued, to avoid doing it multiple times.
    """
    cache_dir = None
    __cache_dir_map = {}

    def __init__(self, cache_dir: Optional[str] = None):
        # cache control, a dictionary with URLs as keys and their values being lists full of the
        # categories that the queries were categorized as
        self.__cache_map = defaultdict(list)
        # @TODO make this configurable
        self.status_200_age = datetime.datetime.now(datetime.UTC) - timedelta(days=7)
        self.status_404_age = datetime.datetime.now(datetime.UTC) - timedelta(days=60)

        if cache_dir:
            self.load_cache_dir(cache_dir)

    def check_cache(self, url_key: str, cache_type: str = "processed", update: bool = True) -> bool:
        """
        Checks if the URL is in the cache, usually to avoid queueing the same URL a second time.

        The category of the request is relevant (default: "processed").
        If '/robots.txt, init_request' exists in the cache,
        the new request won't count as cached if it is checked against '/robots.txt, seed'.

        if the update bool is True (default), the function will also add the key to the cache if it did not exist yet.

        Returns True if it was in the cache.
        Returns False if it was not in the cache.
        """
        if url_key in self.__cache_map and cache_type in self.__cache_map[url_key]:
            cached = True
        else:
            cached = False
        if update:
            self.__cache_map[url_key].append(cache_type)
        return cached

    def get_object_from_object_cache(self, fuzz_result: FuzzResult, key=False) -> Optional[FuzzResult]:
        """
        Return entry in object_cache based on fuzzresult or key if provided (function for --cache-file option)
        """
        if not self.cache_dir:
            return None
        if key is False:
            key = fuzz_result.history.to_cache_key()
        return self._fuzz_result_from_cache(key, fuzz_result)

    def load_cache_dir(self, directory: str) -> None:
        """
        Method to load a cache dir into the runtime if option is set.
        Will keep track of a separate cache than the core cache. Responses loaded into this should run through
        all queues but the HttpQueue, which will check for this cache in specific
        """
        if not os.path.isdir(directory):
            return
        cache_file = os.path.join(directory, "cache.json")
        if not os.path.isfile(cache_file):
            return
        self.cache_dir = directory
        with open(cache_file, "rb") as cache_data:
            self.__cache_dir_map = json.load(cache_data)

    def _fuzz_result_from_cache(self, key: str, fuzz_result: FuzzResult) -> FuzzResult | None:
        if key not in self.__cache_dir_map:
            return None
        cached = self.__cache_dir_map[key]
        if "time" in cached:
            time = dateutil.parser.parse(cached["time"])
            if 200 <= cached['status'] < 400:
                if time < self.status_200_age:
                    return None
            elif 400 <= cached['status'] < 599:
                if time < self.status_404_age:
                    return None

        res_copy = copy.deepcopy(fuzz_result)
        res_copy.item_type = FuzzType.RESULT

        # fuzz_result.code = cached["status"]
        res_copy.lines = cached["lines"] if cached["lines"] is not None else 0
        res_copy.words = cached["words"] if cached["words"] is not None else 0
        res_copy.chars = cached["chars"] if cached["chars"] is not None else 0
        body = None
        if "body" in cached and cached["body"] is not None:
            body = os.path.join(self.cache_dir, "body", cached["body"])
        header = cached.get("headers", None)

        response = CachedResponse("https" if "https" in key else "http", cached["status"], body=body, header=header,
                                  length=cached["chars"])
        res_copy.history._request.response = response

        return res_copy

    def cached_urls(self) -> List[str]:
        """
        Get a list of all cached URLs with status code < 400
        :return:
        """
        if not self.cache_dir:
            return []
        for key, cached in self.__cache_dir_map.items():
            if cached["status"] >= 400:
                continue
            yield key
