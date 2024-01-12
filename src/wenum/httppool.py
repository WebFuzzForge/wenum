from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from .myqueues import FuzzPriorityQueue
from queue import PriorityQueue


if TYPE_CHECKING:
    from wenum.runtime_session import FuzzSession
import pycurl
from io import BytesIO
from threading import Thread, Lock, Event
import itertools
from queue import Queue
import datetime
import pytz as pytz

from .exception import FuzzExceptBadOptions, FuzzExceptNetError
from .fuzzobjects import FuzzResponse, FuzzItem, FuzzType

from .factories.reqresp_factory import ReqRespRequestFactory

# See https://curl.haxx.se/libcurl/c/libcurl-errors.html
UNRECOVERABLE_PYCURL_EXCEPTIONS = [
    28,  # Operation timeout. The specified time-out period was reached according to the conditions.
    7,  # Failed to connect() to host or proxy.
    6,  # Couldn't resolve host. The given remote host was not resolved.
    5,  # Couldn't resolve proxy. The given proxy host could not be resolved.
    63  # Maximum response size exceeded.
]

# Other common pycurl exceptions:
# Exception in perform (35, 'error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table')
# Exception in perform (18, 'SSL read: error:0B07C065:x509 certificate routines:X509_STORE_add_cert:cert already in hash table, errno 11')

MAX_AGE = datetime.datetime.now(pytz.utc) - datetime.timedelta(days=30)


class HttpPool:
    newid = itertools.count(0)

    def __init__(self, session: FuzzSession):
        # Amount of total requests that have been queued. This is not a "remaining" requests counter
        self.queued_requests = 0
        # Amount of total responses that have been received.
        self.processed = 0

        self.mutex_stats = Lock()

        self.logger = logging.getLogger("debug_log")

        # CurlMulti object to which active curl handles will be added to (and removed once done)
        self.curl_multi: Optional[pycurl.CurlMulti] = None
        # List of all the handle objects instances used during runtime (can be adjusted by -t option)
        self.handles: list[pycurl.Curl] = []
        # List of all the curl handles that are not actively used at the moment
        self.curlh_freelist: list[pycurl.Curl] = []
        # Queue object storing all the requests available for sending out. Maxsize avoids buffering tens of thousands of
        # requests beforehand, which would result in gigabytes of reserved memory
        self.request_queue: Queue = Queue(maxsize=session.options.threads)
        # A general default base priority with which results should be processed
        self.base_result_priority = 10
        self.sleep = session.options.sleep

        # The results will be put into this queue for the HTTPQueue to grab the items from there
        self.result_queue: PriorityQueue = PriorityQueue()

        self.next_proxy = None

        self.thread = None
        # This event gets cleared once the thread is supposed to stop. After successfully stopping, it sets it again
        # to signal that it registered and processed the stop instruction.
        self.thread_cancelled = Event()
        self.thread_cancelled.set()

        self.session: FuzzSession = session
        self.cache = self.session.cache

        if self.session.options.proxy_list:
            self.next_proxy = self._get_next_proxy(self.session.options.proxy_list)

    def initialize(self) -> None:
        """
        Set up all the curl handles and start thread to read them
        """
        # pycurl Connection pool
        self.curl_multi = pycurl.CurlMulti()
        self.handles = []

        for i in range(self.session.options.threads):
            curl_h = pycurl.Curl()
            self.handles.append(curl_h)
            self.curlh_freelist.append(curl_h)

        self.thread = Thread(target=getattr(self, "_process_curl_handles"))
        self.thread.daemon = True
        self.thread.start()

    def job_stats(self) -> dict:
        """
        Return stats
        """
        with self.mutex_stats:
            stats_dict = {
                "Requests enqueued": self.queued_requests,
                "Responses received": self.processed,
            }
        return stats_dict

    def iter_results(self):
        """
        Method to receive the next item from the queue which stores the results of all the requests sent
        """
        queue_output = self.result_queue.get()
        self.result_queue.task_done()
        priority = queue_output[0]
        item = queue_output[1]
        requeue = queue_output[2]

        yield item, requeue

    def _prepare_curl_h(self, curl_h, fuzz_result):
        """
        Set up curl handle again for another request
        """
        new_curl_h = ReqRespRequestFactory.to_http_object(fuzz_result.history, curl_h)
        new_curl_h = self._set_extra_options(new_curl_h)

        new_curl_h.response_queue = (BytesIO(), BytesIO(), fuzz_result)
        new_curl_h.setopt(pycurl.WRITEFUNCTION, new_curl_h.response_queue[0].write)
        new_curl_h.setopt(pycurl.HEADERFUNCTION, new_curl_h.response_queue[1].write)

        return new_curl_h

    def enqueue(self, fuzz_result: FuzzResponse):
        """
        This method is called by HttpQueue. Puts a request object into request_queue, which is processed by a
        separate thread actually sending and receiving the requests.
        It is important that enqueue is not called by the thread handling the requests, because it can deadlock if
        the queue is full while trying to append more.
        """
        if self.session.options.cache_dir:
            cached = self.cache.get_object_from_object_cache(fuzz_result)
            # If the request is cached, put it in the queue to be processes by plugins and return.
            # This does not make additional requests, but it does allow plugins to process the cached request.
            if cached:
                cached.plugins_res.clear()
                self.result_queue.put((self.base_result_priority, cached, False))
                return

        if self.sleep:
            time.sleep(self.sleep)

        with self.mutex_stats:
            self.queued_requests += 1
        self.request_queue.put(fuzz_result)

    def join_threads(self):
        self.thread.join()

        while self.request_queue.qsize() > 0:
            self.request_queue.get()
            self.request_queue.task_done()
        self.request_queue.join()

        while self.result_queue.qsize() > 0:
            self.result_queue.get()
            self.result_queue.task_done()
        self.result_queue.join()

    @staticmethod
    def _get_next_proxy(proxy_list):
        index = 0
        while True:
            yield proxy_list[index]
            index += 1
            index = index % len(proxy_list)

    def _set_extra_options(self, curl_h):
        """
        Set custom proxy and request timeout
        """
        if self.next_proxy:
            proxy = next(self.next_proxy)

            parsed_proxy = urlparse(proxy)

            if parsed_proxy.scheme.lower() == "socks5":
                curl_h.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
                curl_h.setopt(pycurl.PROXY, parsed_proxy.netloc)
            elif parsed_proxy.scheme.lower() == "socks4":
                curl_h.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
                curl_h.setopt(pycurl.PROXY, parsed_proxy.netloc)
            else:
                curl_h.setopt(pycurl.PROXY, parsed_proxy.netloc)
        else:
            curl_h.setopt(pycurl.PROXY, "")

        # Do not allow for responses bigger than 200MB
        curl_h.setopt(pycurl.MAXFILESIZE, 200000000)
        curl_h.setopt(pycurl.TIMEOUT, self.session.options.request_timeout)

        return curl_h

    def _process_curl_handle_response(self, curl_h: pycurl.Curl) -> None:
        buff_body, buff_header, res = curl_h.response_queue
        # Bool indicating whether the request should be queued for request again. Useful for exceptions
        requeue = False

        try:
            ReqRespRequestFactory.from_http_object(
                res.history,
                curl_h,
                buff_header.getvalue(),
                buff_body.getvalue(),
            )
        except Exception as e:
            self.result_queue.put((self.base_result_priority, res.update(exception=e), requeue))
        else:
            # reset type to result otherwise backfeed items will enter an infinite loop
            self.result_queue.put((self.base_result_priority, res.update(), requeue))

        with self.mutex_stats:
            self.processed += 1

    def _process_curl_determine_retry(self, fuzz_result: FuzzResponse, errno: int) -> bool:
        """
        Check if the request should be requeued and forward it accordingly.

        Returns True if it should, and False if not
        """
        if errno in UNRECOVERABLE_PYCURL_EXCEPTIONS or fuzz_result.history.retries >= 3:
            return False
        # Bool indicating whether the request should be queued for request again. Useful for exceptions
        requeue = True

        fuzz_result.history.retries += 1

        self.result_queue.put((self.base_result_priority, fuzz_result, requeue))
        return True

    def _process_curl_handle_error(self, fuzz_result: FuzzResponse, errno, errmsg):
        """
        Handle unrecoverable failed request
        """
        # Bool indicating whether the request should be queued for request again. Useful for exceptions
        requeue = False
        e = FuzzExceptNetError("Pycurl error %d: %s" % (errno, errmsg))
        fuzz_result.history.totaltime = 0
        # Clearing the response. Otherwise, if the failed request is a recursive one, it would retain the response
        # data from the one before
        fuzz_result.history._request.response = None
        self.result_queue.put((self.base_result_priority, fuzz_result.update(exception=e), requeue))
        with self.mutex_stats:
            self.processed += 1

    def _process_curl_handles(self):
        """
        Check for curl objects which have terminated, and add them to the curlh_freelist
        """
        while self.thread_cancelled.is_set():
            while self.thread_cancelled.is_set():
                ret, num_handles = self.curl_multi.perform()
                if ret != pycurl.E_CALL_MULTI_PERFORM:
                    break

            num_q, ok_list, err_list = self.curl_multi.info_read()

            # Deal with curl handles that have returned successfully
            for curl_h in ok_list:
                self._process_curl_handle_response(curl_h)
                self.curl_multi.remove_handle(curl_h)
                self.curlh_freelist.append(curl_h)

            # Deal with curl handles that returned errors
            for curl_h, errno, errmsg in err_list:
                buff_body, buff_header, res = curl_h.response_queue

                if not self._process_curl_determine_retry(res, errno):
                    self._process_curl_handle_error(res, errno, errmsg)

                self.curl_multi.remove_handle(curl_h)
                self.curlh_freelist.append(curl_h)

            # Put curl handles for sending out requests
            while self.curlh_freelist and not self.request_queue.empty():
                curl_h = self.curlh_freelist.pop()
                fuzzres = self.request_queue.get()

                self.curl_multi.add_handle(self._prepare_curl_h(curl_h, fuzzres))
                self.request_queue.task_done()
        # cleanup multi stack
        for c in self.handles:
            c.close()
            self.curlh_freelist.append(c)
        self.curl_multi.close()

        self.logger.debug(f"_process_curl_handles stopped")
        self.thread_cancelled.set()
