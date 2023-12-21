from wenum.plugin_api.base import BasePlugin
from wenum.externals.moduleman.plugin import moduleman_plugin
from wenum.plugin_api.static_data import HEADERS_server_headers, HEADERS_common_response_headers_regex_list, \
    HEADERS_common_req_headers_regex_list

import re

KBASE_KEY = "http.servers"
KBASE_KEY_RESP_UNCOMMON = "http.response.headers.uncommon"
KBASE_KEY_REQ_UNCOMMON = "http.request.headers.uncommon"

COMMON_RESPONSE_HEADERS_REGEX = re.compile(
    "({})".format("|".join(HEADERS_common_response_headers_regex_list)), re.IGNORECASE
)

COMMON_REQ_HEADERS_REGEX = re.compile(
    "({})".format("|".join(HEADERS_common_req_headers_regex_list)), re.IGNORECASE
)


@moduleman_plugin
class Headers(BasePlugin):
    name = "headers"
    author = ("Xavi Mendez (@xmendez)",)
    version = "0.1"
    summary = "Looks for HTTP headers."
    description = (
        "Looks for NEW HTTP headers:",
        "\t- Response HTTP headers associated to web servers.",
        "\t- Uncommon response HTTP headers.",
        "\t- Uncommon request HTTP headers.",
        "It is worth noting that, only the FIRST match of the above headers is registered.",
    )
    category = ["info", "passive", "default"]
    priority = 99
    parameters = ()

    def __init__(self, session):
        BasePlugin.__init__(self, session)

    def validate(self, fuzz_result):
        return True

    def check_request_header(self, header, value):
        header_value = None
        if not COMMON_REQ_HEADERS_REGEX.match(header):
            header_value = header

        if header_value is not None:
            if (
                    header_value.lower() not in self.kbase[KBASE_KEY_REQ_UNCOMMON]
                    or KBASE_KEY_REQ_UNCOMMON not in self.kbase
            ):
                self.add_information(f"New uncommon HTTP request header: "
                                     f"[u]{header_value}[/u]: [u]{value}[/u]")
                self.kbase[KBASE_KEY_REQ_UNCOMMON].append(header_value.lower())

    def check_response_header(self, fuzz_result, header):
        header_value = None
        if not COMMON_RESPONSE_HEADERS_REGEX.match(header):
            header_value = header

        if header_value is not None:
            if (
                    header_value.lower() not in self.kbase[KBASE_KEY_RESP_UNCOMMON]
                    or KBASE_KEY_RESP_UNCOMMON not in self.kbase
            ):
                self.add_information(f"New uncommon HTTP response header: "
                                     f"[u]{header_value}[/u]: [u]{header_value}[/u]")
                self.kbase[KBASE_KEY_RESP_UNCOMMON].append(header_value.lower())

    def check_server_header(self, header, value):
        if header.lower() in HEADERS_server_headers:
            if (
                    value.lower() not in self.kbase[KBASE_KEY]
                    or KBASE_KEY not in self.kbase
            ):
                self.add_information(f"New HTTP server header: [u]{value}[/u]")
                self.kbase[KBASE_KEY].append(value.lower())

    def process(self, fuzz_result):
        for header, value in fuzz_result.history.headers.request.items():
            self.check_request_header(header, value)

        for header, value in fuzz_result.history.headers.response.items():
            self.check_response_header(fuzz_result, header)
            self.check_server_header(header, value)
