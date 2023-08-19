from .facade import Facade
from urllib.parse import urlparse

from .externals.reqresp import Request, Response
from .exception import FuzzExceptBadAPI, FuzzExceptBadOptions
from .mixins import FuzzRequestUrlMixing, FuzzRequestSoupMixing

from .helpers.obj_dic import DotDict


class Headers:
    class Header(DotDict):
        def __str__(self):
            return "\n".join(["{}: {}".format(k, v) for k, v in self.items()])

    def __init__(self, req: Request):
        self._req: Request = req

    @property
    def response(self):
        return (
            Headers.Header(self._req.response.get_headers())
            if self._req.response
            else Headers.Header()
        )

    @property
    def request(self):
        return Headers.Header(self._req._headers)

    @request.setter
    def request(self, values_dict):
        self._req._headers.update(values_dict)
        if "Content-Type" in values_dict:
            self._req.ContentType = values_dict["Content-Type"]

    @property
    def all(self):
        return Headers.Header(self.request + self.response)


class Cookies:
    class Cookie(DotDict):
        def __str__(self):
            return "\n".join(["{}={}".format(k, v) for k, v in self.items()])

    def __init__(self, req: Request):
        self.req: Request = req

    @property
    def response(self):
        if self.req.response:
            c = self.req.response.get_cookie().split("; ")
            if c[0]:
                return Cookies.Cookie(
                    {x[0]: x[2] for x in [x.partition("=") for x in c]}
                )

        return Cookies.Cookie({})

    @property
    def request(self):
        if "Cookie" in self.req._headers:
            c = self.req._headers["Cookie"].split("; ")
            if c[0]:
                return Cookies.Cookie(
                    {x[0]: x[2] for x in [x.partition("=") for x in c]}
                )

        return Cookies.Cookie({})

    @request.setter
    def request(self, values):
        self.req._headers["Cookie"] = "; ".join(values)

    @property
    def all(self):
        return Cookies.Cookie(self.request + self.response)


class Params:
    class Param(DotDict):
        def __str__(self):
            return "\n".join(["{}={}".format(k, v) for k, v in self.items()])

    def __init__(self, request: Request):
        self._req: Request = request

    @property
    def get(self):
        return Params.Param({x.name: x.value for x in self._req.get_get_vars()})

    @get.setter
    def get(self, values):
        if isinstance(values, dict) or isinstance(values, DotDict):
            for key, value in values.items():
                self._req.set_variable_get(key, str(value))
        else:
            raise FuzzExceptBadAPI("GET Parameters must be specified as a dictionary")

    @property
    def post(self):
        return Params.Param({x.name: x.value for x in self._req.get_post_vars()})

    @post.setter
    def post(self, pp):
        if isinstance(pp, dict) or isinstance(pp, DotDict):
            for key, value in pp.items():
                self._req.set_variable_post(
                    key, str(value) if value is not None else value
                )

            self._req._non_parsed_post = self._req._variablesPOST.urlEncoded()

        elif isinstance(pp, str):
            self._req.set_post_data(pp)

    @property
    def raw_post(self):
        return self._req._non_parsed_post

    @property
    def all(self):
        return Params.Param(self.get + self.post)

    @all.setter
    def all(self, values):
        self.get = values
        self.post = values


class FuzzRequest(FuzzRequestUrlMixing, FuzzRequestSoupMixing):
    def __init__(self):
        self._request: Request = Request()

        self._proxy = None
        self._allvars = None
        self.wf_fuzz_methods = None
        self.wf_retries = 0
        self.wf_ip = None
        # Original url retains the URL that has been specified for fuzzing, such as http://example.com/FUZZ
        self.fuzzing_url = ""

        self.headers.request = {"User-Agent": Facade().settings.get("connection", "user-agent")}

    # methods for accessing HTTP requests information consistently across the codebase

    def __str__(self):
        return self._request.get_all()

    @property
    def raw_request(self):
        return self._request.get_all()

    @raw_request.setter
    def raw_request(self, raw_req, scheme):
        self.update_from_raw_http(raw_req, scheme)

    @property
    def raw_content(self):
        if self._request.response:
            return self._request.response.get_all()

        return ""

    @property
    def headers(self):
        return Headers(self._request)

    @property
    def params(self):
        return Params(self._request)

    @property
    def cookies(self):
        return Cookies(self._request)

    @property
    def method(self):
        return self._request.method

    @method.setter
    def method(self, method):
        self._request.method = method

    @property
    def scheme(self):
        return self._request.schema

    @scheme.setter
    def scheme(self, s):
        self._request.schema = s

    @property
    def host(self):
        return self._request.host

    @property
    def path(self) -> str:
        return self._request.path

    @property
    def url(self):
        """
        Returns the complete request URL
        """
        return self._request.complete_url

    @url.setter
    def url(self, u):
        # urlparse goes wrong with IP:port without scheme (https://bugs.python.org/issue754016)
        if not u.startswith("FUZ") and urlparse(u).netloc == "" or urlparse(u).scheme == "":
            u = "http://" + u

        if urlparse(u).path == "":
            u += "/"

        if Facade().settings.get("general", "encode_space") == "1":
            u = u.replace(" ", "%20")

        self._request.set_url(u)
        if self.scheme.startswith("fuz") and self.scheme.endswith("z"):
            # avoid FUZZ to become fuzz
            self.scheme = self.scheme.upper()

    @property
    def content(self):
        return self._request.response.get_content() if self._request.response else ""

    @content.setter
    def content(self, content):
        self._request.content = content

    @property
    def code(self):
        """
        Returns response HTTP status code
        """
        return self._request.response.code if self._request.response else 0

    @code.setter
    def code(self, c):
        self._request.response.code = int(c)

    @property
    def auth(self) -> DotDict:
        method, creds = self._request.get_auth()

        return DotDict({"method": method, "credentials": creds})

    @auth.setter
    def auth(self, creds_dict):
        self._request.set_auth(creds_dict["method"], creds_dict["credentials"])
        method, creds = self._request.get_auth()

        return DotDict({"method": method, "credentials": creds})

    @property
    def reqtime(self):
        return self._request.totaltime

    @reqtime.setter
    def reqtime(self, time):
        self._request.totaltime = time

    # Info extra that wfuzz needs within an HTTP request
    @property
    def wf_allvars_set(self):
        if self.wf_allvars == "allvars":
            return self.params.get
        elif self.wf_allvars == "allpost":
            return self.params.post
        elif self.wf_allvars == "allheaders":
            return self.headers.request
        else:
            raise FuzzExceptBadOptions("Unknown variable set: " + self.wf_allvars)

    @wf_allvars_set.setter
    def wf_allvars_set(self, varset):
        try:
            if self.wf_allvars == "allvars":
                self.params.get = varset
            elif self.wf_allvars == "allpost":
                self.params.post = varset
            elif self.wf_allvars == "allheaders":
                self._request.headers.request = varset
            else:
                raise FuzzExceptBadOptions("Unknown variable set: " + self.wf_allvars)
        except TypeError:
            raise FuzzExceptBadOptions(
                "It is not possible to use all fuzzing with duplicated parameters."
            )

    @property
    def wf_allvars(self):
        return self._allvars

    @wf_allvars.setter
    def wf_allvars(self, bl):
        if bl is not None and bl not in ["allvars", "allpost", "allheaders"]:
            raise FuzzExceptBadOptions(
                "Incorrect all parameters brute forcing type specified, correct values are allvars, allpost or "
                "allheaders. "
            )

        self._allvars = bl

    @property
    def wf_proxy(self):
        return self._proxy

    @wf_proxy.setter
    def wf_proxy(self, proxy_tuple):
        self._proxy = proxy_tuple

    @property
    def date(self):
        return self._request.date

    # methods wfuzz needs to perform HTTP requests (this might change in the future).

    def update_from_raw_http(self, raw, scheme, raw_response=None, raw_content=None) -> Request:
        self._request.parse_request(raw, scheme)

        # Parse request sets postdata = '' when there's POST request without data
        if self.method == "POST" and self.params.raw_post is None:
            self.params.post = ""

        if raw_response:
            rp = Response()
            if not isinstance(raw_response, str):
                raw_response = raw_response.decode("utf-8", errors="surrogateescape")

            rp.parse_response(raw_response, raw_content)
            self._request.response = rp

        return self._request

    def to_cache_key(self):
        key = self._request.url_without_variables
        cleaned_key = FuzzRequestUrlMixing.strip_redundant_parts(key)
        return cleaned_key

    # methods wfuzz needs for substituting payloads and building dictionaries

    def update_from_options(self, options):
        if options["url"] != "FUZZ":
            self.url = options["url"]
            self.fuzzing_url = options["url"]

        # headers must be parsed first as they might affect how reqresp parases other params
        self.headers.request = dict(options["headers"])

        if options["auth"].get("method") is not None:
            self.auth = options["auth"]

        if options["postdata"] is not None:
            self.params.post = options["postdata"]

        if options["connect_to_ip"]:
            self.wf_ip = options["connect_to_ip"]

        if options["method"]:
            self.method = options["method"]
            self.wf_fuzz_methods = options["method"]

        if options["cookie"]:
            self.cookies.request = options["cookie"]

        if options["allvars"]:
            self.wf_allvars = options["allvars"]