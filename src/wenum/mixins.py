from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wenum.fuzzobjects import FuzzResponse
from .plugin_api.urlutils import parse_url
import socket
import itertools
from abc import abstractmethod

from urllib.parse import urljoin, urlunparse


class FuzzRequestUrlMixing:

    @property
    @abstractmethod
    def url(self):
        pass

    @property
    @abstractmethod
    def code(self):
        pass

    @property
    @abstractmethod
    def headers(self):
        pass

    @abstractmethod
    def to_cache_key(self):
        """
        Cleans the URL of any GET parameters and "soft values". Convenient when trying to compare URLs in the cache
        to determine whether a URL is a fit for recursion or not
        """
        pass

    # urlparse functions
    @property
    def urlparse(self):
        return parse_url(self.url)

    @staticmethod
    def strip_get_parameters(url) -> str:
        """
        Method to strip GET parameters of any URL
        """
        parsed_url = parse_url(url)
        url_without_params = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""))
        return url_without_params

    @property
    def redirect_header(self) -> bool:
        """
        Return True if there is a location header in the response, and False otherwise
        """
        if "Location" in self.headers.response:
            return True
        else:
            return False

    def request_found_directory(self) -> bool:
        """
        Checks for a dir as opposed to a final endpoint, e.g. a file (/login.php) or api endpoint (/api/users)
        Returns True if it is a dir.
        This isn't only a URL syntax check: it relies on the http response as well, checking whether
        the status code indicates responses typical for valid dirs.
        Returns True if it found a directory, and False if it did not.
        """
        stripped_url = self._request.url_without_variables
        if (self.code in [200, 401, 403]) and stripped_url[-1] == "/":
            return True
        else:
            return False

    def response_redirects_to_directory(self) -> bool:
        """
        Checks whether the response contains a redirection URL and whether the redirection URL points to a directory.
        Returns True if it points to a directory, and False if it doesn't. Returns False if there is no redirection URL.
        """
        if not self.redirect_header:
            return False
        redir_url = self.full_redirect_url
        redir_url_without_junk = self.strip_redundant_parts(redir_url)
        redir_url_without_vars = self.strip_get_parameters(redir_url_without_junk)
        if redir_url_without_vars[-1] == "/":
            return True
        else:
            return False

    @property
    def _redirect_url(self):
        """
        Returns the redirect URL if there is a Location header in the response,
        and an empty string if there isn't. No form of checks, or parsing of the redirect URL.
        May be relative or absolute, depending on the server response.
        Use full_redirect_url to receive the full redirection url
        """
        location = ""
        if self.redirect_header:
            location = self.headers.response["Location"]
        return location

    @property
    def full_redirect_url(self):
        """
        Returns the full redir URL. Useful to catch the case where the redir URL is relative. Will return an empty
        string if there was no Location header. Should only be used by either checking if it exists before calling,
        or properly handling an empty string after calling.
        """
        # print(self._redirect_url)
        location_parsed_url = parse_url(self._redirect_url)
        # print(location_parsed_url)
        # If scheme and netloc are missing in Location header it's probably a relative path and
        # needs to be built into a full url for further processing
        if not location_parsed_url.scheme and not location_parsed_url.netloc:
            full_redir_url = urljoin(self.url, self._redirect_url)
            location_parsed_url = parse_url(full_redir_url)
        # Rebuilding the URL
        url = urlunparse((location_parsed_url.scheme, location_parsed_url.netloc,
                          location_parsed_url.path, location_parsed_url.params,
                          location_parsed_url.query, location_parsed_url.fragment))
        return url

    @staticmethod
    def strip_redundant_parts(url: str) -> str:
        """
        Method to remove redundant parts about a URL. Will parse the path of the endpoint and remove redundant slashes
        and path parts that make no difference. Will retain everything else and return the URL
        """
        location_parsed_url = parse_url(url)
        path = location_parsed_url.path
        # If the path ends with ".", it should be treated as having no extension to it. This avoids false positives
        # between seemingly new paths on /login/test/ and /login/test/.
        if location_parsed_url.ffname == ".":
            path = location_parsed_url.path[:-1]

        # If its HTTP with ":80" appended at the end, it should be treated as though the ":80" did not get appended
        if location_parsed_url.scheme == "http" and location_parsed_url.netloc[-3:] == ":80":
            cleaned_netloc = location_parsed_url.netloc[:-3]
        # Same treatment for HTTPS/443
        elif location_parsed_url.scheme == "https" and location_parsed_url.netloc[-4:] == ":443":
            cleaned_netloc = location_parsed_url.netloc[:-4]
        else:
            cleaned_netloc = location_parsed_url.netloc

        # Magic taken from
        # https://stackoverflow.com/questions/49695477/removing-specific-duplicated-characters-from-a-string-in-python
        # Strips repeated slashes within the path. In practice, I can't think of a situation where they were not
        # ignored by the server, and if these are not stripped /hello/ and /hello// will both cause a recursion
        proper_path = "".join(k if k in "/" else "".join(v) for k, v in
                              itertools.groupby(path, lambda c: c))
        cleaned_url = urlunparse((location_parsed_url.scheme, cleaned_netloc,
                                  proper_path, location_parsed_url.params,
                                  location_parsed_url.query, location_parsed_url.fragment))
        # Path repetition, if not stripped www.example/hello and www.example.com/./hello will both
        # trigger a recursion
        cleaned_url = str(cleaned_url).replace("/./", "/")
        return cleaned_url

    def parse_recursion_url(self) -> str:
        """
        Simply parses the FuzzRequest to a proper recursion URL
        """
        recursion_url = self._request.url_without_variables
        recursion_url = self.strip_redundant_parts(recursion_url)
        return recursion_url

    def check_in_scope(self, url: str, domain_based: bool = False) -> bool:
        """
        Takes a URL and compares its scope to the base URL. Compares whether they belong to the same host.

        By default, same IP with different domain name counts as in scope.
        If the 'domain_based' is True, different domain names are out of scope.

        Returns True if the URL is in scope, and False if it is not

          #TODO The fuzzing URL is currently stored in options.url, in FuzzStats.url, and in FuzzRequest.fuzzing_url.
            This is unnecessary and should be refactored, which may result in this function
            being moved to another class as well
        """
        parsed_initial_fuzzing_url = parse_url(self.fuzzing_url)
        initial_hostname = parsed_initial_fuzzing_url.netloc.strip()
        # If there is a : in the hostname, there is a port specified for it
        # - we want to ignore the port for the scope check
        if initial_hostname.find(':') != -1:
            initial_hostname = initial_hostname[0:initial_hostname.find(':')]

        parsed_target_url = parse_url(url)
        target_hostname = parsed_target_url.netloc.strip()

        # If the target's hostname can't be derived from the response URL,
        # it should mean it is a relative path. Response is in scope accordingly
        if not target_hostname:
            return True

        try:
            # Ignore port
            if target_hostname.find(':') != -1:
                target_hostname = target_hostname[0:target_hostname.find(':')]
            target_ip = socket.gethostbyname(target_hostname)
        except:
            target_ip = "0.0.0.0"

        # Check for domain name match, if domain based check
        if domain_based:
            if initial_hostname == target_hostname:
                return True
            else:
                return False

        try:
            scope_ip = socket.gethostbyname(initial_hostname)
        # Exception thrown when the host name does not resolve. Should not be in scope in such a case either
        except socket.gaierror:
            return False

        if target_ip == scope_ip or initial_hostname == target_hostname:
            return True
        else:
            return False
