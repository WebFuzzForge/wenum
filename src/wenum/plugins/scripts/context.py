from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wenum.fuzzobjects import FuzzResponse
import os
import pathlib
from urllib.parse import urljoin, urlparse

from wenum.plugin_api.base import BasePlugin
from wenum.plugin_api.static_data import extension_list, extension_to_tech, dir_to_tech
from wenum.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class Context(BasePlugin):
    """
    Add requests depending on the detected file extensions
    E.g. will enqueue more .php stuff if .php was detected
    Needs a specific set of wordlists to be available
    """
    name = "context"
    author = ("MTD",)
    version = "0.1"
    summary = "Create context awareness."
    description = ("Create context awareness.",)
    category = ["active", "discovery"]
    priority = 99

    parameters = ()

    @staticmethod
    def last_dir_replace(newpath):
        path = os.path.dirname(os.path.normpath(newpath))
        return os.path.join(path, '')

    def __init__(self, session):
        BasePlugin.__init__(self, session)

    def check_filter_options(self, fuzz_result):
        """
        Return False if the request is filtered out
        """
        # TODO We want to use the filter as only a display filter. Should context.py therefore also not consider
        # the filter when processing? Additionally, this is a check for simple filter statements and is ignored by
        # the autofilter or complex filter statements. If we want to uphold this logic, we need to build on it,
        # this is rather hacky
        if fuzz_result.chars in self.session.options.hs_list or fuzz_result.lines in self.session.options.hl_list or \
                fuzz_result.words in self.session.options.hw_list:
            return False
        else:
            return True

    def validate(self, fuzz_result: FuzzResponse):
        # Don't process if filtered out
        if not self.check_filter_options(fuzz_result) or fuzz_result.code not in [403, 200, 401]:
            return False

        # If a dir was found or if the response redirects to a dir
        found_dir = (fuzz_result.history.request_found_directory() or
                     fuzz_result.history.response_redirects_to_directory())
        # found a dir path AND the dir is a known tech
        if found_dir and \
                os.path.basename(os.path.normpath(fuzz_result.history.urlparse.path)).lower() in dir_to_tech:
            return True
        # If not a dir, it must be a file
        else:
            filename = os.path.basename(fuzz_result.history.urlparse.path)
            extension = pathlib.Path(filename).suffix.lower()
            # If the file extension is a known tech
            if extension in extension_to_tech:
                return True

        return False

    def process(self, fuzz_result):
        path = os.path.basename(os.path.normpath(fuzz_result.history.urlparse.path)).lower()
        # If a dir was found or if the response redirects to a dir
        found_dir = (fuzz_result.history.request_found_directory() or
                     fuzz_result.history.response_redirects_to_directory())
        # found a dir path
        if found_dir:
            # If it could not determine the tech
            if not os.path.basename(os.path.normpath(fuzz_result.history.urlparse.path)).lower() in dir_to_tech:
                return
            tech = dir_to_tech[path]
            directory = path
            original_path = fuzz_result.history.urlparse.path

        # If not a dir, it must be a file
        else:
            filename = os.path.basename(fuzz_result.history.urlparse.path)
            extension = pathlib.Path(filename).suffix.lower()

            if extension not in extension_to_tech:
                self.add_information(f"Could not determine tech")
                return

            tech = extension_to_tech[extension]

            parsed_url = urlparse(fuzz_result.url)
            filename = os.path.basename(parsed_url.path)
            directory = pathlib.Path(filename).suffix.lower()
            # dir path
            split_path = parsed_url.path.split("/")
            original_path = '/'.join(split_path[:-1]) + "/"

        self.add_information(f"Detected tech [u]{tech}[/u] in path {original_path}")
        extensions = extension_list[tech]

        try:
            # Enqueue seeds
            for extension in extensions:
                if directory == "api":
                    fuzzing_path = self.last_dir_replace(original_path) + "FUZZ" + extension
                else:
                    fuzzing_path = original_path + "FUZZ" + extension
                fuzzing_path = fuzzing_path.lstrip("/")
                fuzzing_path = "/" + fuzzing_path
                fuzzing_url = urljoin(fuzz_result.url, fuzzing_path)
                self.queue_seed(seeding_url=fuzzing_url)
        except:
            self.add_exception_information("Failed creating queue items")
