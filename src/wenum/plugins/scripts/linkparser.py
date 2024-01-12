from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wenum.fuzzobjects import FuzzResponse
import os
from urllib.parse import urlparse, urljoin
import pathlib

import linkfinder
from wenum.plugin_api.base import BasePlugin
from wenum.plugin_api.static_data import head_extensions, valid_codes
from wenum.externals.moduleman.plugin import moduleman_plugin


@moduleman_plugin
class Linkparser(BasePlugin):
    name = "linkparser"
    author = ("MTD",)
    version = "0.1"
    summary = "Parse and extract link from JavaScript files using linkfinder"
    description = ("Parses links from JavaScript files using linkfinder",)
    category = ["active", "discovery"]
    priority = 99

    parameters = ()

    def __init__(self, session):
        BasePlugin.__init__(self, session)
        self.linkparser_log = None
        # save to output file if file output active
        if self.session.options.output:
            self.linkparser_log = f"{self.session.options.output}_{self.name}"

    def validate(self, fuzz_result):
        return fuzz_result.code in valid_codes

    def process(self, fuzz_result: FuzzResponse):
        endpoints = linkfinder.parser_file(fuzz_result.content, linkfinder.regex_str, 0, None)
        if not endpoints:
            return

        extracted_list = []

        for result in endpoints:

            extracted_link = result["link"]

            if not extracted_link.isprintable():
                continue

            extracted_list.append(f"{extracted_link}\n")

            target_url = urljoin(fuzz_result.url, extracted_link)  # does initial fuzz url make sense?
            parsed_url = urlparse(target_url)

            filename = os.path.basename(parsed_url.path)
            extension = pathlib.Path(filename).suffix

            # dir path
            split_path = parsed_url.path.split("/")
            newpath = '/'.join(split_path[:-1]) + "/"

            # Send a request to the dir of the full URL endpoint
            dir_request = urljoin(fuzz_result.url, newpath)
            self.queue_url(dir_request)

            # add parsed path request
            if extension in head_extensions:
                self.queue_url(target_url, method="HEAD")
            else:
                self.queue_url(target_url)

        if self.linkparser_log:
            # Open file with a+ to ensure it gets created if it doesn't exist. Use the seek function to reset the
            # pointer and be able to read the current contents.
            linkparser_log_f = open(self.linkparser_log, 'a+')
            linkparser_log_f.seek(0)
            file_entries = linkparser_log_f.readlines()

            # All elements that are not yet in the current entries
            unique_lines = set(extracted_list) - set(file_entries)
            for line in unique_lines:
                linkparser_log_f.write(f'{line}')
            linkparser_log_f.close()
