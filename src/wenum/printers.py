from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wenum.fuzzobjects import FuzzResponse, FuzzStats
import json
from .exception import FuzzExceptPluginError
import sys
from abc import abstractmethod, ABC


class BasePrinter(ABC):
    """
    Base class from which all printers should inherit.

    The design of splitting up the methods for printing to file and updating results serves two purposes:
    - Allow for reducing the amount of file writes, which may become costly (though admittedly untested assumption)
    - Ensure that the user has a valid output file even *during* the runtime, instead of an architecture where
      the file is only valid after the footer has been inserted at the end of a properly closed runtime
    """
    def __init__(self, output: str, verbose: bool):
        self.outputfile_handle = None
        # List containing every result information
        self.result_list = []
        if output:
            self.outputfile_handle = open(output, "w")
        else:
            self.outputfile_handle = sys.stdout

        self.verbose = verbose

    @abstractmethod
    def header(self, summary: FuzzStats):
        """
        Print at the beginning of the file
        """
        raise FuzzExceptPluginError("Method header not implemented")

    @abstractmethod
    def footer(self, summary: FuzzStats):
        """
        Print at the end of the file. Will also be called when runtime is done
        """
        raise FuzzExceptPluginError("Method footer not implemented")

    @abstractmethod
    def update_results(self, fuzz_result: FuzzResponse, stats: FuzzStats):
        """
        Update the result list during runtime. This does not print to file yet
        """
        raise FuzzExceptPluginError("Method result not implemented")

    @abstractmethod
    def print_to_file(self) -> None:
        """
        Overwrite output file contents with data
        """
        raise FuzzExceptPluginError("Method result not implemented")


class HTML(BasePrinter):
    def __init__(self, output, verbose):
        super().__init__(output, verbose)

    def header(self, stats):
        pass

    def update_results(self, fuzz_result, stats):
        pass

    def print_to_file(self):
        pass

    def footer(self, summary: FuzzStats):
        pass


class JSON(BasePrinter):
    name = "json"
    summary = "Results in json format"

    def __init__(self, output, verbose):
        super().__init__(output, verbose)

    def header(self, stats: FuzzStats):
        # Empty JSON header to avoid messing up the file structure
        pass

    def update_results(self, fuzz_result: FuzzResponse, stats: FuzzStats):
        location = ""
        if fuzz_result.history.redirect_header:
            location = fuzz_result.history.full_redirect_url
        server = ""
        if "Server" in fuzz_result.history.headers.response:
            server = fuzz_result.history.headers.response["Server"]
        post_data = []
        if fuzz_result.history.method.lower() == "post":
            for n, v in list(fuzz_result.history.params.post.items()):
                post_data.append({"parameter": n, "value": v})

        plugin_dict = {}

        for plugin in fuzz_result.plugins_res:
            plugin_dict.setdefault(plugin.name, [])
            # Removing ansi color escapes when logging, which plugins may
            # have inserted (magic from https://stackoverflow.com/a/14693789)
            # 7-bit C1 ANSI sequences
            ansi_escape = re.compile(r"""
                \x1B  # ESC
                (?:   # 7-bit C1 Fe (except CSI)
                    [@-Z\\-_]
                |     # or [ for CSI, followed by a control sequence
                    \[
                    [0-?]*  # Parameter bytes
                    [ -/]*  # Intermediate bytes
                    [@-~]   # Final byte
                )
            """, re.VERBOSE)
            result = ansi_escape.sub('', plugin.message)
            plugin_dict[plugin.name].append(result)

        res_entry = {
            "id": fuzz_result.id,
            "url": fuzz_result.url,
            "method": fuzz_result.history.method,
            "req_body": post_data,
            "code": fuzz_result.code,
            "lines": fuzz_result.lines,
            "words": fuzz_result.words,
            "bytes": fuzz_result.chars,
            "location": location,
            "server": server,
            "info": plugin_dict,
        }
        self.result_list.append(res_entry)
        return self.result_list

    def print_to_file(self):
        self.outputfile_handle.write(json.dumps(
            {"responses": self.result_list,
             #TODO Find more suitable name before utilizing meta-plugin output. This is dedicated for info coming
             # from the execution of meta-plugins
             # (metaplugins being plugins that do not run per-response but rather once per runtime)
             # "meta_plugins": [],
             "runtime_stats": []}
        ))
        self.outputfile_handle.flush()
        # Resetting the file pointer so that the next file write overwrites the content
        self.outputfile_handle.seek(0)

    def footer(self, stats: FuzzStats):
        # Empty JSON footer to avoid messing up the file structure
        pass
