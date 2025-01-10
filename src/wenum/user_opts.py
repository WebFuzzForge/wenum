import argparse
import logging
import re
import sys
from typing import Optional
from urllib.parse import urlparse

import rich.console

from wenum import __version__ as version

from tomlkit import document, dumps, comment, TOMLDocument, load
from tomlkit.items import String, Array, Integer
from tomlkit.exceptions import ParseError

from wenum.exception import FuzzExceptBadOptions, FuzzExceptBadFile

default_threads = 40
default_request_timeout = 40
default_plugin_threads = 3
default_method = "GET"
default_iterator = "product"
default_output_format = "json"
valid_format_choices = ["json", "html", "all"]


def flatten_list(list_of_lists: list[list[str]]) -> list[str]:
    """
    Takes a list of lists and flattens it to a list.
    """
    flattened_list = []
    for string_list in list_of_lists:
        for string in string_list:
            flattened_list.append(string)
    return flattened_list


class Options:
    """
    Class responsible for handling user options
    """

    def __init__(self):
        self.url: Optional[str] = None
        # These option names will be centrally used as identifiers in the CLI and config files,
        # to avoid hard-coding strings for each use case
        self.opt_name_url: str = "url"

        self.wordlist_list: list[str] = []
        self.opt_name_wordlist: str = "wordlist"

        self.colorless: Optional[bool] = None
        self.opt_name_colorless: str = "colorless"

        self.quiet: Optional[bool] = None
        self.opt_name_quiet: str = "quiet"

        self.noninteractive: Optional[bool] = None
        self.opt_name_noninteractive: str = "noninteractive"

        self.verbose: Optional[bool] = None
        self.opt_name_verbose: str = "verbose"

        self.output: Optional[str] = None
        self.opt_name_output: str = "output"

        self.output_format: Optional[str] = None
        self.opt_name_output_format = "output-format"

        self.debug_log: Optional[str] = None
        self.opt_name_debug_log: str = "debug-log"

        self.proxy_list: list[str] = []
        self.opt_name_proxy: str = "proxy"

        self.threads: Optional[int] = None
        self.opt_name_threads: str = "threads"

        self.plugin_threads: Optional[int] = None
        self.opt_name_plugin_threads: str = "plugin-threads"

        self.sleep: Optional[int] = None
        self.opt_name_sleep: str = "sleep"

        self.location: Optional[bool] = None
        self.opt_name_location: str = "location"

        self.recursion: Optional[int] = None
        self.opt_name_recursion: str = "recursion"

        self.plugin_recursion: Optional[int] = None
        self.opt_name_plugin_recursion: str = "plugin-recursion"

        self.method: Optional[str] = None
        self.opt_name_method: str = "method"

        self.data: Optional[str] = None
        self.opt_name_data: str = "data"

        self.header_list: list[str] = []
        self.opt_name_header: str = "header"

        self.cookie: Optional[str] = None
        self.opt_name_cookie: str = "cookie"

        self.stop_error: Optional[bool] = None
        self.opt_name_stop_error: str = "stop-error"

        self.hc_list: list[str] = []
        self.opt_name_hc: str = "hc"

        self.hl_list: list[str] = []
        self.opt_name_hl: str = "hl"

        self.hw_list: list[str] = []
        self.opt_name_hw: str = "hw"

        self.hs_list: list[str] = []
        self.opt_name_hs: str = "hs"

        self.hr: Optional[str] = None
        self.opt_name_hr: str = "hr"

        self.sc_list: list[str] = []
        self.opt_name_sc: str = "sc"

        self.sl_list: list[str] = []
        self.opt_name_sl: str = "sl"

        self.sw_list: list[str] = []
        self.opt_name_sw: str = "sw"

        self.ss_list: list[str] = []
        self.opt_name_ss: str = "ss"

        self.sr: Optional[str] = None
        self.opt_name_sr: str = "sr"

        self.filter: Optional[str] = None
        self.opt_name_filter: str = "filter"

        self.hard_filter: Optional[bool] = None
        self.opt_name_hard_filter: str = "hard-filter"

        self.auto_filter: Optional[bool] = None
        self.opt_name_auto_filter: str = "auto-filter"

        self.dump_config: Optional[str] = None
        self.opt_name_dump_config: str = "dump-config"

        self.config: Optional[str] = None
        self.opt_name_config: str = "config"

        self.dry_run: Optional[bool] = None
        self.opt_name_dry_run: str = "dry-run"

        self.limit_requests: Optional[int] = None
        self.opt_name_limit_requests: str = "limit-requests"

        self.ip: Optional[str] = None
        self.opt_name_ip: str = "ip"

        self.request_timeout: Optional[int] = None
        self.opt_name_request_timeout: str = "request-timeout"

        self.domain_scope: Optional[bool] = None
        self.opt_name_domain_scope: str = "domain-scope"

        self.plugins_list: list[str] = []
        self.opt_name_plugins: str = "plugins"

        self.iterator: Optional[str] = None
        self.opt_name_iterator: str = "iterator"

        self.version: Optional[bool] = None
        self.opt_name_version: str = "version"

        self.cache_dir: Optional[str] = None
        self.opt_name_cache_dir: str = "cache-dir"

        self.extensions: list[str] = []
        self.opt_name_extensions: str = "ext"

    def __str__(self):
        return str(vars(self))

    def read_args(self, parsed_args: argparse.Namespace, console: rich.console.Console) -> None:
        """Checks all options for their validity, parses and assigns them."""

        if parsed_args.config:
            self.config = parsed_args.config
            self.import_config()

        if parsed_args.url:
            self.url = parsed_args.url

        if parsed_args.wordlist:
            self.wordlist_list = self.wordlist_list + flatten_list(parsed_args.wordlist)

        if parsed_args.colorless:
            self.colorless = parsed_args.colorless
            console.no_color = True

        if parsed_args.quiet:
            self.quiet = parsed_args.quiet

        if parsed_args.noninteractive:
            self.noninteractive = parsed_args.noninteractive

        if parsed_args.verbose:
            self.verbose = parsed_args.verbose

        if parsed_args.output:
            self.output = parsed_args.output

        if parsed_args.debug_log:
            logger = logging.getLogger("debug_log")
            logger.propagate = False
            logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%d.%m.%Y %H:%M:%S")
            handler = logging.FileHandler(filename=parsed_args.debug_log)
            handler.setLevel(logging.DEBUG)
            logger.handlers.clear()
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        self.debug_log = parsed_args.debug_log

        if parsed_args.proxy:
            self.proxy_list = self.proxy_list + flatten_list(parsed_args.proxy)

        if parsed_args.threads:
            self.threads = parsed_args.threads

        if parsed_args.plugin_threads:
            self.plugin_threads = parsed_args.plugin_threads

        if parsed_args.sleep:
            self.sleep = parsed_args.sleep

        if parsed_args.location:
            self.location = parsed_args.location

        if parsed_args.recursion:
            self.recursion = parsed_args.recursion

        if parsed_args.plugin_recursion:
            self.plugin_recursion = parsed_args.plugin_recursion

        if parsed_args.method:
            self.method = parsed_args.method

        if parsed_args.data:
            self.data = parsed_args.data

        if parsed_args.header:
            self.header_list = self.header_list + flatten_list(parsed_args.header)

        if parsed_args.cookie:
            self.cookie = parsed_args.cookie

        if parsed_args.stop_error:
            self.stop_error = parsed_args.stop_error

        if parsed_args.hc:
            self.hc_list = self.hc_list + flatten_list(parsed_args.hc)

        if parsed_args.hw:
            self.hw_list = self.hw_list + flatten_list(parsed_args.hw)

        if parsed_args.hl:
            self.hl_list = self.hl_list + flatten_list(parsed_args.hl)

        if parsed_args.hs:
            self.hs_list = self.hs_list + flatten_list(parsed_args.hs)

        if parsed_args.hr:
            self.hr = parsed_args.hr

        if parsed_args.sc:
            self.sc_list = self.sc_list + flatten_list(parsed_args.sc)

        if parsed_args.sw:
            self.sw_list = flatten_list(parsed_args.sw)

        if parsed_args.sl:
            self.sl_list = flatten_list(parsed_args.sl)

        if parsed_args.ss:
            self.ss_list = flatten_list(parsed_args.ss)

        if parsed_args.sr:
            self.sr = parsed_args.sr

        if parsed_args.filter:
            self.filter = parsed_args.filter

        if parsed_args.hard_filter:
            self.hard_filter = parsed_args.hard_filter

        if parsed_args.auto_filter:
            self.auto_filter = parsed_args.auto_filter

        if parsed_args.dump_config:
            self.dump_config = parsed_args.dump_config

        if parsed_args.dry_run:
            self.dry_run = parsed_args.dry_run

        if parsed_args.limit_requests:
            self.limit_requests = parsed_args.limit_requests

        if parsed_args.ip:
            self.ip = parsed_args.ip

        if parsed_args.request_timeout:
            self.request_timeout = parsed_args.request_timeout

        if parsed_args.domain_scope:
            self.domain_scope = parsed_args.domain_scope

        if parsed_args.plugins:
            self.plugins_list = flatten_list(parsed_args.plugins)

        if parsed_args.iterator:
            self.iterator = parsed_args.iterator

        if parsed_args.cache_dir:
            self.cache_dir = parsed_args.cache_dir

        if parsed_args.ext:
            self.extensions = flatten_list(parsed_args.ext)

    def get_all_opts(self) -> list[tuple]:
        """
        Returns all option parameters in a list of tuples,
        whereas tuple[0] is opt_name and tuple[1] is opt_value
        """
        all_opts = [
            (self.opt_name_url, self.url),
            (self.opt_name_wordlist, self.wordlist_list),
            (self.opt_name_colorless, self.colorless),
            (self.opt_name_quiet, self.quiet),
            (self.opt_name_noninteractive, self.noninteractive),
            (self.opt_name_verbose, self.verbose),
            (self.opt_name_output, self.output),
            (self.opt_name_output_format, self.output_format),
            (self.opt_name_debug_log, self.debug_log),
            (self.opt_name_proxy, self.proxy_list),
            (self.opt_name_threads, self.threads),
            (self.opt_name_plugin_threads, self.plugin_threads),
            (self.opt_name_sleep, self.sleep),
            (self.opt_name_location, self.location),
            (self.opt_name_recursion, self.recursion),
            (self.opt_name_plugin_recursion, self.plugin_recursion),
            (self.opt_name_method, self.method),
            (self.opt_name_data, self.data),
            (self.opt_name_header, self.header_list),
            (self.opt_name_cookie, self.cookie),
            (self.opt_name_stop_error, self.stop_error),
            (self.opt_name_hc, self.hc_list),
            (self.opt_name_hw, self.hw_list),
            (self.opt_name_hl, self.hl_list),
            (self.opt_name_hs, self.hs_list),
            (self.opt_name_hr, self.hr),
            (self.opt_name_sc, self.sc_list),
            (self.opt_name_sw, self.sw_list),
            (self.opt_name_sl, self.sl_list),
            (self.opt_name_ss, self.ss_list),
            (self.opt_name_sr, self.sr),
            (self.opt_name_filter, self.filter),
            (self.opt_name_auto_filter, self.auto_filter),
            (self.opt_name_dump_config, self.dump_config),
            (self.opt_name_config, self.config),
            (self.opt_name_hard_filter, self.hard_filter),
            (self.opt_name_dry_run, self.dry_run),
            (self.opt_name_limit_requests, self.limit_requests),
            (self.opt_name_ip, self.ip),
            (self.opt_name_request_timeout, self.request_timeout),
            (self.opt_name_domain_scope, self.domain_scope),
            (self.opt_name_plugins, self.plugins_list),
            (self.opt_name_iterator, self.iterator),
            (self.opt_name_version, self.version),
            (self.opt_name_cache_dir, self.cache_dir),
            (self.opt_name_extensions, self.extensions),
                    ]

        return all_opts

    def export_config(self):
        """
        Exports the activated configuration (through CLI + optional config file) into a TOML file.

        All TOML keys are named according to the corresponding command line option names.
        The TOML file also is formatted without any tables, as it can be confusing to the user trying to find out
        which table an option belongs to.
        """
        # Using tomlkit for writing, as tomllib does not provide a way to do so
        doc = document()
        doc.add(comment("All keys are named equal to the command line options."))
        doc.add(comment("If you struggle creating the TOML by hand, "))
        doc.add(comment(f"you can use the --{self.opt_name_dump_config} option of wenum"))
        doc.add(comment("to export the specified options to a config file"))
        doc.add(comment("and use it as a reference."))
        doc.add(comment(""))
        for opt_name, opt_value in self.get_all_opts():
            self.add_toml_if_exists(doc, opt_name, opt_value)
        try:
            with open(self.dump_config, "w") as file:
                file.writelines(dumps(doc))
        except OSError:
            raise FuzzExceptBadFile("Specified file path could not be opened for exporting the config. Please ensure "
                                    "it is a valid path and it is accessible.")

    def import_config(self) -> None:
        """
        Imports the config from the given option path.

        Does strict type checking of supplied values and also errors if the user supplied unknown keys to ensure that
        user typos do not get silently ignored when users supply their config.
        Only modifies options if they have been explicitly set.
        """
        try:
            with open(self.config, "rb") as file:
                toml_dict: TOMLDocument = load(file)
        except OSError:
            raise FuzzExceptBadFile(f"Config {self.config} can not be opened.")
        except ParseError as e:
            raise FuzzExceptBadOptions(f"The config file {self.config} does not contain valid TOML. "
                                       f"Please check the syntax. Exception: {e}")

        if self.opt_name_url in toml_dict:
            self.url = self.pop_toml_string(toml_dict, self.opt_name_url)

        if self.opt_name_wordlist in toml_dict:
            self.wordlist_list += self.pop_toml_list_str(toml_dict, self.opt_name_wordlist)

        if self.opt_name_colorless in toml_dict:
            self.colorless = self.pop_toml_bool(toml_dict, self.opt_name_colorless)

        if self.opt_name_quiet in toml_dict:
            self.quiet = self.pop_toml_bool(toml_dict, self.opt_name_quiet)

        if self.opt_name_noninteractive in toml_dict:
            self.noninteractive = self.pop_toml_bool(toml_dict, self.opt_name_noninteractive)

        if self.opt_name_verbose in toml_dict:
            self.verbose = self.pop_toml_bool(toml_dict, self.opt_name_verbose)

        if self.opt_name_output in toml_dict:
            self.output = self.pop_toml_string(toml_dict, self.opt_name_output)

        if self.opt_name_output_format in toml_dict:
            self.output_format = self.pop_toml_string(toml_dict, self.opt_name_output_format)

        if self.opt_name_debug_log in toml_dict:
            self.debug_log = self.pop_toml_string(toml_dict, self.opt_name_debug_log)

        if self.opt_name_proxy in toml_dict:
            self.proxy_list += self.pop_toml_list_str(toml_dict, self.opt_name_proxy)

        if self.opt_name_threads in toml_dict:
            self.threads = self.pop_toml_int(toml_dict, self.opt_name_threads)

        if self.opt_name_plugin_threads in toml_dict:
            self.plugin_threads = self.pop_toml_int(toml_dict, self.opt_name_plugin_threads)

        if self.opt_name_sleep in toml_dict:
            self.sleep = self.pop_toml_int(toml_dict, self.opt_name_sleep)

        if self.opt_name_location in toml_dict:
            self.location = self.pop_toml_bool(toml_dict, self.opt_name_location)

        if self.opt_name_recursion in toml_dict:
            self.recursion = self.pop_toml_int(toml_dict, self.opt_name_recursion)

        if self.opt_name_plugin_recursion in toml_dict:
            self.plugin_recursion = self.pop_toml_int(toml_dict, self.opt_name_plugin_recursion)

        if self.opt_name_method in toml_dict:
            self.method = self.pop_toml_string(toml_dict, self.opt_name_method)

        if self.opt_name_data in toml_dict:
            self.data = self.pop_toml_string(toml_dict, self.opt_name_data)

        if self.opt_name_header in toml_dict:
            self.header_list += self.pop_toml_list_str(toml_dict, self.opt_name_header)

        if self.opt_name_cookie in toml_dict:
            self.cookie = self.pop_toml_string(toml_dict, self.opt_name_cookie)

        if self.opt_name_stop_error in toml_dict:
            self.stop_error = self.pop_toml_bool(toml_dict, self.opt_name_stop_error)

        if self.opt_name_hc in toml_dict:
            self.hc_list += self.pop_toml_list_int(toml_dict, self.opt_name_hc)

        if self.opt_name_hw in toml_dict:
            self.hw_list += self.pop_toml_list_int(toml_dict, self.opt_name_hw)

        if self.opt_name_hl in toml_dict:
            self.hl_list += self.pop_toml_list_int(toml_dict, self.opt_name_hl)

        if self.opt_name_hs in toml_dict:
            self.hs_list += self.pop_toml_list_int(toml_dict, self.opt_name_hs)

        if self.opt_name_hr in toml_dict:
            self.hr = self.pop_toml_string(toml_dict, self.opt_name_hr)

        if self.opt_name_sc in toml_dict:
            self.sc_list += self.pop_toml_list_int(toml_dict, self.opt_name_sc)

        if self.opt_name_sw in toml_dict:
            self.sw_list += self.pop_toml_list_int(toml_dict, self.opt_name_sw)

        if self.opt_name_sl in toml_dict:
            self.sl_list += self.pop_toml_list_int(toml_dict, self.opt_name_sl)

        if self.opt_name_ss in toml_dict:
            self.ss_list += self.pop_toml_list_int(toml_dict, self.opt_name_ss)

        if self.opt_name_sr in toml_dict:
            self.sr = self.pop_toml_string(toml_dict, self.opt_name_sr)

        if self.opt_name_filter in toml_dict:
            self.filter = self.pop_toml_string(toml_dict, self.opt_name_filter)

        if self.opt_name_hard_filter in toml_dict:
            self.hard_filter = self.pop_toml_bool(toml_dict, self.opt_name_hard_filter)

        if self.opt_name_auto_filter in toml_dict:
            self.auto_filter = self.pop_toml_bool(toml_dict, self.opt_name_auto_filter)

        if self.opt_name_dry_run in toml_dict:
            self.dry_run = self.pop_toml_bool(toml_dict, self.opt_name_dry_run)

        if self.opt_name_limit_requests in toml_dict:
            self.limit_requests = self.pop_toml_int(toml_dict, self.opt_name_limit_requests)

        if self.opt_name_request_timeout in toml_dict:
            self.request_timeout = self.pop_toml_int(toml_dict, self.opt_name_request_timeout)

        if self.opt_name_ip in toml_dict:
            self.ip = self.pop_toml_string(toml_dict, self.opt_name_ip)

        if self.opt_name_domain_scope in toml_dict:
            self.domain_scope = self.pop_toml_bool(toml_dict, self.opt_name_domain_scope)

        if self.opt_name_plugins in toml_dict:
            self.plugins_list += self.pop_toml_list_str(toml_dict, self.opt_name_plugins)

        if self.opt_name_iterator in toml_dict:
            self.iterator = self.pop_toml_string(toml_dict, self.opt_name_iterator)

        if self.opt_name_version in toml_dict:
            self.version = self.pop_toml_bool(toml_dict, self.opt_name_version)

        if self.opt_name_cache_dir in toml_dict:
            self.cache_dir = self.pop_toml_string(toml_dict, self.opt_name_cache_dir)

        if self.opt_name_extensions in toml_dict:
            self.extensions += self.pop_toml_list_str(toml_dict, self.opt_name_extensions)

        # If any keys are left
        if toml_dict:
            unknown_keys = []
            for key in toml_dict:
                unknown_keys.append(key)
            raise FuzzExceptBadOptions(f"Unknown keys {unknown_keys} were supplied in the config file. "
                                       f"Please check for typos.")

    @staticmethod
    def pop_toml_list_str(toml_dict: TOMLDocument, toml_key: str) -> list[str]:
        """
        Throws an exception if the type of the toml key is not a list of strings. Pops value from dict if it is.
        Converts the type to pure Python classes.
        """
        string_list = toml_dict.pop(toml_key)
        if type(string_list) != Array:
            raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file is not a list")
        string_list = string_list.unwrap()
        for index, item in enumerate(string_list):
            if type(item) != str:
                raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file "
                                           f"contains a nonstring item: {item}")
        return string_list

    @staticmethod
    def pop_toml_list_int(toml_dict: TOMLDocument, toml_key: str) -> list[int]:
        """
        Throws an exception if the type of the toml key is not a list of strings. Pops value from dict if it is.
        """
        integer_list = toml_dict.pop(toml_key)
        if type(integer_list) != Array:
            raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file is not a list")
        integer_list = integer_list.unwrap()
        for index, item in enumerate(integer_list):
            if type(item) != int:
                raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file "
                                           f"contains a nonint item: {item}")
        return integer_list

    @staticmethod
    def pop_toml_bool(toml_dict: TOMLDocument, toml_key: str) -> bool:
        """
        Throws an exception if the type of the toml key is not a bool. Pops value from dict if it is.
        """
        boolean = toml_dict.pop(toml_key)
        if type(boolean) != bool:
            raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file is not a bool")
        return boolean

    @staticmethod
    def pop_toml_string(toml_dict: TOMLDocument, toml_key: str) -> str:
        """
        Throws an exception if the type of the toml key is not a string. Pops value from dict if it is.
        """
        standard_string = toml_dict.pop(toml_key)
        if type(standard_string) != String:
            raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file is not a string")
        standard_string = standard_string.unwrap()

        return standard_string

    @staticmethod
    def pop_toml_int(toml_dict: TOMLDocument, toml_key: str) -> int:
        """
        Throws an exception if the type of the toml key is not an int. Pops value from dict if it is.
        """
        integer = toml_dict.pop(toml_key)
        if type(integer) != Integer:
            raise FuzzExceptBadOptions(f"\"{toml_key}\" option's value in the config file is not an int")
        integer = integer.unwrap()
        return integer

    def basic_validate(self) -> None:
        """
        Check initially set opts.

        Sets defaults where adequate, and throws errors on faulty states.
        """
        if self.version:
            print(f"wenum version: {version}")
            sys.exit(0)

        if not self.threads:
            self.threads = default_threads

        if not self.plugin_threads:
            self.plugin_threads = default_plugin_threads

        if not self.method:
            self.method = default_method

        if not self.request_timeout:
            self.request_timeout = default_request_timeout

        if not self.recursion:
            self.recursion = 0

        if not self.plugin_recursion:
            self.plugin_recursion = self.recursion

        if self.output_format:
            if self.output_format not in valid_format_choices:
                raise FuzzExceptBadOptions(f"Output format does not exist")
        else:
            self.output_format = default_output_format

        if self.url is None:
            raise FuzzExceptBadOptions(f"Specify the URL with --{self.opt_name_url}")

        if not self.wordlist_list:
            raise FuzzExceptBadOptions("Bad usage: You must specify a wordlist.")

        for wordlist in self.wordlist_list:
            try:
                open(wordlist, "r")
            except OSError:
                raise FuzzExceptBadFile(f"Wordlist {wordlist} can not be opened. Please ensure it "
                                        f"exists and the permissions are correct.")

        if self.output:
            try:
                open(self.output, "w")
            except OSError:
                raise FuzzExceptBadFile(f"Output file {self.output} can not be opened. Please ensure it is a valid path"
                                        f"with valid permissions.")

        if self.debug_log:
            try:
                open(self.debug_log, "a")
            except OSError:
                raise FuzzExceptBadFile(f"Debug file {self.debug_log} can not be opened. "
                                        f"Please ensure it is a valid path with valid permissions.")

        if self.sleep and self.sleep < 0:
            raise FuzzExceptBadOptions("Can not sleep for a negative time.")

        if self.threads < 0:
            raise FuzzExceptBadOptions("Threads can not be a negative number.")

        for header in self.header_list:
            split_header = header.split(":", maxsplit=1)
            if len(split_header) != 2:
                raise FuzzExceptBadOptions("Please provide the header in the format 'name: value'")

        if self.recursion < 0 or self.plugin_recursion < 0:
            raise FuzzExceptBadOptions("Can not set a negative recursion limit.")

        for proxy in self.proxy_list:
            parsed_proxy = urlparse(proxy)
            if parsed_proxy.scheme.lower() not in ["socks4", "socks5", "http"]:
                raise FuzzExceptBadOptions(
                    "The supplied proxy protocol is not supported. Please use SOCKS4, SOCKS5, "
                    "or HTTP.")
            if ":" not in parsed_proxy.netloc:
                raise FuzzExceptBadOptions("Please supply the port that should be used for the proxy.")
            split_netloc = parsed_proxy.netloc.split(":")
            if not len(split_netloc) == 2:
                raise FuzzExceptBadOptions("Please ensure that the proxy string contains exactly one colon.")
            try:
                int(split_netloc[1])
            except ValueError:
                raise FuzzExceptBadOptions("Please ensure that the proxy string's port is numeric.")

        if self.ip:
            # Regex for validating an IP address
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

            ip = self.ip

            split_ip = ip.split(":")

            if len(split_ip) == 2:
                try:
                    int(split_ip[1])
                except ValueError:
                    raise FuzzExceptBadOptions(
                        f"Please ensure that the port of the --{self.opt_name_ip} argument is numeric.")
                if not (re.search(regex, split_ip[0])):
                    raise FuzzExceptBadOptions(
                        f"Please ensure that the IP address of the --{self.opt_name_ip} argument is valid")
                self.ip = ip
            else:
                raise FuzzExceptBadOptions(
                    f"Please ensure that the --{self.opt_name_ip} argument string contains one colon.")

        if ((self.hw_list or self.hc_list or self.hl_list or self.hs_list or self.hr) and
                (self.sw_list or self.sc_list or self.sl_list or self.ss_list or self.sr)):
            raise FuzzExceptBadOptions("Bad usage: Hide and show flags are mutually exclusive.")

        if len(self.wordlist_list) == 1 and self.iterator:
            raise FuzzExceptBadOptions("Several dictionaries must be used when specifying an iterator.")

        if not self.wordlist_list:
            raise FuzzExceptBadOptions("At least one wordlist needs to be specified.")

        if not self.url:
            raise FuzzExceptBadOptions("A target URL needs to be specified.")

        if self.plugins_list and self.dry_run:
            raise FuzzExceptBadOptions(
                "Bad usage: Plugins cannot work without making any HTTP request."
            )

        if self.dump_config:
            try:
                open(self.dump_config, "w")
            except OSError:
                raise FuzzExceptBadFile(f"Config export file can not be opened. Please ensure it is a valid path"
                                        f"and the permissions to the path are correct.")

        if self.extensions:
            for extension in self.extensions:
                ext = extension.split(",")
                for e in ext:
                    if not e.startswith("."):
                        raise FuzzExceptBadOptions(f"Extension {e} does not start with a dot. Please ensure that it is a valid file extension.")

    def add_toml_if_exists(self, doc: TOMLDocument, key: str, value):
        """Convenience function to enable one-liners when building the TOML config."""
        if value:
            # For some reason, the sleep parameter would get converted to a float by default
            if isinstance(value, float):
                value = int(value)
            # Do not store these parameters in the config file, as they would lead to confusing behavior
            if key == self.opt_name_dump_config or key == self.opt_name_config:
                return
            doc.add(key, value)

    def configure_parser(self) -> argparse.ArgumentParser:
        """
        argparse setup.
        Default values should not be set here. The session reads from a config file, and overwrites the file options
        if the command line has a conflicting flag. If argparse specifies defaults here, the file options will always be
        overwritten, even if the user does not intend to do so.
        """
        parser = argparse.ArgumentParser(prog="wenum",
                                         description="A Web Fuzzer. The options follow the curl schema where possible.",
                                         epilog="Examples")

        request_building_group = parser.add_argument_group("Request building options")
        response_proessing_group = parser.add_argument_group("Response processing options")
        io_group = parser.add_argument_group("Input/Output options")
        terminal_group = parser.add_argument_group("Terminal options")

        terminal_group.add_argument("-c", f"--{self.opt_name_colorless}", action="store_true",
                                    help="Disable colors in CLI output.")
        terminal_group.add_argument("-q", f"--{self.opt_name_quiet}", action="store_true",
                                    help="Disable progress messages in CLI output.")
        terminal_group.add_argument("-n", f"--{self.opt_name_noninteractive}", action="store_true",
                                    help="Disable runtime interactions.")
        terminal_group.add_argument("-v", f"--{self.opt_name_verbose}", action="store_true",
                                    help="Enable verbose information in CLI output.")

        io_group.add_argument("-w", f"--{self.opt_name_wordlist}", action="append",
                              help="Specify a wordlist file to iterate through.", nargs="*")
        io_group.add_argument("-o", f"--{self.opt_name_output}",
                              help="Store results in the specified output file.")
        io_group.add_argument("-f", f"--{self.opt_name_output_format}",
                              help=f"Set the format of the output file. If you specify \"all\", each format will be "
                                   f"used as a suffix for the specified output path. "
                                   f"(default: {default_output_format})",
                              choices=valid_format_choices)
        io_group.add_argument("-l", f"--{self.opt_name_debug_log}",
                              help="Store runtime information in the specified file.")
        io_group.add_argument(f"--{self.opt_name_dump_config}",
                              help="Write all supplied options to a config file and exit.")
        io_group.add_argument("-K", f"--{self.opt_name_config}",
                              help="Read config from specified path. ")
        io_group.add_argument(f"--{self.opt_name_plugins}", action="append",
                              help="Plugins to be run, supplied as a list of plugin-files or plugin-categories",
                              nargs="*")
        io_group.add_argument(f"--{self.opt_name_cache_dir}", help="Specify a directory to read cached requests from.")

        request_building_group.add_argument("-u", f"--{self.opt_name_url}", help="Specify a URL for the request.")
        request_building_group.add_argument("-p", f"--{self.opt_name_proxy}", action="append",
                                            help="Proxy requests. Use format 'protocol://ip:port'. "
                                                 "Protocols SOCKS4, SOCKS5 and HTTP are supported. If "
                                                 "supplied multiple"
                                                 "times, the requests will be split between all "
                                                 "supplied proxies.", nargs="*")
        # request_building_group.add_argument("-P", "--replay-proxy", help="Send requests that were not filtered through the specified proxy. Format and conditions match -p.")#TODO implement
        request_building_group.add_argument("-t", f"--{self.opt_name_threads}", type=int,
                                            help="Modify the number of concurrent \"threads\"/connections "
                                                 f"for requests. (default: {default_threads})")
        request_building_group.add_argument("-s", f"--{self.opt_name_sleep}", type=float,
                                            help="Wait supplied seconds between requests.")
        request_building_group.add_argument("-X", f"--{self.opt_name_method}",
                                            help=f"Set the HTTP method used for requests. (default: {default_method})")
        request_building_group.add_argument("-d", f"--{self.opt_name_data}",
                                            help="Use POST method with supplied data (e.g. \"id=FUZZ&catalogue=1\"). "
                                                 f"Method can be overridden with --{self.opt_name_method}.")
        request_building_group.add_argument("-H", f"--{self.opt_name_header}", action="append",
                                            help="Add/modify a header, e.g. \"User-Agent: Changed\". "
                                                 "Multiple flags accepted.", nargs="*")
        request_building_group.add_argument("-b", f"--{self.opt_name_cookie}",
                                            help="Add cookies, e.g. \"Cookie1=foo; Cookie2=bar\".")
        request_building_group.add_argument(f"--{self.opt_name_dry_run}", action="store_true",
                                            help="Test run without actually making any HTTP request.")
        request_building_group.add_argument(f"--{self.opt_name_ip}",
                                            help="Specify an IP to connect to. Format ip:port. "
                                                 "Uses port 80 if none specified. "
                                                 "This can help if you want to force connecting to a specific "
                                                 "IP and still present a "
                                                 "host name in the SNI, which will remain the URL's host.")  # TODO Change from --ip to --sni, which allows for same featureset and feels less convoluted next to --url
        request_building_group.add_argument("-i", f"--{self.opt_name_iterator}",
                                            help="Set the iterator used when combining "
                                                 f"multiple wordlists. (default: {default_iterator})",
                                            choices=["product", "zip", "chain"])

        request_building_group.add_argument("-e", f"--{self.opt_name_extensions}", action="append",
                                            help="Specify extensions to be appended to the wordlist items e.g. \".aspx,.asmx\"", nargs="*")

        filter_group = parser.add_argument_group("Filter options")
        filter_group.add_argument(f"--{self.opt_name_hc}", action="append",
                                  help=f"Hide responses matching the supplied codes "
                                       f"(e.g. --{self.opt_name_hc} 302 404 405).",
                                  nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_hl}", action="append",
                                  help="Hide responses matching the supplied lines.",
                                  nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_hw}", action="append",
                                  help="Hide responses matching the supplied words.",
                                  nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_hs}", action="append",
                                  help="Hide responses matching the supplied sizes/chars.", nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_hr}", help="Hide responses matching the supplied regex.")
        filter_group.add_argument(f"--{self.opt_name_sc}", action="append",
                                  help="Show responses matching the supplied codes.",
                                  nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_sl}", action="append",
                                  help="Show responses matching the supplied lines.",
                                  nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_sw}", action="append",
                                  help="Show responses matching the supplied words.",
                                  nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_ss}", action="append",
                                  help="Show responses matching the supplied sizes/chars.", nargs="*", type=int)
        filter_group.add_argument(f"--{self.opt_name_sr}", help="Show responses matching the supplied regex.")
        filter_group.add_argument(f"--{self.opt_name_filter}", help="Show/hide responses using the supplied regex.")
        # parser.add_argument("--pre-filter", help="Filter items before fuzzing using the specified expression. Repeat for concatenating filters.")#TODO Current prefilter function is not what we want it to be. We want to provide a means to block sending requests that contain a specific request, e.g. because dynamically generated by plugins.
        # parser.add_argument("--filter-help", action="store_true", help="Show the filter language specification.")#TODO May be phased out with the generic info option, currently broken
        filter_group.add_argument(f"--{self.opt_name_hard_filter}", action="store_true",
                                  help="Don't only hide the responses, but also prevent post "
                                       "processing of them (e.g. sending to plugins).")
        filter_group.add_argument(f"--{self.opt_name_auto_filter}", action="store_true",
                                  help="Filter automatically during runtime. "
                                       "If a response occurs too often, it will get filtered out.")

        response_proessing_group.add_argument("-L", f"--{self.opt_name_location}", action="store_true",
                                              help="Follow redirections by sending "
                                                   "an additional request to the redirection URL if it's in scope.")
        response_proessing_group.add_argument("-R", f"--{self.opt_name_recursion}", type=int,
                                              help="Enable recursive path discovery by specifying a maximum depth.")
        response_proessing_group.add_argument("-r", f"--{self.opt_name_plugin_recursion}", type=int,
                                              help="Adjust the max depth for recursions originating from plugins. "
                                                   f"Matches --{self.opt_name_recursion} by default.")
        # request_processing_group.add_argument("-e", "--stop-errors", action="store_true", help="Stop when 10 errors were detected")#TODO Implement
        response_proessing_group.add_argument("-E", f"--{self.opt_name_stop_error}", action="store_true",
                                              help="Stop on any connection error.")
        response_proessing_group.add_argument(f"--{self.opt_name_limit_requests}", type=int,
                                              help="Limit recursions. Once specified amount of requests are sent, "
                                                   "recursions will be deactivated")
        response_proessing_group.add_argument(f"--{self.opt_name_request_timeout}", type=int,
                                              help="Change the maximum seconds the request is allowed to take. "
                                                   f"(default: {default_request_timeout})")
        response_proessing_group.add_argument(f"--{self.opt_name_domain_scope}", action="store_true",
                                              help="Base the scope check on the domain name instead of IP.")
        response_proessing_group.add_argument(f"--{self.opt_name_plugin_threads}", type=int,
                                              help="Modify the amount of threads used for concurrent "
                                              f"execution of plugins. (default: {default_plugin_threads})")

        # parser.add_argument("--list-plugins", help="List all plugins and categories")#TODO implement, though maybe this falls off with the info option
        # parser.add_argument("--plugin-args", help="Provide arguments to scripts. e.g. --plugin-args grep.regex=\"<A href=\\\"(.*?)\\\">\"", nargs="*")#TODO Maybe remove? Really no plugin utilizes this except for regex.py, and I dont know if they ever will

        # parser.add_argument("info", help="Print information about the specified topic and exit.", choices=["plugins", "iterators", "filter"])#TODO implement, and this feels like a good positional argument. Probably because by design the user should not use it in combination with anything else
        parser.add_argument("-V", f"--{self.opt_name_version}", action="store_true", help="Print version and exit.")

        return parser

    def header_dict(self) -> dict:
        """
        Returns the headers in dict instead of list form. Returns None if no headers have been set
        """
        header_dict: dict = {}
        if not self.header_list:
            return {}
        for header in self.header_list:
            split_header = header.split(":", maxsplit=1)
            header_dict[split_header[0]] = split_header[1].strip()
        return header_dict

