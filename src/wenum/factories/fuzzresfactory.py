import copy

from .fuzzfactory import reqfactory
from .payman import payman_factory

from ..fuzzobjects import FuzzResult, FuzzType, FuzzWord, FuzzWordType
from ..helpers.obj_factory import ObjectFactory, SeedBuilderHelper
import logging


class FuzzResultFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "fuzzres_from_options_and_dict": FuzzResultDictioBuilder(),
                "fuzzres_from_fuzzres": FuzzResBackfeedBuilder(),
                "fuzzres_from_message": FuzzResMessageBuilder(),
                "seed_from_recursion": FuzzResSeedBuilder(),
                "seed_from_plugin": FuzzResPluginSeedBuilder(),
                "seed_from_options": FuzzResOptionsSeedBuilder(),
            },
        )


class FuzzResultDictioBuilder:
    def __call__(self, session, dictio_item):
        fuzz_result: FuzzResult = copy.deepcopy(session.compiled_seed)
        fuzz_result.item_type = FuzzType.RESULT
        fuzz_result.payload_man.update_from_dictio(dictio_item)
        fuzz_result.from_plugin = False

        SeedBuilderHelper.replace_markers(fuzz_result.history, fuzz_result.payload_man)
        fuzz_result.result_id = next(FuzzResult.newid)

        return fuzz_result


class FuzzResOptionsSeedBuilder:
    def __call__(self, session) -> FuzzResult:
        seed = reqfactory.create("seed_from_options", session)
        fuzz_result = FuzzResult(seed)
        fuzz_result.payload_man = payman_factory.create("payloadman_from_request", seed)
        fuzz_result.from_plugin = False

        return fuzz_result


class FuzzResSeedBuilder:
    """
    Create a new seed. Polls the recursion URL from the seed object's response.
    """

    def __call__(self, originating_fuzzresult: FuzzResult) -> FuzzResult:
        try:
            seeding_url = originating_fuzzresult.history.parse_recursion_url() + "FUZZ"
            new_seed: FuzzResult = copy.deepcopy(originating_fuzzresult)
            new_seed.history.url = seeding_url
            # Plugin rlevel should be increased in case the new seed results out of a backfed
            # (and therefore plugin) object
            if originating_fuzzresult.from_plugin:
                new_seed.plugin_rlevel += 1
            elif not originating_fuzzresult.from_plugin:
                new_seed.rlevel += 1
            # The plugin results of the response before are irrelevant for the new request
            new_seed.plugins_res = []
            if new_seed.rlevel_desc:
                new_seed.rlevel_desc += " - "
            new_seed.rlevel_desc += f"Seed originating from URL {originating_fuzzresult.url}"
            new_seed.item_type = FuzzType.SEED
            new_seed.from_plugin = False
            new_seed.discarded = False
            new_seed.payload_man = payman_factory.create(
                "payloadman_from_request", new_seed.history
            )
        except RuntimeError as exception:
            logger = logging.getLogger("debug_log")
            logger.exception("An exception occured in FuzzResSeedBuilder")
            exit()

        return new_seed


class FuzzResPluginSeedBuilder:
    """
    Create a new seed. Used by plugins.
    Takes a seeding_url that will be taken as a FUZZ URL instead of directly polling the recursion URL
    """

    def __call__(self, seed: FuzzResult, seeding_url: str) -> FuzzResult:
        try:
            if not seeding_url:
                seeding_url = seed.history.parse_recursion_url() + "FUZZ"
            new_seed: FuzzResult = copy.deepcopy(seed)
            new_seed.history.url = seeding_url
            new_seed.plugin_rlevel += 1
            # The plugin results of the response before are irrelevant for the new request
            new_seed.plugins_res = []
            if new_seed.rlevel_desc:
                new_seed.rlevel_desc += " - "
            new_seed.rlevel_desc += f"Seed originating from URL {seed.url}"
            new_seed.item_type = FuzzType.SEED
            new_seed.from_plugin = False
            new_seed.discarded = False
            new_seed.payload_man = payman_factory.create(
                "payloadman_from_request", new_seed.history
            )
        except RuntimeError as exception:
            logger = logging.getLogger("debug_log")
            logger.exception("An exception occured in FuzzResPluginSeedBuilder")
            exit()
        return new_seed


class FuzzResBackfeedBuilder:
    """
    Can be called to create a BACKFEED object from fuzzresult object
    """

    def __call__(self, originating_fuzzres: FuzzResult, url, method: str, from_plugin: bool,
                 custom_description: str = "") -> FuzzResult:
        try:
            backfeed_fuzzresult: FuzzResult = copy.deepcopy(originating_fuzzres)
            backfeed_fuzzresult.history.url = str(url)
            backfeed_fuzzresult.history.method = method
            # The plugin results of the response before are irrelevant for the new request and should be cleared
            backfeed_fuzzresult.plugins_res = []
            backfeed_fuzzresult.result_id = next(FuzzResult.newid)
            if custom_description:
                backfeed_fuzzresult.rlevel_desc = custom_description
            else:
                backfeed_fuzzresult.rlevel_desc = f"Backfeed originating from {originating_fuzzres.url}"
            backfeed_fuzzresult.item_type = FuzzType.BACKFEED
            # Bool is set by plugins to True to signal where the backfeed is coming from
            backfeed_fuzzresult.from_plugin = True if from_plugin else False
            backfeed_fuzzresult.backfeed_level += 1
            backfeed_fuzzresult.discarded = False

            backfeed_fuzzresult.payload_man = payman_factory.create("empty_payloadman",
                                                                    FuzzWord(url, FuzzWordType.WORD))
        except RuntimeError as exception:
            logger = logging.getLogger("debug_log")
            logger.exception("An exception occured in FuzzResBackfeedBuilder")
            exit()

        return backfeed_fuzzresult


class FuzzResMessageBuilder:
    """
    Can be called to create a message object to be printed out by the PrinterQ.
    At its core it is not a FuzzResult object, but rather a way of displaying information not related to a specific
    result in a clean manner.
    """

    def __call__(self, message: str) -> FuzzResult:
        message_result = FuzzResult()
        message_result.item_type = FuzzType.MESSAGE
        message_result.rlevel_desc = message
        return message_result


resfactory = FuzzResultFactory()
