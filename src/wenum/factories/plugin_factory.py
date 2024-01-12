from ..helpers.obj_factory import ObjectFactory

from ..fuzzobjects import FuzzPlugin, FuzzError, FuzzResponse
from ..factories.fuzzresfactory import resfactory


class PluginFactory(ObjectFactory):
    def __init__(self):
        ObjectFactory.__init__(
            self,
            {
                "backfeed_plugin": PluginBackfeedBuilder(),
                "seed_plugin": PluginSeedBuilder(),
                "plugin_from_error": PluginErrorBuilder(),
                "plugin_from_finding": PluginFindingBuilder(),
            },
        )


class PluginBackfeedBuilder:
    """
    When a plugin is built here, the seed attribute becomes set
    by resfactory to BACKFEED, adding a request to the queue
    """
    def __call__(self, name, originating_fuzzres, url, method) -> FuzzPlugin:
        plugin = FuzzPlugin()
        plugin.name = name
        plugin.exception = None
        from_plugin = True
        plugin.seed = resfactory.create("fuzzres_from_fuzzres", originating_fuzzres, url, method, from_plugin)

        return plugin


class PluginSeedBuilder:
    """
    When a plugin is built here, the seed attribute becomes set
    by resfactory to SEED, adding a new seed (full recursion) to the queue
    """
    def __call__(self, name, seed, seeding_url) -> FuzzPlugin:
        plugin = FuzzPlugin()
        plugin.name = name
        plugin.exception = None
        plugin.seed = resfactory.create("seed_from_plugin", seed, seeding_url)

        return plugin


class PluginErrorBuilder:
    def __call__(self, name, exception) -> FuzzPlugin:
        plugin = FuzzPlugin()
        plugin.name = name
        plugin.message = "Exception within plugin %s: %s" % (name, str(exception))
        plugin.exception = FuzzError(exception)
        plugin.severity = FuzzPlugin.HIGH
        plugin.seed = None

        return plugin


class PluginFindingBuilder:
    """
    Creates a Plugin object dedicated to storing message information linked to the fuzzresult for logging purposes
    """
    def __call__(self, name, message, severity) -> FuzzPlugin:
        plugin = FuzzPlugin()
        plugin.name = name
        plugin.message = message
        plugin.severity = severity
        plugin.exception = None
        plugin.seed = None

        return plugin


plugin_factory = PluginFactory()
