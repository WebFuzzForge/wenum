from wenum.externals.moduleman.plugin import moduleman_plugin
from wenum.fuzzobjects import FuzzResult
from wenum.plugin_api.base import BasePlugin


@moduleman_plugin
class Cache(BasePlugin):
    name = "cache"
    author = ("Marmelatze",)
    version = "0.1"
    summary = "Feed cache entries to the fuzz queue."
    description = ("Feed cache entrie to the fuzz queue",)
    category = ["active", "discovery"]
    priority = 200
    output = []

    parameters = (
    )

    def __init__(self, session):
        BasePlugin.__init__(self, session)
        self.run_once = True

    def validate(self, fuzz_result):
        return True

    def process(self, fuzz_result: FuzzResult):
        for url in self.session.cache.cached_urls():
            self.queue_url(url)
