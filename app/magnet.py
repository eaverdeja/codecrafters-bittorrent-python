from dataclasses import dataclass
from urllib.parse import unquote


@dataclass
class MagnetLink:
    tracker_url: str
    info_hash: str

    @classmethod
    def parse(cls, link: str):
        # https://en.wikipedia.org/wiki/Magnet_URI_scheme
        query = link.split("?")[1]
        query_params = {}
        for param in query.split("&"):
            key, value = param.split("=")
            query_params[key] = value

        tracker_url = unquote(query_params["tr"])
        info_hash = query_params["xt"].split("urn:btih:")[1]

        return cls(tracker_url=tracker_url, info_hash=info_hash)

    @property
    def info_hash_bytes(self) -> bytes:
        return bytes.fromhex(self.info_hash)
