from dataclasses import dataclass
from functools import cached_property
from hashlib import sha1

from .encoding import encode_bencode, decode_bencode


@dataclass
class TorrentInfo:
    tracker_url: str
    content_length: int
    piece_length: int
    pieces: str
    bencoded_info: bytes

    @cached_property
    def piece_hashes(self) -> list[str]:
        piece_size = 20
        chunks: list[bytes] = [
            self.pieces[i : i + piece_size]
            for i in range(0, len(self.pieces), piece_size)
        ]
        return [
            # Format the piece as a hex string
            "".join("{:02x}".format(x) for x in piece)
            for piece in chunks
        ]

    @property
    def info_hash(self) -> bytes:
        return sha1(self.bencoded_info).digest()


def get_torrent_info(torrent_filename: str) -> TorrentInfo:
    with open(torrent_filename, "rb") as file:
        bencoded_content = file.read()
    content, _bytes_read = decode_bencode(bencoded_content)
    torrent_info = TorrentInfo(
        tracker_url=content["announce"].decode(),
        content_length=int(content["info"]["length"]),
        piece_length=int(content["info"]["piece length"]),
        pieces=content["info"]["pieces"],
        bencoded_info=encode_bencode(content["info"]),
    )
    return torrent_info
