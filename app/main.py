from hashlib import sha1
from dataclasses import dataclass
import random
import requests
import json
import sys
import asyncio


@dataclass
class TorrentInfo:
    tracker_url: str
    content_length: str
    piece_length: str
    pieces: str


PEER_ID = random.randbytes(20)


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello", 7
# - decode_bencode(b"10:hello12345") -> b"hello12345", 13
def decode_bencode(bencode: bytes, pos=0) -> tuple[bytes, int]:
    char_at_pos = chr(bencode[pos])
    if char_at_pos == "l":  # lists
        items = []
        pos += 1  # +1 to account for the start of list marker
        while pos < len(bencode):
            if chr(bencode[pos]) == "e":
                break
            item, pos = decode_bencode(bencode, pos)
            items.append(item)

        return items, pos + 1  # +1 to account for the end of list marker
    elif char_at_pos == "d":  # dictionaries
        items = {}
        pos += 1
        while pos < len(bencode):
            if chr(bencode[pos]) == "e":
                break
            key, pos = decode_bencode(bencode, pos)
            value, pos = decode_bencode(bencode, pos)
            items[key.decode()] = value

        return items, pos + 1  # +1 to account for the end of dictionary marker
    elif char_at_pos == "i":  # integers
        end = bencode.index(b"e", pos)
        return (
            int(bencode[pos + 1 : end]),
            end + 1,
        )  # +1 to account for the end of int marker
    elif char_at_pos.isdigit():  # strings
        colon = bencode.index(b":", pos)
        length = int(bencode[pos:colon])
        start = colon + 1
        end = start + length
        return bencode[start:end], end
    else:
        raise NotImplementedError(
            f"Only strings are supported at the moment - got: {char_at_pos}"
        )


def encode_bencode(data: int | str | list | dict | bytes) -> bytes:
    if isinstance(data, int):
        return f"i{data}e".encode()
    elif isinstance(data, str):
        return f"{len(data)}:{data}".encode()
    elif isinstance(data, list):
        elements = [encode_bencode(element) for element in data]
        return b"l" + b"".join(elements) + b"e"
    elif isinstance(data, dict):
        elements = [
            encode_bencode(key) + encode_bencode(value) for key, value in data.items()
        ]
        return b"d" + b"".join(elements) + b"e"
    elif isinstance(data, bytes):
        return f"{len(data)}:".encode() + data
    raise TypeError(f"Cannot encode {type(data)}")


def get_torrent_info(torrent_filename: str) -> tuple[TorrentInfo, bytes]:
    with open(torrent_filename, "rb") as file:
        bencoded_content = file.read()
    content, _bytes_read = decode_bencode(bencoded_content)
    torrent_info = TorrentInfo(
        tracker_url=content["announce"].decode(),
        content_length=content["info"]["length"],
        piece_length=content["info"]["piece length"],
        pieces=content["info"]["pieces"],
    )
    bencoded_info = encode_bencode(content["info"])

    return torrent_info, bencoded_info


# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
#
# Let's convert them to strings for printing to the console.
def bytes_to_str(data: bytes) -> str:
    if isinstance(data, bytes):
        return data.decode()

    raise TypeError(f"Type not serializable: {type(data)}")


async def main():
    command = sys.argv[1]

    match command:
        case "decode":
            bencoded_value = sys.argv[2].encode()

            decoded_value, _bytes_read = decode_bencode(bencoded_value)
            print(json.dumps(decoded_value, default=bytes_to_str))
        case "info":
            torrent_filename = sys.argv[2]
            torrent_info, bencoded_info = get_torrent_info(torrent_filename)

            print(f"Tracker URL: {torrent_info.tracker_url}")
            print(f"Length: {torrent_info.content_length}")
            print(f"Info Hash: {sha1(bencoded_info).hexdigest()}")
            print(f"Piece Length: {torrent_info.piece_length}")

            piece_size = 20
            chunks: list[bytes] = [
                torrent_info.pieces[i : i + piece_size]
                for i in range(0, len(torrent_info.pieces), piece_size)
            ]
            print("Piece Hashes: ")
            for piece in chunks:
                # Format the piece as a hex string
                print("".join("{:02x}".format(x) for x in piece))
        case "peers":
            torrent_filename = sys.argv[2]
            peers = []
            torrent_info, bencoded_info = get_torrent_info(torrent_filename)
            response = requests.get(
                torrent_info.tracker_url,
                params={
                    "info_hash": sha1(bencoded_info).digest(),
                    "peer_id": PEER_ID,
                    "port": 6881,
                    "uploaded": 0,
                    "downloaded": 0,
                    "left": torrent_info.content_length,
                    "compact": 1,
                },
            )
            result, _ = decode_bencode(response.content)
            pos = 0
            while pos < len(result["peers"]):
                # First 4 bytes compose the peer's address
                peer_address = ".".join(
                    str(int.from_bytes(result["peers"][pos + i : pos + i + 1]))
                    for i in range(4)
                )
                # Next 2 bytes represent the peer's port
                peer_port = int.from_bytes(result["peers"][pos + 4 : pos + 6])
                peers.append(f"{peer_address}:{peer_port}")
                pos += 6
            print(peers)
        case "handshake":
            torrent_filename = sys.argv[2]
            peer = sys.argv[3]
            torrent_info, bencoded_info = get_torrent_info(torrent_filename)
            peer_address, peer_port = peer.split(":")
            reader, writer = await asyncio.open_connection(
                host=peer_address,
                port=peer_port,
            )

            # Handshake request
            message = (
                int.to_bytes(19)
                + "BitTorrent protocol".encode()
                + bytes().join(int.to_bytes(0) for _ in range(8))
                + sha1(bencoded_info).digest()
                + PEER_ID
            )
            writer.write(message)
            await writer.drain()

            # Handshake response
            data = await reader.read(len(message))
            encoded_peer_id = data[len(message) - len(PEER_ID) :]
            print(f"Peer ID: {"".join(f"{piece:02x}" for piece in encoded_peer_id)}")
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    asyncio.run(main())
