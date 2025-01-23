from hashlib import sha1
from dataclasses import dataclass
from functools import cached_property
import random
import requests
import json
import sys
import asyncio
import argparse


@dataclass
class TorrentInfo:
    tracker_url: str
    content_length: int
    piece_length: int
    pieces: str

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


PEER_ID = random.randbytes(20)
BLOCK_SIZE = 16 * 1024  # 16kb


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
        content_length=int(content["info"]["length"]),
        piece_length=int(content["info"]["piece length"]),
        pieces=content["info"]["pieces"],
    )
    bencoded_info = encode_bencode(content["info"])

    return torrent_info, bencoded_info


def get_peers(torrent_filename: str) -> list[str]:
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

    return peers


async def perform_handshake(
    torrent_filename: str, peer: str
) -> tuple[str, asyncio.StreamReader, asyncio.StreamWriter]:
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
    data = await reader.readexactly(len(message))
    encoded_peer_id = data[len(message) - len(PEER_ID) :]
    peer_id = "".join(f"{piece:02x}" for piece in encoded_peer_id)

    return peer_id, reader, writer


# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
#
# Let's convert them to strings for printing to the console.
def bytes_to_str(data: bytes) -> str:
    if isinstance(data, bytes):
        return data.decode()

    raise TypeError(f"Type not serializable: {type(data)}")


def chunk_piece(piece_length: int, chunk_size: int) -> list[list[int]]:
    blocks = []
    for start in range(0, piece_length, chunk_size):
        end = min(start + chunk_size - 1, piece_length)
        block = list(range(start, end + 1))
        blocks.append(block)

    return blocks


def parse_download_piece_args():
    parser = argparse.ArgumentParser(description="Downloads a torrent piece")
    parser.add_argument(
        "--output_dir",
        "-o",
        type=str,
        nargs="*",
        help="Output directory. Also contains the torrent filename and piece index as trailing arguments",
    )
    return parser.parse_args(sys.argv[2:])


async def initiate_transfer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Receive bitfield message
    bitfield_size = int.from_bytes(await reader.readexactly(4))
    bitfield_type = int.from_bytes(await reader.readexactly(1))
    if bitfield_type != 0x05:
        raise Exception("Expected bitfield type")
    # Read the rest of the bitfield payload, but ignore it for now
    _bitfield_payload = await reader.read(bitfield_size - 1)

    # Send interested message
    # Payload size is 0, interested type is 2
    # The message length (4 bytes) should account for the type byte
    message = int.to_bytes(1, length=4) + int.to_bytes(2, length=1)
    writer.write(message)
    await writer.drain()

    # Receive unchoke message
    unchoke_size = int.from_bytes(await reader.readexactly(4))
    unchoke_type = int.from_bytes(await reader.readexactly(1))
    if unchoke_type != 0x01 or unchoke_size != 0x01:
        raise Exception("Expected unchoke type with size 1")


async def download_piece_chunk(
    chunk: list[int],
    chunks: list[list[int]],
    piece_index: int,
    is_last_piece: bool,
    idx: int,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    # Send request message
    index = int.to_bytes(int(piece_index), length=4)
    begin = int.to_bytes(chunk[0], length=4)
    # Chunk length is tricky - if we're on the
    # last chunk of the last piece, we need
    # to decrement 1.
    #
    # Hacky, but it worked ¯\_(ツ)_/¯
    length = int.to_bytes(
        len(chunk) - 1 if idx == len(chunks) - 1 and is_last_piece else len(chunk),
        length=4,
    )
    payload = index + begin + length
    message = (
        int.to_bytes(len(payload) + 1, length=4)  # Message length
        + int.to_bytes(6, length=1)  # Request type
        + payload
    )
    writer.write(message)
    await writer.drain()

    # Receive piece message and return data
    piece_size = int.from_bytes(await reader.readexactly(4))
    piece_type = int.from_bytes(await reader.readexactly(1))
    if piece_type != 0x07:
        raise Exception("Expected piece type")
    return await reader.readexactly(piece_size - 1)


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

            print("Piece Hashes: ")
            for piece_hash in torrent_info.piece_hashes:
                print(piece_hash)
        case "peers":
            torrent_filename = sys.argv[2]
            peers = get_peers(torrent_filename)
            print(peers)
        case "handshake":
            torrent_filename = sys.argv[2]
            peer = sys.argv[3]
            peer_id, _, _ = await perform_handshake(torrent_filename, peer)
            print(f"Peer ID: {peer_id}")
        case "download_piece":
            args = parse_download_piece_args()
            output_dir, torrent_filename, piece_index = args.output_dir

            # Perform handshake and send initial messages (BITFIELD, UNCHOKE)
            torrent_info, _ = get_torrent_info(torrent_filename)
            peers = get_peers(torrent_filename)
            peer_id, reader, writer = await perform_handshake(
                torrent_filename, peer=peers[0]
            )
            await initiate_transfer(reader, writer)

            # Create piece chunks
            blocks: list[bytes] = []
            is_last_piece = len(torrent_info.piece_hashes) == int(piece_index) + 1
            piece_length = (
                torrent_info.piece_length
                if not is_last_piece
                else torrent_info.content_length % torrent_info.piece_length
            )
            chunks = chunk_piece(piece_length, BLOCK_SIZE)
            for idx, chunk in enumerate(chunks):
                data = await download_piece_chunk(
                    chunk=chunk,
                    chunks=chunks,
                    piece_index=piece_index,
                    is_last_piece=is_last_piece,
                    idx=idx,
                    reader=reader,
                    writer=writer,
                )
                # Skip 4 bytes for the index + 4 bytes for the begin offset.
                # TODO: come back to this when working on a parallel implementation.
                # We'll need to consider the index & offset to properly align pieces
                # when putting them back together
                # (i.e. b"".join(blocks) probably won't work)
                block = data[8:]
                blocks.append(block)

            # Check piece integrity
            piece = b"".join(blocks)
            piece_hash = sha1(piece).hexdigest()
            if not piece_hash in torrent_info.piece_hashes:
                raise Exception(
                    f"Expected to find {piece_hash} in {torrent_info.piece_hashes}"
                )

            # Write piece
            with open(output_dir, "wb") as file:
                file.write(piece)
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    asyncio.run(main())
