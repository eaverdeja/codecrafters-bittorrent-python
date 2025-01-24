import asyncio
import requests
import random
from hashlib import sha1
from itertools import zip_longest

from .magnet import MagnetLink
from .encoding import decode_bencode
from .metainfo import get_torrent_info

PEER_ID = random.randbytes(20)


def get_peers_from_file(torrent_filename: str) -> list[str]:
    torrent_info, bencoded_info = get_torrent_info(torrent_filename)
    info_hash = sha1(bencoded_info).digest()
    return _get_peers(torrent_info.tracker_url, info_hash, torrent_info.content_length)


def get_peers_from_magnet(magnet_link: MagnetLink):
    return _get_peers(magnet_link.tracker_url, magnet_link.info_hash_bytes)


def _get_peers(tracker_url: str, info_hash: str, content_length: int = 999):
    peers = []
    response = requests.get(
        tracker_url,
        params={
            "info_hash": info_hash,
            "peer_id": PEER_ID,
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": content_length,
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
    info_hash: str, peer: str
) -> tuple[str, asyncio.StreamReader, asyncio.StreamWriter]:
    peer_address, peer_port = peer.split(":")
    reader, writer = await asyncio.open_connection(
        host=peer_address,
        port=peer_port,
    )

    # Reserved bytes
    reserved_bytes = b"\x00" * 8
    modified_bytes = _add_magnet_link_extension(reserved_bytes)

    # Handshake request
    message = (
        int.to_bytes(19)
        + "BitTorrent protocol".encode()
        + modified_bytes
        + info_hash
        + PEER_ID
    )
    writer.write(message)
    await writer.drain()

    # Handshake response
    data = await reader.readexactly(len(message))
    encoded_peer_id = data[len(message) - len(PEER_ID) :]
    peer_id = "".join(f"{piece:02x}" for piece in encoded_peer_id)

    return peer_id, reader, writer


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


def _add_magnet_link_extension(reserved_bytes: bytes) -> bytes:
    # 20th bit announces support for magnet link extension
    bit_position = 20
    # Which byte has the 20th bit?
    byte_index = len(reserved_bytes) - 1 - (bit_position // 8)
    # Which bit in that byte corresponds to the 20th bit?
    bit_offset = bit_position % 8

    # Use bytearray to allow for update of a specific byte
    modified_bytes = bytearray(reserved_bytes)
    # Create a mask with the bit offset
    # and apply it to the correct byte
    modified_bytes[byte_index] |= 1 << bit_offset
    modified_bytes = bytes(modified_bytes)
    return modified_bytes
