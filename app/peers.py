import asyncio
import requests
import random
from dataclasses import dataclass

from .dataclasses import MagnetLink
from .encoding import decode_bencode, encode_bencode
from .metainfo import get_torrent_info

PEER_ID = random.randbytes(20)
PROTOCOL_STRING = "BitTorrent protocol"
RESERVED_BYTES_LENGTH = 8
METADATA_EXTENSION_BIT_POSITION = 20
EXTENSION_MESSAGE_ID = 20
EXTENSION_HANDSHAKE_ID = 0
METADATA_EXTENSION_ID = 42


@dataclass
class PeerExtensions:
    supports_metadata: bool


def get_peers_from_file(torrent_filename: str) -> list[str]:
    torrent_info = get_torrent_info(torrent_filename)
    return _get_peers(
        torrent_info.tracker_url, torrent_info.info_hash, torrent_info.content_length
    )


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
) -> tuple[str, PeerExtensions, asyncio.StreamReader, asyncio.StreamWriter]:
    print(f"Performing handshake with peer {peer}")
    peer_address, peer_port = peer.split(":")
    reader, writer = await asyncio.open_connection(
        host=peer_address,
        port=peer_port,
    )

    # Reserved bytes
    reserved_bytes = b"\x00" * RESERVED_BYTES_LENGTH
    modified_bytes = _add_magnet_link_extension(reserved_bytes)

    # Handshake request
    message = (
        int.to_bytes(19)
        + PROTOCOL_STRING.encode()
        + modified_bytes
        + info_hash
        + PEER_ID
    )
    writer.write(message)
    await writer.drain()

    # Handshake response
    data = await reader.readexactly(len(message))
    # Protocol string
    protocol_string_size = data[0]
    protocol_string = data[1 : protocol_string_size + 1].decode()
    assert (
        protocol_string == PROTOCOL_STRING
    ), f"Unexpected protocol string: {protocol_string}"

    # Reserved bytes
    offset = protocol_string_size + 1
    peer_reserved_bytes = data[offset : offset + RESERVED_BYTES_LENGTH]
    extensions = PeerExtensions(
        supports_metadata=_is_bit_set(
            peer_reserved_bytes, METADATA_EXTENSION_BIT_POSITION
        )
    )

    # Peer ID
    encoded_peer_id = data[len(message) - len(PEER_ID) :]
    peer_id = "".join(f"{piece:02x}" for piece in encoded_peer_id)

    print(f"Handshake succeeded with peer {peer}")
    return peer_id, extensions, reader, writer


async def initiate_transfer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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


async def receive_bitfield_message(reader: asyncio.StreamReader):
    # Receive bitfield message
    bitfield_size = int.from_bytes(await reader.readexactly(4))
    bitfield_type = int.from_bytes(await reader.readexactly(1))
    if bitfield_type != 0x05:
        raise Exception("Expected bitfield type")
    # Return the rest of the bitfield payload
    return await reader.read(bitfield_size - 1)


async def perform_metadata_extension_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> int:
    # https://www.bittorrent.org/beps/bep_0010.html#handshake-message
    # Send extension handshake
    message_id = int.to_bytes(EXTENSION_MESSAGE_ID, length=1)
    extension_message_id = int.to_bytes(EXTENSION_HANDSHAKE_ID, length=1)
    extension_payload = encode_bencode({"m": {"ut_metadata": METADATA_EXTENSION_ID}})
    payload = extension_message_id + extension_payload
    length = int.to_bytes(len(message_id) + len(payload), length=4)
    message = length + message_id + payload
    writer.write(message)
    await writer.drain()

    # Receive extension handshake
    extension_handshake_size = int.from_bytes(await reader.readexactly(4))
    extension_handshake_type = int.from_bytes(await reader.readexactly(1))
    if extension_handshake_type != EXTENSION_MESSAGE_ID:
        raise Exception(
            f"Expected extension handshake type, got {extension_handshake_type}"
        )

    # Read the extension handshake payload
    extension_handshake_id = int.from_bytes(await reader.readexactly(1))
    if extension_handshake_id != EXTENSION_HANDSHAKE_ID:
        raise Exception(
            f"Expected extension handshake ID, got {extension_handshake_id}"
        )
    extension_handshake_payload, _ = decode_bencode(
        await reader.read(extension_handshake_size - 1)
    )
    # Grab the peer's ID for the ut_metadata extension
    return extension_handshake_payload["m"]["ut_metadata"]


async def send_metadata_request_message(
    peer_metadata_extension_id: int,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    # Send metadata request message
    message_id = int.to_bytes(EXTENSION_MESSAGE_ID, length=1)
    extension_message_id = int.to_bytes(peer_metadata_extension_id, length=1)
    extension_payload = encode_bencode({"msg_type": 0, "piece": 0})
    payload = extension_message_id + extension_payload
    length = int.to_bytes(len(message_id) + len(payload), length=4)
    message = length + message_id + payload
    writer.write(message)
    await writer.drain()

    # Receive data message
    data_message_size = int.from_bytes(await reader.readexactly(4))
    data_message_type = int.from_bytes(await reader.readexactly(1))
    if data_message_type != EXTENSION_MESSAGE_ID:
        raise Exception(f"Expected extension message ID, got {data_message_type}")
    received_peer_metadata_extension_id = int.from_bytes(await reader.readexactly(1))
    if received_peer_metadata_extension_id != METADATA_EXTENSION_ID:
        raise Exception("Peer metadata extension IDs don't match!")

    data_message_payload = await reader.readexactly(data_message_size - 2)
    # The first variable sized part of the payload is the metadata info dict
    # It would be relevant if the metadata was split into several pieces
    _, bytes_read = decode_bencode(data_message_payload)
    # Next is the actual metadata piece contents.
    # In our case, it's the entire metadata info
    metadata_info, _ = decode_bencode(data_message_payload[bytes_read:])

    return metadata_info


def _add_magnet_link_extension(reserved_bytes: bytes) -> bytes:
    # 20th bit announces support for magnet link extension
    bit_position = METADATA_EXTENSION_BIT_POSITION
    # Which byte has the 20th bit?
    byte_index = len(reserved_bytes) - 1 - (bit_position // 8)
    # Which bit in that byte corresponds to the 20th bit?
    bit_offset = bit_position % 8

    # Use bytearray to allow for update of a specific byte
    modified_bytes = bytearray(reserved_bytes)
    # Create a mask with the bit offset
    # and apply it with |= to the correct byte
    modified_bytes[byte_index] |= 1 << bit_offset

    return bytes(modified_bytes)


def _is_bit_set(byte_sequence: bytes, bit_position: int) -> bool:
    # Which byte should we look at?
    byte_index = len(byte_sequence) - 1 - (bit_position // 8)
    # Which bit in that byte is the relevant one?
    bit_offset = bit_position % 8
    # Create a mask and apply it with
    # & to get our answer
    return bool(byte_sequence[byte_index] & (1 << bit_offset))
