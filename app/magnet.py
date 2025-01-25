import asyncio

from .encoding import encode_bencode
from .peers import (
    get_peers_from_magnet,
    perform_handshake,
    perform_metadata_extension_handshake,
    receive_bitfield_message,
    send_metadata_request_message,
)
from .metainfo import TorrentInfo
from .dataclasses import MagnetLink


async def get_torrent_info_from_magnet_link(
    magnet_link: MagnetLink, peer: str | None = None
) -> tuple[TorrentInfo, str, asyncio.StreamReader, asyncio.StreamWriter]:
    peers = get_peers_from_magnet(magnet_link)
    peer = peer or peers[0]

    _, extensions, reader, writer = await perform_handshake(
        magnet_link.info_hash_bytes, peer
    )
    await receive_bitfield_message(reader)

    if not extensions.supports_metadata:
        raise Exception(f"Peer {peer} does not support metadata extension")

    peer_metadata_extension_id = await perform_metadata_extension_handshake(
        reader, writer
    )
    metadata_info = await send_metadata_request_message(
        peer_metadata_extension_id, reader, writer
    )
    return (
        TorrentInfo(
            tracker_url=magnet_link.tracker_url,
            content_length=metadata_info["length"],
            piece_length=metadata_info["piece length"],
            pieces=metadata_info["pieces"],
            bencoded_info=encode_bencode(metadata_info),
        ),
        peer,
        reader,
        writer,
    )
