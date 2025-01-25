from hashlib import sha1
import json
import sys
import asyncio

from .encoding import decode_bencode, bytes_to_str, encode_bencode
from .metainfo import get_torrent_info
from .peers import (
    get_peers_from_file,
    get_peers_from_magnet,
    initiate_transfer,
    perform_handshake,
    perform_metadata_extension_handshake,
    receive_bitfield_message,
)
from .download import (
    download_piece_from_peer,
    download_torrent_from_file,
    download_torrent_from_magnet,
    download_torrent_piece,
    parse_download_args,
)
from .magnet import MagnetLink, get_torrent_info_from_magnet_link


async def main():
    command = sys.argv[1]

    match command:
        case "decode":
            bencoded_value = sys.argv[2].encode()

            decoded_value, _bytes_read = decode_bencode(bencoded_value)
            print(json.dumps(decoded_value, default=bytes_to_str))
        case "info":
            torrent_filename = sys.argv[2]
            torrent_info = get_torrent_info(torrent_filename)

            print(f"Tracker URL: {torrent_info.tracker_url}")
            print(f"Length: {torrent_info.content_length}")
            print(f"Info Hash: {sha1(torrent_info.bencoded_info).hexdigest()}")
            print(f"Piece Length: {torrent_info.piece_length}")

            print("Piece Hashes: ")
            for piece_hash in torrent_info.piece_hashes:
                print(piece_hash)
        case "peers":
            torrent_filename = sys.argv[2]
            peers = get_peers_from_file(torrent_filename)
            print(peers)
        case "handshake":
            torrent_filename = sys.argv[2]
            peer = sys.argv[3]

            torrent_info = get_torrent_info(torrent_filename)
            peer_id, _, _, _ = await perform_handshake(torrent_info.info_hash, peer)
            print(f"Peer ID: {peer_id}")
        case "download_piece":
            args = parse_download_args()
            output_dir, torrent_filename, piece_index = args.output_dir
            piece_index = int(piece_index)

            await download_torrent_piece(torrent_filename, piece_index, output_dir)
        case "download":
            args = parse_download_args()
            output_dir, torrent_filename = args.output_dir

            await download_torrent_from_file(torrent_filename, output_dir)
        case "magnet_parse":
            raw_magnet_link = sys.argv[2]

            magnet_link = MagnetLink.parse(raw_magnet_link)
            print(f"Tracker URL: {magnet_link.tracker_url}")
            print(f"Info Hash: {magnet_link.info_hash}")
        case "magnet_handshake":
            raw_magnet_link = sys.argv[2]

            magnet_link = MagnetLink.parse(raw_magnet_link)
            peers = get_peers_from_magnet(magnet_link)
            peer = peers[0]

            peer_id, extensions, reader, writer = await perform_handshake(
                magnet_link.info_hash_bytes, peer
            )
            # Note: for this challenge, we don't need to send
            # the bitfield message, but it would be part of the flow here
            await receive_bitfield_message(reader)

            # Extend!
            if extensions.supports_metadata:
                peer_metadata_extension_id = await perform_metadata_extension_handshake(
                    reader, writer
                )

            print(f"Peer ID: {peer_id}")
            print(f"Peer Metadata Extension ID: {peer_metadata_extension_id}")
        case "magnet_info":
            raw_magnet_link = sys.argv[2]
            magnet_link = MagnetLink.parse(raw_magnet_link)
            torrent_info, _, _, _ = await get_torrent_info_from_magnet_link(magnet_link)

            assert (
                magnet_link.info_hash_bytes == torrent_info.info_hash
            ), "Info hashes don't match!"

            print(f"Tracker URL: {torrent_info.tracker_url}")
            print(f"Length: {torrent_info.content_length}")
            print(f"Info Hash: {magnet_link.info_hash}")
            print(f"Piece Length: {torrent_info.piece_length}")
            print("Piece hashes:")
            for piece_hash in torrent_info.piece_hashes:
                print(piece_hash)
        case "magnet_download_piece":
            args = parse_download_args()
            output_dir, raw_magnet_link, piece_index = args.output_dir
            piece_index = int(piece_index)

            magnet_link = MagnetLink.parse(raw_magnet_link)
            torrent_info, peer, reader, writer = (
                await get_torrent_info_from_magnet_link(magnet_link)
            )

            await initiate_transfer(reader, writer)
            piece, piece_index = await download_piece_from_peer(
                reader=reader,
                writer=writer,
                torrent_info=torrent_info,
                peer=peer,
                piece_index=piece_index,
            )

            # Write piece
            with open(output_dir, "wb") as file:
                file.write(piece)
        case "magnet_download":
            args = parse_download_args()
            output_dir, raw_magnet_link = args.output_dir

            magnet_link = MagnetLink.parse(raw_magnet_link)

            await download_torrent_from_magnet(magnet_link, output_dir)
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    asyncio.run(main())
