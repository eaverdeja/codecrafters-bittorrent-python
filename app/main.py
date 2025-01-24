from hashlib import sha1
import json
import sys
import asyncio


from .encoding import decode_bencode, bytes_to_str
from .metainfo import get_torrent_info
from .peers import get_peers, perform_handshake
from .download import (
    download_torrent,
    download_torrent_piece,
    parse_download_args,
)


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
            args = parse_download_args()
            output_dir, torrent_filename, piece_index = args.output_dir
            piece_index = int(piece_index)

            await download_torrent_piece(torrent_filename, piece_index, output_dir)
        case "download":
            args = parse_download_args()
            output_dir, torrent_filename = args.output_dir

            await download_torrent(torrent_filename, output_dir)
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    asyncio.run(main())
