from hashlib import sha1
import json
import sys
import asyncio


from .encoding import decode_bencode, bytes_to_str
from .metainfo import get_torrent_info
from .peers import get_peers, perform_handshake, initiate_transfer
from .download import (
    download_torrent,
    parse_download_args,
    download_piece_chunk,
    chunk_piece,
    check_piece_integrity,
)
from .constants import BLOCK_SIZE


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

            piece = b"".join(blocks)
            check_piece_integrity(piece, torrent_info)

            # Write piece
            with open(output_dir, "wb") as file:
                file.write(piece)
        case "download":
            args = parse_download_args()
            output_dir, torrent_filename = args.output_dir

            await download_torrent(torrent_filename, output_dir)
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    asyncio.run(main())
