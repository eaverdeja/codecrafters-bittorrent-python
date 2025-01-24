import sys
import argparse
import asyncio
from hashlib import sha1
import random

from .metainfo import get_torrent_info, TorrentInfo
from .peers import get_peers_from_file, perform_handshake, initiate_transfer
from .constants import BLOCK_SIZE


def parse_download_args():
    parser = argparse.ArgumentParser(description="Downloads a torrent (piece)")
    parser.add_argument(
        "--output_dir",
        "-o",
        type=str,
        nargs="*",
        help="Output directory. Also contains the torrent filename (and piece index) as trailing arguments",
    )
    return parser.parse_args(sys.argv[2:])


async def download_torrent(torrent_filename, output_dir):
    torrent_info = get_torrent_info(torrent_filename)
    peers = get_peers_from_file(torrent_filename)
    random.shuffle(peers)

    piece_tasks = []
    pieces = {}

    print(f"\nDownloading torrent [{torrent_filename}]")
    print("Content length: ", torrent_info.content_length)
    print("Piece length: ", torrent_info.piece_length)
    print("# of pieces: ", len(torrent_info.piece_hashes))

    # For each piece, select a peer and request the piece from them
    for piece_index, _piece_hash in enumerate(torrent_info.piece_hashes):
        # Choose a peer
        peer = peers[piece_index % len(peers)]
        task = asyncio.create_task(
            _download_piece_from_peer(torrent_filename, torrent_info, peer, piece_index)
        )
        piece_tasks.append(task)

        # Are all peers occupied? Then wait for downloads to
        # finish before requesting for more pieces
        if len(piece_tasks) == len(peers):
            results = await asyncio.gather(*[piece_tasks.pop() for _ in peers])
            for result in results:
                piece, piece_index = result
                pieces[piece_index] = piece

    # Gather remaining tasks
    if len(piece_tasks) > 0:
        results = await asyncio.gather(*piece_tasks)
        for result in results:
            piece, piece_index = result
            pieces[piece_index] = piece

    print("\nFinished downloading pieces")

    # Sort pieces by their indexes
    sorted_pieces = dict(sorted(pieces.items())).values()

    # Validate that all tasks succeeded
    valid_pieces = [p for p in sorted_pieces if p is not None]
    if len(valid_pieces) != len(torrent_info.piece_hashes):
        raise Exception(
            f"Could not download all pieces. Got {len(valid_pieces)} expected {len(torrent_info.piece_hashes)}"
        )

    # Write pieces
    with open(output_dir, "wb") as file:
        file.write(b"".join(valid_pieces))


async def download_torrent_piece(
    torrent_filename: str, piece_index: int, output_dir: str
):
    # Get metainfo and choose a peer
    torrent_info = get_torrent_info(torrent_filename)
    peers = get_peers_from_file(torrent_filename)
    peer = peers[piece_index % len(peers)]

    # Download piece
    piece, _ = await _download_piece_from_peer(
        torrent_filename, torrent_info, peer, piece_index
    )

    # Write piece
    with open(output_dir, "wb") as file:
        file.write(piece)


async def _download_piece_from_peer(
    torrent_filename: str, torrent_info: TorrentInfo, peer: str, piece_index: int
):
    print(f"Performing handshake with peer {peer}")
    torrent_info = get_torrent_info(torrent_filename)
    _, reader, writer = await perform_handshake(torrent_info.info_hash, peer)
    try:
        await initiate_transfer(reader, writer)
        print(f"Handshake succeeded with peer {peer}")

        is_last_piece = len(torrent_info.piece_hashes) == int(piece_index) + 1
        piece_length = (
            torrent_info.piece_length
            if not is_last_piece
            else torrent_info.content_length % torrent_info.piece_length
        )
        chunks = _chunk_piece(piece_length, BLOCK_SIZE)

        print("Downloading piece")
        print("# of chunks", len(chunks))
        blocks, response_piece_idx = await _download_piece(
            reader, writer, piece_index, chunks, is_last_piece
        )

        piece = b"".join(blocks)
        _check_piece_integrity(piece, torrent_info)
        print(f"Integrity verified for piece [{piece_index}]")

        return piece, response_piece_idx
    except Exception as e:
        print(f"Error downloading piece {piece_index} from peer {peer} - {e}")
        return None
    finally:
        writer.close()
        await writer.wait_closed()


async def _download_piece(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    piece_index: int,
    chunks: list[list[int]],
    is_last_piece: bool,
) -> tuple[list[bytes], int]:
    blocks: list[bytes] = []

    response_tasks = []
    semaphore = asyncio.Semaphore()
    for idx, chunk in enumerate(chunks):
        task = asyncio.create_task(
            _download_piece_chunk(
                chunk=chunk,
                chunks=chunks,
                piece_index=piece_index,
                is_last_piece=is_last_piece,
                idx=idx,
                reader=reader,
                writer=writer,
                semaphore=semaphore,
            )
        )
        response_tasks.append(task)

    response_piece_index = None
    responses = await asyncio.gather(*response_tasks)
    for response in responses:
        # First 4 bytes from the response represent the piece index
        # - it shouldn't change throughout chunks
        rpi = int.from_bytes(response[:4])
        if response_piece_index and rpi != response_piece_index:
            raise Exception(
                f"Invalid response piece index from peer. Expected {response_piece_index} got {rpi}"
            )
        response_piece_index = rpi
        # The next 4 bytes represent the offset within the piece
        # - we can ignore it for now

        # Bytes 8 onwards represent the actual data
        blocks.append(response[8:])

    return blocks, response_piece_index


def _chunk_piece(piece_length: int, chunk_size: int) -> list[list[int]]:
    blocks = []
    for start in range(0, piece_length, chunk_size):
        end = min(start + chunk_size - 1, piece_length)
        block = list(range(start, end + 1))
        blocks.append(block)

    return blocks


async def _download_piece_chunk(
    chunk: list[int],
    chunks: list[list[int]],
    piece_index: int,
    is_last_piece: bool,
    idx: int,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    semaphore,
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

    async with semaphore:
        # Receive piece message and return data
        piece_size = int.from_bytes(await reader.readexactly(4))
        piece_type = int.from_bytes(await reader.readexactly(1))
        if piece_type != 0x07:
            raise Exception("Expected piece type")

        # Read the payload
        return await reader.readexactly(piece_size - 1)


def _check_piece_integrity(piece: bytes, torrent_info: TorrentInfo):
    piece_hash = sha1(piece).hexdigest()
    if not piece_hash in torrent_info.piece_hashes:
        raise Exception(f"Expected to find {piece_hash} in {torrent_info.piece_hashes}")
