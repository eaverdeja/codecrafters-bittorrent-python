from hashlib import sha1
import json
import sys

# import requests - available if you need it!


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


# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
#
# Let's convert them to strings for printing to the console.
def bytes_to_str(data: bytes) -> str:
    if isinstance(data, bytes):
        return data.decode()

    raise TypeError(f"Type not serializable: {type(data)}")


def main():
    command = sys.argv[1]

    match command:
        case "decode":
            bencoded_value = sys.argv[2].encode()

            decoded_value, _bytes_read = decode_bencode(bencoded_value)
            print(json.dumps(decoded_value, default=bytes_to_str))
        case "info":
            torrent_filename = sys.argv[2]
            with open(torrent_filename, "rb") as file:
                bencoded_content = file.read()
            content, _bytes_read = decode_bencode(bencoded_content)
            tracker_url = content["announce"].decode()
            content_length = content["info"]["length"]
            piece_length = content["info"]["piece length"]
            pieces = content["info"]["pieces"]
            bencoded_info = encode_bencode(content["info"])

            print(f"Tracker URL: {tracker_url}")
            print(f"Length: {content_length}")
            print(f"Info Hash: {sha1(bencoded_info).hexdigest()}")
            print(f"Piece Length: {piece_length}")

            piece_size = 20
            chunks: list[bytes] = [
                pieces[i : i + piece_size] for i in range(0, len(pieces), piece_size)
            ]
            print("Piece Hashes: ")
            for piece in chunks:
                # Format the piece as a hex string
                print("".join("{:02x}".format(x) for x in piece))
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
