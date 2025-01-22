import json
import sys

# import requests - available if you need it!


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello", 7
# - decode_bencode(b"10:hello12345") -> b"hello12345", 13
def decode_bencode(s: bytes, pos=0) -> tuple[bytes, int]:
    char_at_pos = chr(s[pos])
    if char_at_pos == "l":
        items = []
        pos += 1  # +1 to account for the start of list marker
        while pos < len(s):
            if chr(s[pos]) == "e":
                break
            item, pos = decode_bencode(s, pos)
            items.append(item)

        return items, pos + 1  # +1 to account for the end of list marker
    elif char_at_pos == "i":
        end = s.index(b"e", pos)
        return int(s[pos + 1 : end]), end + 1  # +1 to account for the end of int marker
    elif char_at_pos.isdigit():
        colon = s.index(b":", pos)
        length = int(s[pos:colon])
        start = colon + 1
        end = start + length
        return s[start:end], end
    else:
        raise NotImplementedError(
            f"Only strings are supported at the moment - got: {char_at_pos}"
        )


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
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
