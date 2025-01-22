import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!


# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def decode_bencode(bencoded_value: bytes) -> bytes:
    first_char = chr(bencoded_value[0])
    if first_char.isdigit():  # strings
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return bencoded_value[first_colon_index + 1 :]
    elif first_char == "i":  # integers
        end_marker_index = bencoded_value.find(b"e")
        if end_marker_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_marker_index])
    else:
        raise NotImplementedError("Only strings are supported at the moment")


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

            print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
        case _:
            raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
