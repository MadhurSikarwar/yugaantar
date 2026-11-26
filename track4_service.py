"""Official adapter entry point: one JSON request per process.

Derived from the toolkit's starter adapter (attribution is in the README). The
one change made to the starter: stdin is read as bytes with a size cap and
decoded as strict UTF-8, so the proof bytes never depend on the system locale.

Contract: read one JSON object from stdin, write one JSON object to stdout,
exit. Nothing else ever goes to stdout. On any failure a fixed, generic line
goes to stderr (never request data, keys or contents) and the exit code is 1.
"""
import json
import sys

from t4.api import Track4Error
from t4.validate_in import read_request
from team_app import dispatch, record_failure


def main() -> int:
    try:
        request = read_request(sys.stdin.buffer)
        response = dispatch(request)
        if not isinstance(response, dict):
            raise TypeError("response must be an object")
        encoded = json.dumps(response, allow_nan=False)
    except Exception as error:  # noqa: BLE001 - everything fails closed
        record_failure(error)
        label = error.category if isinstance(error, Track4Error) else "error"
        print(f"Request failed ({label}).", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(encoded.encode("ascii") + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
