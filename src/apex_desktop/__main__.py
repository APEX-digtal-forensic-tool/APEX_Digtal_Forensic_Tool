"""OS-assigned loopback port; readiness contains no credentials."""

import argparse
import json
import os
import socket
from pathlib import Path

import uvicorn

from .app import create_app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    app = create_app(args.data_dir, os.environ.pop("APEX_DESKTOP_TOKEN", ""))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    print(json.dumps({"type": "apex-ready", "port": sock.getsockname()[1]}), flush=True)
    uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning")).run(sockets=[sock])


if __name__ == "__main__":
    main()
