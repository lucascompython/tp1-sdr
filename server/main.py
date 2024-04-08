import sys

from server import TCPHandler, ThreadedTCPServer

HOST, PORT = "localhost", 12345


def main() -> None:
    with ThreadedTCPServer((HOST, PORT), TCPHandler) as server:
        print(f"Server started on {HOST}:{PORT}")
        server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Server stopped.")
        sys.exit(0)
else:
    sys.stderr.write("This file is not meant to be imported.")
    sys.exit(1)
