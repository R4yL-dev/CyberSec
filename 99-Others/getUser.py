import argparse
import sys
import requests

from urllib.parse import urlparse

def main():
    args = parse_args()
    try:
        check_args(args)
    except ValueError as e:
        sys.exit(f"Error: {e}")

    show_args(args)
    exec_loop(args)


def parse_args():
    parser = argparse.ArgumentParser(description="getUser.py")
    parser.add_argument("target", help="Script target")
    parser.add_argument("-s", "--start", type=int, default=1)
    parser.add_argument("-e", "--end", type=int, default=100)
    return parser.parse_args()

def check_args(args):
    if not args.target.strip():
        raise ValueError("target cannot be empty")
    if not is_url(args.target.strip()):
        raise ValueError("target is not a valid URL")

    if args.start < 0:
        raise ValueError("start cannot be lower than 0")
    if args.end < 1:
        raise ValueError("end cannot be lower than 1")
    if args.start >= args.end:
        raise ValueError("start cannot be greater or egal to end")

def is_url(url):
    res = urlparse(url)
    return res.scheme in ("http", "https") and bool(res.netloc)

def show_args(args):
    print("-- SHOW ARGS")
    print("args.target: " + args.target)
    print("args.start: " + str(args.start))
    print("args.end: " + str(args.end))

def exec_loop(args):
    target = args.target
    if not target.endswith("/"):
        target += "/"

    for i in range(args.start, args.end + 1):
        url = f"{target}{i}"

        try:
            response = requests.get(url, timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"[ERR] {url} -> {e}")
            continue

        code = response.status_code
        if code == 200:
            print(f"[200] {url}")
            print(response.text)
        else:
            print(f"[{code}] {url}")



if __name__ == "__main__":
    main()
