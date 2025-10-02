#!/usr/bin/env python3
import sys

def process_line(line):
    parts = line.strip().split("<30>")
    for p in parts:
        if p.strip():
            print(p.strip(), flush=True)

def main():
    for line in sys.stdin:
        process_line(line)

if __name__ == "__main__":
    main()
