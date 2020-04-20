#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

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

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = wpa[0].info
APmac       = a2b_hex(wpa[5].addr2.replace(':', '')) # Get AP mac address from Source of the first packet of the 4-way handshake
Clientmac   = a2b_hex(wpa[5].addr1.replace(':', '')) # Get STA mac address  from Source of the first packet of the 4-way handshake

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(b2a_hex(wpa[5].load)[26:90]) # getting nounce in the first packet of the 4-way handshake
SNonce      = a2b_hex(b2a_hex(wpa[6].load)[26:90]) # getting nounce in the second packet of the 4-way handshake

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b2a_hex(wpa[8].load)[154:186] # getting MIC from the last (4e) packet of the 4-way handshake

B           = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce)+max(ANonce, SNonce) #used in pseudo-random function

data        = a2b_hex("%02x" % wpa[8][5].version +     # add version in 1 Byte hex
                             "%02x" % wpa[8][5].type + # add key type in 1 Byte hex
                             "%04x" % wpa[8][5].len +  # Add len in 2 Byte hex
                             b2a_hex(wpa[8][5].load[:77]).decode().ljust(190, '0')) # Add Key (description + information + len) + Replay counter + Key (Nounce + IV + RSC ID) + padding

print("Values used to derivate keys")
print("============================")
print("Passphrase: ", passPhrase)
print("SSID: ", ssid)
print("AP Mac: ", b2a_hex(APmac))
print("CLient Mac: ", b2a_hex(Clientmac))
print("AP Nonce: ", b2a_hex(ANonce))
print("Client Nonce: ", b2a_hex(SNonce))

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

# expand pmk to obtain PTK
ptk = customPRF512(pmk, str.encode(A), B)

# calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16], data, hashlib.sha1)

print("\nResults of the key expansion")
print("=============================")
print("PMK:\t\t", pmk.hex())
print("PTK:\t\t", ptk.hex())
print("KCK:\t\t", ptk[0:16].hex())
print("KEK:\t\t", ptk[16:32].hex())
print("TK:\t\t", ptk[32:48].hex())
print("MICK:\t\t", ptk[48:64].hex())
print("MIC:\t\t", mic.hexdigest())
