import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://10.92.55.4:5000'

stuID = 28991
#stuID = 28414

# Server's Identitiy public key
IKey_Ser = Point(0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d,
                 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, Curve.get_curve('secp256k1'))
# Use the values in the project description document to form the server's IK as a point on the EC. Note that the values should be in decimal.


def IKRegReq(h, s, x, y, stuID):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if ((response.ok) == False):
        print(response.json())


def IKRegVerify(code, stuID, IKey_Pr, IKey_Pub):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    if ((response.ok) == False):
        raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: " +
                str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()


def SPKReg(h, s, x, y, stuID):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    if ((response.ok) == False):
        print(response.json())
    else:
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']


def OTKReg(keyID, x, y, hmac, stuID):
    mes = {'ID': stuID, 'KEYID': keyID,
           'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetIK(rcode, stuID):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetSPK(h, s, stuID):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetOTK(h, s, stuID):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    if ((response.ok) == False):
        print(response.json())


def generateKeys(n, P):
    sA = random.randint(1, n-2)
    qA = sA * P
    return qA, sA


def hashMessage(m):
    h = SHA3_256.new(m)
    digest = int.from_bytes(h.digest(), byteorder='big')
    return digest


def encodeParam(x):
    if (type(x) == str):
        return x.encode()
    elif (type(x) == int):
        return x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
    elif (type(x) == Point):
        return (encodeParam(x.x) + encodeParam(x.y))


def generateSignature(n, P, m, sA):
    k = random.randint(1, n-2)
    R = k * P
    r = R.x % n
    h = hashMessage(encodeParam(r) + encodeParam(m)) % n
    s = (k + sA * h) % n
    return h, s


def verifySignature(s, P, h, qA, n, m):
    V = (s * P) - (h * qA)
    v_small = V.x % n
    h_prime = hashMessage(encodeParam(v_small) + encodeParam(m)) % n

    if (h == h_prime):
        return True
    else:
        return False


def generateHMAC(SPKPri, SPKPUB_server):
    T = SPKPri * SPKPUB_server
    U = b'CuriosityIsTheHMACKeyToCreativity' + encodeParam(T)
    kHMAC = hashMessage(U)
    return kHMAC


E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b


IKAPub, IKAPri = generateKeys(n, P)

print("Identitiy Key is created")  # Identity key creation
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("IKey is a long term key and shouldn't be changed and private part should be kept secret. But this is a sample run, so here is my private IKey:", IKAPri)
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("My ID number is", stuID, "\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Signature of my ID number is:")

h, s = generateSignature(n, P, stuID, IKAPri)
print("h=", h)
print("s=", s, "\n")

print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Sending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(h, s, IKAPub.x, IKAPub.y, stuID)
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Received the verification code through email")
print("+++++++++++++++++++++++++++++++++++++++++++++")
code = int(input("Enter verification code which is sent to you: "))
print("+++++++++++++++++++++++++++++++++++++++++++++")
IKRegVerify(code, stuID, IKAPri, IKAPub)

print("\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Generating SPK...")  # SPK generation
SPKPub, SPKPri = generateKeys(n, P)
print("Private SPK:", SPKPri)
print("Public SPK.x:", SPKPub.x)
print("Public SPK.y:", SPKPub.y)
print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them result will be like: ", encodeParam(SPKPub))
print("\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")

h, s = generateSignature(n, P, SPKPub, IKAPri)
print("Signature of SPK is:")
print("h:", h)
print("s:", s)
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")
print("\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")
SPKPUB_x_server, SPKPUB_Y_server, h_server, s_server = SPKReg(
    h, s, SPKPub.x, SPKPub.y, stuID)
SPKPUB_server = Point(SPKPUB_x_server, SPKPUB_Y_server,
                      Curve.get_curve('secp256k1'))
print("if server verifies the signature it will send its SPK and corresponding signature. If this is the case SPKReg() function will return thoseServer's SPK Verification")
print("Recreating the message(SPK) signed by the server")
print("\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Verifying the server's SPK...")
print("If server's SPK is verified we can move to the OTK generation step")
SPKverified = verifySignature(
    s_server, P, h_server, IKey_Ser, n, SPKPUB_server)
print("Is SPK verified?:", SPKverified)

if (SPKverified is True):
    print("\n")
    print("+++++++++++++++++++++++++++++++++++++++++++++")

    print("Creating HMAC key (Diffie Hellman)")
    print("+++++++++++++++++++++++++++++++++++++++++++++")

    T = SPKPri * SPKPUB_server  # HMAC key generation
    print("T is", T)
    U = b'CuriosityIsTheHMACKeyToCreativity' + \
        encodeParam(T.y) + encodeParam(T.x)
    print("U is", U)
    kHMAC = SHA3_256.new(U).digest()
    print("HMAC key is created", kHMAC)
    print("+++++++++++++++++++++++++++++++++++++++++++++")
    print("\n")

    print("Creating OTKs starting from index 0...")
    print("\n")

    for y in range(0, 11):  # OTK generation
        OTKPub, OTKPri = generateKeys(n, P)
        print("{i}th key generated. Private part={private}".format(
            i=y, private=OTKPri))
        print("Public (x coordinate)={x_coor}".format(x_coor=OTKPub.x))
        print("Public (y coordinate)={y_coor}".format(y_coor=OTKPub.y))
        OTKPub_byte = encodeParam(OTKPub)
        print("x and y coordinates of the OTK converted to bytes and concatanated message", OTKPub_byte)
        hmac = HMAC.new(kHMAC, OTKPub_byte, digestmod=SHA256).hexdigest()
        print("HMAC is calculated and converted with 'hexdigest()':", hmac)
        print("\n")

        OTKReg(y, OTKPub.x, OTKPub.y, hmac, stuID)
        print("\n")
        print("+++++++++++++++++++++++++++++++++++++++++++++")
        print("\n")
    print("\n")
    print("+++++++++++++++++++++++++++++++++++++++++++++")

    print("Trying to delete OTKs...")  # Deleting keys
    h, s = generateSignature(n, P, stuID, IKAPri)
    ResetOTK(h, s, stuID)
    print("+++++++++++++++++++++++++++++++++++++++++++++")
    print("\n")
    print("Trying to delete SPKs...")
    h, s = generateSignature(n, P, stuID, IKAPri)
    ResetSPK(h, s, stuID)
    print("+++++++++++++++++++++++++++++++++++++++++++++")
    print("Trying to delete Identity Key...")
    rcode = int(
        input("Please enter your rcode (reset code) that was sent via email: "))
    ResetIK(rcode, stuID)
