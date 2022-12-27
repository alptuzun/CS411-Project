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

API_URL = 'http://10.92.52.255:5000/'

stuID = 28991
stuIDB = 2014


def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b//a, b % a
        m, n = x-u*q, y-v*q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def Setup():
    E = Curve.get_curve('secp256k1')
    return E


def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1, n-1)
    QA = sA*P
    return sA, QA


def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes(
        (r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big') % n
    s = (sA*h + k) % n
    return h, s


def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P - h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes(
        (v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big') % n
    if h_ == h:
        return True
    else:
        return False


def encodeParam(x):
    if (type(x) == str):
        return x.encode()
    elif (type(x) == int):
        return x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
    elif (type(x) == Point):
        return (encodeParam(x.x) + encodeParam(x.y))


# server's Identitiy public key
IKey_Ser = Point(0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d,
                 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, Curve.get_curve('secp256k1'))


def IKRegReq(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if ((response.ok) == False):
        print(response.json())


def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    if ((response.ok) == False):
        raise Exception(response.json())
    print(response.json())


def SPKReg(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    if ((response.ok) == False):
        print(response.json())
    else:
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']


def OTKReg(keyID, x, y, hmac):
    mes = {'ID': stuID, 'KEYID': keyID,
           'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetSPK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetOTK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())

############## The new functions of phase 2 ###############

# Pseudo-client will send you 5 messages to your inbox via server when you call this function


def PseudoSendMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json=mes)
    print(response.json())

# Get your messages. server will send 1 message from your inbox


def ReqMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

# Get the list of the deleted messages' ids.


def ReqDelMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["MSGID"]

# If you decrypted the message, send back the plaintext for checking


def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB': stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())


def SessionKey(OTK_A_Pri, EK_B_Pub):
    T = OTK_A_Pri * EK_B_Pub
    U = encodeParam(T) + b'ToBeOrNotToBe'
    hashU = SHA3_256.new(U).digest()
    return hashU


def KDFChain(K_KDF):
    ENC = encodeParam(K_KDF) + b'YouTalkingToMe'
    K_ENC = SHA3_256.new(ENC).digest()
    HMAC = encodeParam(K_KDF) + encodeParam(K_ENC) + b'YouCannotHandleTheTruth'
    K_HMAC = SHA3_256.new(HMAC).digest()
    KDF_Next = encodeParam(K_ENC) + encodeParam(K_HMAC) + \
        b'MayTheForceBeWithYou'
    K_KDF_Next = SHA3_256.new(KDF_Next).digest()
    return K_ENC, K_HMAC, K_KDF_Next


E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

IKAPub, IKAPri = KeyGen(E)
h_id, s_id = SignGen(stuID, E, sA)
print("Sending signature and my IKEY to server via IKRegReq() function in json format\n")
IKRegReq(h_id, s_id, IKAPub.x, IKAPub.y, stuID)
code = int(input("Enter verification code which is sent to you: "))
print("+++++++++++++++++++++++++++++++++++++++++++++")
IKRegVerify(code)
SPKPub, SPKPri = KeyGen(E)
h, s = SignGen(SPKPub, E, sA)
SPKPUB_x_server, SPKPUB_Y_server, h_server, s_server = SPKReg(
    h, s, SPKPub.x, SPKPub.y, stuID)
SPKPUB_server = Point(SPKPUB_x_server, SPKPUB_Y_server,
                      Curve.get_curve('secp256k1'))
print("Verifying the server's SPK...")
print("If server's SPK is verified we can move to the OTK generation step")
    
SPKverified = SignVer(SPKPUB_server, h_server, s_server, E, IKey_Ser)

if SPKverified:
    T = SPKPri * SPKPUB_server
    U = b'CuriosityIsTheHMACKeyToCreativity' + \
        encodeParam(T.y) + encodeParam(T.x)
    kHMAC = SHA3_256.new(U).digest()
    OTKPub, OTKPri = KeyGen(E)
    OTKPub_byte = encodeParam(OTKPub)
    hmac = HMAC.new(kHMAC, OTKPub_byte, digestmod=SHA256).hexdigest()
    OTKReg(y, OTKPub.x, OTKPub.y, hmac, stuID)

    print("Checking the inbox for incoming messages\n")
    print("+++++++++++++++++++++++++++++++++++++++++++++\n\n")
    PseudoSendMsg(h_sign, s_sign)