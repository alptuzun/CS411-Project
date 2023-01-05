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
    global E
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


stuID = 28991
stuIDB = 26045
# server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813,
                 8985629203225767185464920094198364255740987346743912071843303975587695337619, Curve.get_curve('secp256k1'))
print("In signature generation I fixed the random variable to 1748178 so that you can re-generate if you want")


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
    if (response.ok == False):
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


def PseudoSendMsgPH3(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put(
        '{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())


def ReqMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]


def ReqDelMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["MSGID"]


def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB': stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())


def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(
        otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())


def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB': stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get(
        '{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json())
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']

    else:
        return -1, 0, 0


def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


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


def generateSignatureFixedK(n, P, m, sA, k):
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
    print("T is", T)
    U = b'CuriosityIsTheHMACKeyToCreativity' + \
        encodeParam(T.y) + encodeParam(T.x)
    print("U is", U)
    kHMAC = SHA3_256.new(U).digest()  # ??????
    print("HMAC key is created", kHMAC)
    return kHMAC


def create_session_key(OTKPri, EKPubPoint):
    T = OTKPri * EKPubPoint
    U = encodeParam(T.x) + encodeParam(T.y) + b'ToBeOrNotToBe'
    ks = SHA3_256.new(U).digest()
    return ks


def create_KDF_chain(ks):
    kENC = SHA3_256.new(ks + b'YouTalkingToMe').digest()
    kHMAC = SHA3_256.new(ks + kENC + b'YouCannotHandleTheTruth').digest()
    KDFNext = SHA3_256.new(kENC + kHMAC + b'MayTheForceBeWithYou').digest()
    return kENC, kHMAC, KDFNext


E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b

IKAPub, IKAPri = generateKeys(n,P)

print("Identitiy Key is created")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("IKey is a long term key and shouldn't be changed and private part should be kept secret.")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("My ID number is", stuID, "\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Signature of my ID number is:")

h, s = generateSignature(n, P, stuID, IKAPri)
print("h=", h)
print("s=", s, "\n")

print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Sending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(h, s, IKAPub.x, IKAPub.y)
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Received the verification code through email")
print("+++++++++++++++++++++++++++++++++++++++++++++")
code = int(input("Enter verification code which is sent to you: "))
print("+++++++++++++++++++++++++++++++++++++++++++++")
IKRegVerify(code)
print("\n")
print("+++++++++++++++++++++++++++++++++++++++++++++")
print("Generating SPK...")
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
SPKPUB_x_server, SPKPUB_Y_server, h_server, s_server = SPKReg(
    h, s, SPKPub.x, SPKPub.y)
SPKPUB_server = Point(SPKPUB_x_server, SPKPUB_Y_server,
                      Curve.get_curve('secp256k1'))
SPKverified = verifySignature(
    s_server, P, h_server, IKey_Ser, n, SPKPUB_server)
print("Is SPK verified?:", SPKverified)

if (SPKverified):
    kHMAC_otk = generateHMAC(SPKPri, SPKPUB_server)
    OTKlist = []
    for y in range(0, 10):
        OTKPub, OTKPri = generateKeys(n, P)
        OTKPub_byte = encodeParam(OTKPub)
        hmac = HMAC.new(kHMAC_otk, OTKPub_byte, digestmod=SHA256).hexdigest()
        OTKReg(y, OTKPub.x, OTKPub.y, hmac)
        OTKlist.append(OTKPri)

    #Step 2 Codes

    print("Checking the inbox for incoming messages")
    print("+++++++++++++++++++++++++++++++++++++++++++++\n")
    print("Signing my stuID with my private IK")
    print("In signature generation I fixed the random variable to 1748178 so that you can re-generate if you want\n")

    fixed_k = 1748178 

    h, s = generateSignatureFixedK(n, P, stuID, IKAPri, fixed_k)    
    PseudoSendMsgPH3(h,s)
    print("+++++++++++++++++++++++++++++++++++++++++++++")
    curr_OTKid = 0
    counter = 0
    messages = {}
    valid_messages = {}
    for i in range(5):
        
        stuIDB, OTKID, MSGID, MSG, EKX, EKY = ReqMsg(h, s)
        print("I got this from client {p}:".format(p=stuIDB))
        print(MSG)
        
        print("Converting message to bytes to decrypt it...")
        MSG_bytes = MSG.to_bytes((MSG.bit_length() + 7) // 8, byteorder="big")
        print("Converted message is:")
        print(MSG_bytes)
        
        if(counter == 0):
            curr_OTKid = OTKID
            EKPubPoint = Point(EKX, EKY,
                                Curve.get_curve('secp256k1'))
            
            ks = create_session_key(OTKlist[curr_OTKid], EKPubPoint)
            print("Generating the key Ks, Kenc, & Khmac and then the HMAC value ..")
            kENC,kHMAC,KDFNext = create_KDF_chain(ks)
            
            counter += 1
        else:
            kENC,kHMAC,KDFNext = create_KDF_chain(KDFNext)
            
        nonce = MSG_bytes[:8]
        MAC = MSG_bytes[-32:]
        ciphertext = MSG_bytes[8:-32]

        AESCTR = AES.new(kENC, AES.MODE_CTR, nonce=nonce)
        
        hmac = HMAC.new(kHMAC, msg=ciphertext, digestmod=SHA256).digest()
        print("hmac is:", hmac)
        print("\n")
        
        if(hmac == MAC):
            print("Hmac value is verified")
            plaintext = AESCTR.decrypt(ciphertext).decode("UTF-8")
            print("The collected plaintext:", plaintext)
            Checker(stuID, stuIDB, MSGID, plaintext)
            print("\n")
            print("+++++++++++++++++++++++++++++++++++++++++++++")
            messages[MSGID] = plaintext
        else:
            print("Hmac value couldn't be verified")
            Checker(stuID, stuIDB, MSGID, "INVALIDHMAC")
            print("\n")
            print("+++++++++++++++++++++++++++++++++++++++++++++")
            messages[MSGID] = "INVALIDHMAC"

    deleted_messages = ReqDelMsg(h,s)
    print("Checking whether there were some deleted messages!! ")
    print("==========================================")
    for i,v in messages.items():
        if(v != "INVALIDHMAC"):
            try:
                if(i in deleted_messages):
                    print("Message", i, "-", "Was deleted by sender - X")
                    valid_messages[i] = v
                else:
                    print("Message", i, "-", v, "- Read")
                    valid_messages[i] = v
            except:
                print("Message", i, "-", v, "- Read")

    messages = ["Dormammu, I have come to bargain", "I have come to talk with you again"]
    print("Start of the main functions of phase 3 ...")
    print("++++++++++++++++++++++++++++++++++++++++++++\n")
    print("Now I want to send messages to my friend. Her id is 26045. Yes she is also imaginary")
    stuIDB = 26045
    fixed_k = 1748178 
    h, s = generateSignatureFixedK(n, P, stuIDB, IKAPri, fixed_k) 

    print("Signing The stuIDB of party B with my private IK")
    OTKID, OTKX, OTKY = reqOTKB(stuID, stuIDB, h, s)
    print("++++++++++++++++++++++++++++++++++++++++++++\n")
    print("The other party's OTK public key is acquired from the server ...")
    print("Generating Ephemeral key")

    OTKPoint = Point(OTKX, OTKY,Curve.get_curve('secp256k1'))

    ephemPub, ephemPri = generateKeys(n,P)

    #message = b'Dormammu, I have come to bargain'
    counter = 0
    for message in messages:
        if(counter == 0):
            KDFNext = create_session_key(ephemPri, OTKPoint)
            kENC,kHMAC,KDFNext = create_KDF_chain(KDFNext)
            counter += 1 
        else:
            kENC,kHMAC,KDFNext = create_KDF_chain(KDFNext)
            print("Sending another message")
            counter += 1

        print("The message I want to send:", message)
        message = encodeParam(message)
        print("Generating the KDF chain for the encryption and the MAC value generation")
        print("Generating session key using my EK and my friends Public OTK/ Phase 3...\n")
        cipher = AES.new(kENC, AES.MODE_CTR)
        nonce = cipher.nonce

        ciphertext = cipher.encrypt(message)

        hmac = HMAC.new(kHMAC, msg=ciphertext, digestmod=SHA256).digest()

        MSG = nonce + ciphertext + hmac

        MSG_int = int.from_bytes(MSG, byteorder='big')
        print("++++++++++++++++++++++++++++++++++++++++++++")
        print("Sending the message to the server, so it would deliver it to my friend whenever she is active ...")
        SendMsg(stuID, stuIDB, OTKID, counter, MSG_int, IKAPub.x, IKAPub.y)

    print("Now I'll encrypt the messages I retrieved initially from the server and send it to pseudo-client (26045)")
    print("I'll send them in a single block. But order of the messages should be considered\n")
    print("Signing The stuIDB of party B with my private IK")
    stuIDB = 26045
    fixed_k = 1748178 
    h, s = generateSignatureFixedK(n, P, stuIDB, IKAPri, fixed_k) 
    OTKID, OTKX, OTKY = reqOTKB(stuID, stuIDB, h, s)
    print("The other party's OTK public key is acquired from the server ...\n")
    print("++++++++++++++++++++++++++++++++++++++++++++")

    OTKPoint = Point(OTKX, OTKY,Curve.get_curve('secp256k1'))
    print("Get the message from the list of received messages ...\n")


    counter = 0

    for i,v in valid_messages.items():
        
        ephemPub, ephemPri = generateKeys(n,P)
        print("\n")
        print("++++++++++++++++++++++++++++++++++++++++++++")
        print("Generating Ephemeral key")
        print("Private part of my EK:", ephemPri)
        print("Generating the KDF chain for the encryption and the MAC value generation")
        print("Generating session key using my EK and my friend's Public OTK for the message with id", i)
        print("\n")
        print("Sending the message to the server, so it would deliver it to pseudo-client/user whenever it is active ...")

        
        if(counter == 0):
            KDFNext = create_session_key(ephemPri, OTKPoint)
            kENC,kHMAC,KDFNext = create_KDF_chain(KDFNext)
            counter += 1 
        else:
            kENC,kHMAC,KDFNext = create_KDF_chain(KDFNext)
            counter += 1

        message = encodeParam(valid_messages[i])

        cipher = AES.new(kENC, AES.MODE_CTR)
        nonce = cipher.nonce

        ciphertext = cipher.encrypt(message)

        hmac = HMAC.new(kHMAC, msg=ciphertext, digestmod=SHA256).digest()

        MSG = nonce + ciphertext + hmac

        MSG_int = int.from_bytes(MSG, byteorder='big')

        SendMsg(stuID, stuIDB, OTKID, i, MSG_int, IKAPub.x, IKAPub.y)

    print("\n")
    print("Checking the status of the inbox ...")
    fixed_k = 1748178 
    h, s = generateSignatureFixedK(n, P, stuID, IKAPri, fixed_k)
    numMsg, numOTK, statusmes = Status(stuID, h, s)
    if(numOTK < 2):
        print("You have", numMsg, "unread messages in your mailbox.")
        print("You have only", numOTK ,"OTK left. Please register new OTKs")
        
        newOTKlist = []
        newOTKlist.append(OTKlist[9])
        for y in range(0,9):
            OTKPub, OTKPri = generateKeys(n,P)
            OTKPub_byte = encodeParam(OTKPub)
            hmac = HMAC.new(kHMAC_otk, OTKPub_byte, digestmod = SHA256).hexdigest()
            OTKReg(y,OTKPub.x,OTKPub.y,hmac)
            newOTKlist.append(OTKPri)
        OTKlist = newOTKlist
        
    else:
        print("You have", numMsg, "unread messages in your mailbox.")
        print("You have", numOTK, "OTKs left.")

    print("+++++++++++++++++++++++++++++++++++++++++++++")
    print("Trying to delete OTKs...")  # Deleting keys
    h, s = generateSignature(n, P, stuID, IKAPri)
    ResetOTK(h, s)
    print("+++++++++++++++++++++++++++++++++++++++++++++")
    print("\n")
    print("Trying to delete SPKs...")
    h, s = generateSignature(n, P, stuID, IKAPri)
    ResetSPK(h, s)
    print("+++++++++++++++++++++++++++++++++++++++++++++")
    print("Trying to delete Identity Key...")
    rcode = int(
        input("Please enter your rcode (reset code) that was sent via email: "))
    ResetIK(rcode)
