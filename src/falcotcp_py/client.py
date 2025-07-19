from typing import Callable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from socket import socket
from random import randbytes, shuffle
from threading import Thread, Lock
from time import sleep,time
from errors import AuthenticationError


class Client:
    timeout = 10
    def __init__(self) -> None:
        self.started = False
        self.connected = False
        self.host = ""
        self.ip = 0
        self.lock = Lock()
        pass
    def connect(self,host,port,key):
        """
            Connects to a FalcoTCP server
            - **host**: The ip the server is at
            - **port**: The port the server is listening
            - **key**: The connection key, for cryptography
        """
        with self.lock:
            if self.started == True:
                return
            self.started = True
            self.cipher = AESGCM(key)
            raw_payload = randbytes(128)
            nonce = randbytes(12)
            payload = self.cipher.encrypt(nonce,raw_payload,None)
            self.server = socket()
            self.server.settimeout(Client.timeout)
            self.server.connect((host,port))
            self.server.sendall(b'\x00' + nonce + payload) 
            response = self.server.recv(1)
            if response == b'\xff':
                self.connected = True
                self.started = True
            else:
                raise AuthenticationError("Failed to authenticate")
    def message(self,message : bytes) -> bytes:
        """
        Send a message to the FalcoTCP server and returns a response
        """
        with self.lock:
            nonce = randbytes(12)
            safe_pl = nonce+self.cipher.encrypt(nonce,message,None)
            self.server.sendall(b"\x01"+len(safe_pl).to_bytes(length=8,byteorder='big',signed=False)+safe_pl)
            length = int.from_bytes(signed=False,byteorder="big",bytes=self.server.recv(8))
        
            encrypted_response = self.server.recv(length)
            return self.cipher.decrypt(encrypted_response[:12],encrypted_response[12:],None)
    def ping(self):
        """
        Pings the server
        """
        with self.lock:
            self.server.sendall(b"\x02")
            pass
    def start_ping_cycle(self):
        """
        Allocate a green thread to send pings to the server over time, avoiding the connection ending due to idle.
        """
        Thread(daemon=True,target=self.___ping___).start()
    def ___ping___(self):
        while True:
            self.ping_with_delay()
    def ping_with_delay(self):
        """
        Sleeps for 15 seconds and then pings the server
        """
        sleep(15)
        with self.lock:
            self.ping()
 
