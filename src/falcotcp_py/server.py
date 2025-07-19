from typing import Callable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from socket import socket
from random import randbytes, shuffle
from threading import Thread, Lock
from time import sleep,time
from errors import AuthenticationError

class ServerTaskCounter:
    def __init__(self) -> None:
        self.count = [0,Lock()]
    def ad(self):
        with self.count[1]:
            self.count[0] += 1
    def su(self):
        with self.count[1]:
            self.count[0] -= 1
    def what(self) -> int:
        with self.count[1]:
            return self.count[0]

class ConnectionKeeperItem:
    def __init__(self,socket : socket,clock : float, l) -> None:
        self.socket = socket
        self.clock = clock
        self.lock = l
def cki(s,c,l) -> ConnectionKeeperItem:
    return ConnectionKeeperItem(s,c,l)


class Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 1200, key: bytes = bytes(32), message_handler: Callable = print, workers: int = 2, timeout: int = 5, interval: float = 0.01) -> None:
        """
            Creates a `Server` object and run it.
        """
        self.socket = socket()
        self.socket.bind((host, port))
        self.socket.listen(5)
        self.task = (ServerTaskCounter(), Lock())
        self.cipher = AESGCM(key)
        self.handler = message_handler
        self.key = key
        self.timeout = timeout
        self.interval = interval
        self.connection_keeper = [[], 0, Lock()]
        self.task_count = ServerTaskCounter()
        thread = Thread(target=self.accept, daemon=True)
        thread.start()
        
        for _ in range(max(workers-1, 1)):
            Thread(target=self.compute, daemon=True).start()
        print("\033[32m[INFO]\033[0m \tServer is now running.")
        thread.join()
    
    def accept(self):
        while True:
            sock = self.socket.accept()[0]
            sock.settimeout(self.timeout)
            
            payload = sock.recv(157)  
            
            
            if len(payload) < 157 or payload[0] != 0:
                print("Invalid handshake format")
                sock.close()
                continue
                
            nonce = payload[1:13]      
            cipher_text = payload[13:]            
            try:
                decrypted = self.cipher.decrypt(nonce=nonce, data=cipher_text, associated_data=None)
                
                sock.sendall(b'\xff')
                
                with self.connection_keeper[2]:
                    self.connection_keeper[0].append(cki(sock, time(), Lock()))
                    self.connection_keeper[1] += 1
                    print("\033[32m[INFO]\033[0m \tA new connection was established") 
            except Exception as ex:
                print(f"Authentication failed: {str(ex)}")
                
                try:
                    sock.sendall(b'\x00') 
                except:
                    pass
                sock.close()
                continue
            sleep(self.interval)
    
    def compute(self):
        while True:
            connections_snapshot = []
            with self.connection_keeper[2]:
                connections_snapshot = [(i, self.connection_keeper[0][i]) for i in range(len(self.connection_keeper[0]))]
            
            shuffle(connections_snapshot)
            
            if len(connections_snapshot) > 0:
                for i, ci in connections_snapshot:
                    if ci is not None:
                        should_remove = False
                        
                        with ci.lock:
                            if time() - ci.clock > 60:
                                should_remove = True
                            else:
                                s: socket = ci.socket
                                try:
                                    msg_type = s.recv(1)
                                    if not msg_type:
                                        should_remove = True
                                        continue
                                    
                                    if msg_type == b'\x01':  
                                        length_bytes = s.recv(8)
                                        if len(length_bytes) < 8:
                                            should_remove = True
                                            continue
                                        
                                        element = int.from_bytes(bytes=length_bytes, byteorder="big")
                                        array = s.recv(element)
                                        
                                        if len(array) < 12: 
                                            should_remove = True
                                            continue
                                        
                                        nonce = array[:12]
                                        cipher = array[12:]
                                        value = self.cipher.decrypt(data=cipher, nonce=nonce, associated_data=None)
                                        
                                        respb = bytes(self.handler(value))
                                        response_nonce = randbytes(12)
                                        encrypted_response = self.cipher.encrypt(nonce=response_nonce, data=respb, associated_data=None)
                                        full_response = response_nonce + encrypted_response
                                        
                                        length = len(full_response).to_bytes(length=8, byteorder="big", signed=False)
                                        s.sendall(length)
                                        s.sendall(full_response)
                                        
                                        ci.clock = time()
                                    
                                    elif msg_type == b'\x02':  
                                        ci.clock = time()
                                    else:
                                        should_remove = True
                                        
                                except Exception as ex:
                                    print(f"\033[38;5;208m[WARN]\033[0m \tAn exception was raised: {str(ex)}")
                                    try:
                                        s.sendall(int(0).to_bytes(length=8, byteorder="big", signed=False))
                                    except:
                                        should_remove = True
                        
                        if should_remove:
                            with self.connection_keeper[2]:
                                try:
                                    if i < len(self.connection_keeper[0]) and self.connection_keeper[0][i] == ci:
                                        self.connection_keeper[0][i].socket.close()
                                        del self.connection_keeper[0][i]
                                        self.connection_keeper[1] -= 1
                                        print("\033[38;5;208m[WARN]\033[0m \tDropped a connection due to timeout or error")
                                except (IndexError, AttributeError):
                                    pass
            
            sleep(self.interval)