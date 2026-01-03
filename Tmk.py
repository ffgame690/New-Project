import socket
import select
import requests
import threading
import re
import time
import struct
import random
import urllib3
from datetime import datetime
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#CLASS SOCKES5!
SOCKS_VERSION = 5
class Proxy:
    def __init__(self):
        self.username = "your_username"
        self.password = "your_password"
    def handle_client(self, connection):
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS_VERSION, 2]))
        if not self.verify_credentials(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
            else:
                connection.close()
            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        except Exception as e:
            reply = self.generate_failed_reply(address_type, 5)
        connection.sendall(reply)
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)
        connection.close()
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    def get_bot(self):
        try:
            get_bot1 = f""
            self.client0500.send(bytes.fromhex(get_bot1))    
        except:
            pass
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    def handle_id(self, iddd):
        if '***' in iddd:
            iddd = iddd.replace('***', '106')
        iddd = str(iddd).split('(\\x')[0]
        add_id_packet = self.Encrypt_ID(iddd)
        finale_packet = Danse_Players(add_id_packet)
        self.client0500.send(bytes.fromhex(finale_packet))
#━━━━━━━━━━━━━━━━━━━
    def exchange_loop(self, client, remote):
        global fake_friend, spam_room, spam_inv, get_room_code, packet_start, recode_packet, bot_true, bot_codes
        while True:
            r, w, e = select.select([client, remote], [], [])
            #CLIENT
            if client in r:
                try:
                    dataC = client.recv(9999)
                except:
                    break
                #ports
                if "39699" in str(client):
                    self.client0500 = client
                if "39699" in str(remote):
                    self.remote0500 = remote
                try:
                    if remote.send(dataC) <= 0:
                        break 
                except:
                    break 
            #SERVER
            if remote in r:
                try:
                    dataS = remote.recv(9999)
                except:
                    break
                self.EncryptedPlayerid = dataS.hex()[12:22]
                self.client1200 = client
                if "0500" in dataS.hex()[0:4]:
                    self.client0500 = client                
                if b"@1" in dataS:
                    look_idss = ['9980edb303', 'e1e8ecb303', '8391eab303', '8291eab303', '91d9ecb303', '9980edb303', '8188edb303', '9a80edb303', 'd9c1ecb303', 'f1b9ecb303', 'd197edb303']
                    try:
                            for look_ids in look_idss:
                                self.client0500.send(bytes.fromhex(f"080000003208c0c5cefb18100820062a260a2408{look_ids}100118a7ebd7c60620ffffffffffffffffff01280130809a9e0138024009"))
                    except:
                        pass
                if client.send(dataS) <= 0:
                    pass
#━━━━━━━━━━━━━━━━━━━
    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ]) 
    def verify_credentials(self, connection):
        version = connection.recv(1)[0]
        username_len = connection.recv(1)[0]
        username = connection.recv(username_len).decode('utf-8')
        password_len = connection.recv(1)[0]
        password = connection.recv(password_len).decode('utf-8')
        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        else:
            response = bytes([version, 0])
            connection.sendall(response)
            return True  
    def get_available_methods(self, nmethods, connection):
        methods = []
        for _ in range(nmethods):
            methods.append(connection.recv(1)[0])
        return methods
    def run(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # تكفي مرة واحدة
        try:
            s.bind((ip, port))
            s.listen()
            print(f"* Socks5 proxy server is running on {ip}:{port}")
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(conn,))
                t.daemon = True  # ⬅️ تجعل الثريد ينتهي عند إغلاق البرنامج
                t.start()
        except OSError as e:
            print(f"Error: {e} (Port may be in use)")
        except Exception as e:
            print(f"Unexpected error: {e}")
        finally:
            s.close()

def start_bot():
    threads = []
    try:
        proxy = Proxy()
        t = threading.Thread(target=proxy.run, args=("127.0.0.1", 3000))
        t.daemon = True  # ⬅️ تجعل الثريد الرئيسي ينتهي عند إغلاق البرنامج
        t.start()
        threads.append(t)
        
        # الانتظار إلى الأبد (بدون join الذي يسبب التوقف)
        while True:
            pass
    except Exception as e:
        print(f"Error in start_bot: {e}")

if __name__ == "__main__":
    start_bot()
