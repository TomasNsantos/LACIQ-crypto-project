import socket
import threading
import json
import os
from datetime import datetime
from key_protocol import exchange_keys_client, exchange_keys_server, create_keys, get_key
from utils import encrypt_message, decrypt_message, format_msg, write_msg_on_file,  send_json
import time

g = 2053
p = 3571


class GroupChat:
    def __init__(self, username, host, port):
        self.username = username
        self.host = host
        self.port = port
        self.key = None  # Will be set after key exchange
        self.history_file = os.path.join("Chats",f"chat_history_{username}.json")
        self.conversation_file_txt = os.path.join("Chats",f"chat_history_{username}.txt")
        self.clients = {}
        self.load_history()

    def load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                self.chat_history = json.load(f)
        else:
            self.chat_history = []

    def save_history(self):
        with open(self.history_file, 'w') as f:
            json.dump(self.chat_history, f, indent=4)


    def handle_incoming(self, client_socket, client_id, stop_event):
        while not stop_event.is_set():
            #try:
            encrypted_data = client_socket.recv(1024).decode()

            if encrypted_data:
                data = decrypt_message(encrypted_data, self.key)
                message = json.loads(data)

                if client_id is not None:
                    if "status" in message and message["status"] == "exit":
                        self.clients.pop(client_id)
                        print("remove client", client_id)
                        print(self.clients)
                        break
                    self.broadcast_message(message, client_id)


                print(format_msg(message))
                write_msg_on_file(message, self.conversation_file_txt)
                
                self.chat_history.append(message)
                self.save_history()
            
            # except Exception as e:
            #     print("Connection lost", e)
            #     break
  
    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        server.settimeout(20)
        print(f"Server started at {self.host}:{self.port}")

        server_stop_event = threading.Event()

        print(g,p)
        s, S = create_keys(g, p)
        print("chave compartilhada:", S)
        
        self.key = get_key(S)
        print("chave conforme fernet:",self.key)
        conf_msg = "funcionou"
        enc_msg = encrypt_message(conf_msg, self.key)
        client_stop_events = {}

        def monitor_clients():
            while not server_stop_event.is_set():
                if len(self.clients) == 0:
                    print("No clients connected. Starting 60-second countdown...")
                    for t in range(1,7):
                        time.sleep(10)
                        print(str(t*10) + "s")
                        if len(self.clients) > 0:
                            break

                    if len(self.clients) == 0:  # Check again after 60 seconds
                        print("No clients connected for 60 seconds. Shutting down server...")
                        server_stop_event.set()
                        break
            time.sleep(5)  # Check clients every 5 seconds

        
        # Start the monitor thread
        threading.Thread(target=monitor_clients, daemon=True).start()

        while not server_stop_event.is_set():
            try:
                client_socket, addr = server.accept()
            except TimeoutError:
                print("Server was waiting to accept clients, but reached time out")
                print("Closing Server")
                break
            print(f"Connection established with {addr}")
            client_stop_event = threading.Event()

            self.clients[addr] = client_socket
            client_stop_events[addr] = client_stop_event

            exchange_keys_server(client_socket, p, g, s, enc_msg, conf_msg)

            threading.Thread(target=self.handle_incoming, args=(client_socket, addr,client_stop_event), daemon= True).start()


        for addr, client_stop_event in client_stop_events.items():
            client_stop_event.set()  # Signal each client thread to stop
        for client in list(self.clients.values()):
            client.close()
        server.close()

    def connect_to_server(self, server_host, server_port):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_host, server_port))
        print(f"connected to the server at {server_host}:{server_port}")

        self.key = exchange_keys_client(client)
        
        stop_event = threading.Event()

        threading.Thread(target=self.handle_incoming, args=(client,None, stop_event), daemon= True).start()

        while True:
            message = input()
            if message.strip().lower() == 'exit':
                print("exiting chat...")
                stop_event.set()
                send_json(client, {"status" : "exit"}, self.key)
                break

            message_data = {
                "user": self.username,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": message
            }

            write_msg_on_file(message_data, file_path=self.conversation_file_txt)
            send_json(client, message_data, self.key)

        client.close()
        print("Connection closed.")

    def broadcast_message(self, message_data, from_client):
        for client_id, client_socket in self.clients.items():
            if client_id != from_client:
                send_json(client_socket, message_data, self.key)
                

    def run(self):

        print("1. start as server")
        print("2. connect to a server")
        choice = input("enter choice (1/2): ")

        if choice == '1':
            self.start_server()
        elif choice == '2':
            #server_host = input("enter server IP: ")
            #server_port = int(input("enter server port: "))
            server_host = self.host
            server_port = self.port
            self.connect_to_server(server_host, server_port)
        else:
            print("Invalid choice.")


