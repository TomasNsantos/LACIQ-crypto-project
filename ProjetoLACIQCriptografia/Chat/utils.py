from cryptography.fernet import Fernet
import hashlib
import base64
import json
from datetime import datetime

def encrypt_message(message, key):
	fernet = Fernet(key)
	return fernet.encrypt(message.encode()).decode()

def decrypt_message(cipher, key):
    fernet = Fernet(key)
    return fernet.decrypt(cipher.encode()).decode()

def get_key(S):
	derived_key = hashlib.sha256(str(S).encode()).digest()[:32]
	key = base64.urlsafe_b64encode(derived_key)
	return key

def format_msg(message_data):
	return f"[{message_data['time']}] {message_data['user']}: {message_data['message']}"

def write_msg_on_file(message_data, file_path):
	with open(file_path, "a") as f:
		message_formated = format_msg(message_data) + '\n'
		f.write(message_formated)
	


def send_json(socket, data, key= None):

	data = json.dumps(data)
	if key is not None:
		data = encrypt_message(data, key)

	socket.send(data.encode())

def recv_json(socket, key= None):
	data = socket.recv(1024).decode()
	if key is not None:
		data = decrypt_message(data, key)
	
	message = json.loads(data)
	return message