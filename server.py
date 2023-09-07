import socket
import threading
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

HOST = '127.0.0.1'
PORT = 12345
LISTENER_LIMIT = 5
active_clients = []
parameters = dh.generate_parameters(generator=2, key_size=2048)

def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext)

def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:])

def send_messages_to_all(message):
    for user in active_clients:
        username, client, derived_key = user
        encrypted_message = encrypt(derived_key, message.encode('utf-8'))
        client.sendall(encrypted_message)

def client_handler(client):
    parameters_pem = parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
    client.sendall(parameters_pem)

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    client.sendall(public_key)

    client_public_key_bytes = client.recv(2048)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
    shared_key = private_key.exchange(client_public_key)
    derived_key = hashlib.sha256(shared_key).digest()

    encrypted_username = client.recv(2048)
    username = decrypt(derived_key, encrypted_username).decode('utf-8')
    active_clients.append((username, client, derived_key))
    prompt_message = "SERVER~" + f"{username} added to the chat"
    send_messages_to_all(prompt_message)

    while True:
        encrypted_message = client.recv(2048)
        message = decrypt(derived_key, encrypted_message).decode('utf-8')
        if message != '':
            final_msg = username + '~' + message
            send_messages_to_all(final_msg)
        else:
            print(f"The message sent from client {username} is empty")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except:
        print(f"Unable to bind to host {HOST} and port {PORT}")

    server.listen(LISTENER_LIMIT)

    while True:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")
        threading.Thread(target=client_handler, args=(client,)).start()

if __name__ == '__main__':
    main()