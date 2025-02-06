import os
from utils import get_key
from utils import decrypt_message, recv_json, send_json
from sympy import randprime
from math import log2


"""
As funcoes recv_json e send_json sao usadas para enviar e receber dicionarios

recv_json tem:
    * input: socket 
    * output: dicionario
send_json tem:
    * input: socket e o dicionario
    * output: None

Quando o servidor inicia, ele ja escolhe uma mensagem de confirmacao (conf_msg) para os clients e ja cifra (obtendo enc_msg).
Por isso nao precisa usar o algoritmo de encriptacao, pois o cifrotexto ja vem no argumento da funcao.

A funcao decrypt_message inverte a funcao de encriptacao usada pelo servidor se for usada com a mesma chave.
    * input: cifrotexto (use str) e chave
    * output: mensagem decriptada

    ATENCAO, A chave DEVE SER OBTIDA USANDO A FUNCAO get_key.
    Nao passe o valor da chave compartilhada obtida diretamente para decrypt_message.
    Faca:
    chave = get_key(chave_compatilhada) # chave_compartilhada tem tipo int
    decrypt_message(cifrotexto, chave)

"""



def create_private_key(g, p, prime_key= False):
    if prime_key:
        a = randprime(2**16, 2**20)
    else:
        n_bits = int(log2(p))
        a = int.from_bytes(os.urandom(n_bits), 'little')

    return a

def create_keys(g, p, prime_key= False) :
    # INSERT THE REST OF THE CODE HERE
    # must return the private key a and the public key A
    # if prime_key == True, a must be prime.
    a = create_private_key(g, p, prime_key)
    A = pow(g, a, p) # A = g^a mod p , conforme a formula do protocolo de Diffie-Hellman
    return a, A


def exchange_keys_server(client_socket, p, g, s, enc_msg, conf_msg):
    # Send p and g to client
    send_json(client_socket, {"p": p, "g": g})

    # INSERT THE REST OF THE CODE HERE

    # Receive client's public key
    client_data = recv_json(client_socket)
    A = client_data['client_public_key']
    print(f"Servidor recebeu A (chave pública do cliente): {A}")

    # Calculate shared key from server
    B = pow(g, s, p) # S = g^s mod p , conforme a formula do protocolo de Diffie-Hellman
    print(f"Servidor calculou B (chave pública do servidor): {B}")
    
    #g elevado a S, nao B elevado a s #IMPORTANTE
    # Calculate key
    #key = get_key(S)

    # Enviar B e enc_msg para o cliente
    send_json(client_socket, {"server_public_key": B, "encrypted_message": enc_msg})

    # Calcular a chave compartilhada (S = A^s mod p)
    shared_key = pow(A, s, p)

    # Derivar a chave com get_key
    fernet_key = get_key(shared_key)

    print(f"Servidor calculou chave compartilhada (S): {shared_key}")
    print(f"Servidor derivou chave Fernet: {fernet_key}")
    print(f"Servidor enviou mensagem cifrada: {enc_msg}")

    # Decrypt message
    #msg = decrypt_message(enc_msg, key) NAO USA ISSO NO SERVER
    #server nao usa decrypt!!1!!
    # Send confirmation message
    send_json(client_socket, {"confirmation_message": conf_msg})
    #msg = key
    
    return shared_key




def exchange_keys_client(server_socket):
    """Client side key exchange implementation."""
    
    # Receive p, g, and server's public key from server
    server_data = recv_json(server_socket)
    p = server_data['p']
    g = server_data['g']
    print(f"Cliente recebeu p: {p}, g: {g}")

    # INSERT THE REST OF THE CODE HERE

    # Generate CLIENT private and public keys (a, A)
    a, A = create_keys(g, p, prime_key=True)
    print(f"Cliente gerou a (privada): {a}, A (pública): {A}")

    # Send A (CLIENT public key) to server
    send_json(server_socket, {"client_public_key": A})

    # Receive  B (SERVER's public key) and enc_msg from server
    server_data = recv_json(server_socket)
    B = server_data['server_public_key']
    enc_msg = server_data['encrypted_message']
    print(f"Cliente recebeu B (chave pública do servidor): {B}")

    # Calculate shared key
    shared_key = pow(B, a, p)  # Shared_key = B^a mod p

    # Calculate key with get_key
    fernet_key = get_key(shared_key)

    
    print(f"Cliente calculou chave compartilhada (S): {shared_key}")
    print(f"Cliente derivou chave Fernet: {fernet_key}")
    print(f"Cliente recebeu mensagem cifrada: {enc_msg}")

    # Decrypt message   DECRIPTACAO
    #message = decrypt_message(enc_msg, key)
    # Decifrar a mensagem com a chave derivada
    try:
        message = decrypt_message(enc_msg, fernet_key)
        print(f"Cliente decifrou mensagem: {message}")
    except Exception as e:
        print(f"Erro ao decifrar mensagem: {e}")
        raise

    # Receive confirmation message
    confirmation = server_data['confirmation_message']

    return shared_key, message, confirmation