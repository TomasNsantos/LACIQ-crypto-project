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
    NotImplemented
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
    B = client_data['B']

    # Calculate shared key
    S = pow(B, s, p) # S = B^s mod p , conforme a formula do protocolo de Diffie-Hellman
    
    # Calculate key
    key = get_key(S)

    # Decrypt message
    msg = decrypt_message(enc_msg, key)
    
    # Send confirmation message
    send_json(client_socket, {"msg": conf_msg})

    return key, msg





def exchange_keys_client(server_socket):
    """Client side key exchange implementation."""
    # Receive p, g, and server's public key from server
    server_data = recv_json(server_socket)
    p = server_data['p']
    g = server_data['g']

    # INSERT THE REST OF THE CODE HERE
    # Generate private and public keys
    a, A = create_keys(g, p)
    # Send public key to server
    send_json(server_socket, {"B": A})

    # Receive server's public key
    server_data = recv_json(server_socket)
    B = server_data['B']

    # Calculate shared key
    S = pow(B, a, p)  # S = B^a mod p

    # Calculate key
    key = get_key(S)

    # Receive and decrypt message
    enc_msg = server_data['enc_msg']
    msg = decrypt_message(enc_msg, key)

    # Receive confirmation message
    server_data = recv_json(server_socket)
    conf_msg = server_data['msg']

    return a, p, g, conf_msg