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
    A = pow(g, a, p) # A = g^a mod p , conforme a formula do protocolo de Diffie-Hellman(MAS ALTERADO,NAO USANDO A FORMULA ORIGINAL EM TUDO)
    return a, A


def exchange_keys_server(client_socket, p, g, s, enc_msg, conf_msg):
    # Send p and g to client
    send_json(client_socket, {"p": p, "g": g})

    # INSERT THE REST OF THE CODE HERE


    # Receive client's public key (A_i)
    client_data = recv_json(client_socket)
    A_i = client_data['client_public_key']
    print(f"Servidor recebeu A_i (chave pública do cliente): {A_i}")

    # Calculate public key A_i^s = (A_i)^s mod p
    A_i_s = pow(A_i, s, p)
    print(f"Servidor calculou A_i^s: {A_i_s}")

    # Send A_i^s (Public key do servidor) and encrypted message to client
    send_json(client_socket, {"A_i_s": A_i_s, "encrypted_message": enc_msg})
    print(f"Servidor enviou cifrotexto: {enc_msg}")
    print(f"Servidor enviou A_i^s (chave pública do servidor): {A_i_s}")

    #Receive m' from client / m_prime = m'= possible decrypted message
    client_data = recv_json(client_socket)
    m_prime = client_data["decrypted_message"]
    print(f"Servidor recebeu m' do cliente: {m_prime}")

    # Compare m' with original confirmation message
    if m_prime == conf_msg:
        result = "ok"
    else:
        result = "not ok"
    print(f"Servidor enviou resultado: {result}")

    # Send result to client
    send_json(client_socket, {"result": result})

    return result




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
    send_json(server_socket, {"client_public_key": A})
    print(f"Cliente gerou a (privada): {a}, A (pública): {A}")
    print(f"Cliente enviou A (chave pública do cliente): {A}")


    # Receive A_i^s (SERVER's public key) and enc_msg from server
    server_data = recv_json(server_socket)
    A_i_s = server_data['A_i_s']
    enc_msg = server_data['encrypted_message']
    print(f"Cliente recebeu A_i_s (chave pública do servidor): {A_i_s}")
    print(f"Cliente recebeu mensagem cifrada: {enc_msg}")


    #ADEQUANDO AO PROTOCOLO DO PDF: Calcular g^s = (A_i^s)^(a_i^-1) mod p
    #shared_key_g_s = shared_key = g^s
    #represents the shared key calculated as g^s, derived from the protocol

    a_inverse = pow(a, -1, p-1) #a_i^-1 , o inverso modular de a_i
    shared_key_g_s = pow(A_i_s, a_inverse, p) #g^s = (A_i^s)^(a_i^-1) mod p
    print(f"Cliente calculou chave compartilhada(a partir do inv_modular) (S): {shared_key_g_s}")

    # Derive Fernet key from shared key
    fernet_key = get_key(shared_key_g_s)

    print(f"Cliente derivou chave Fernet: {fernet_key}")

    # Decryption of the message with the derived key
    m_prime = decrypt_message(enc_msg, fernet_key)
    print(f"Cliente decifrou mensagem: {m_prime}")

    #Send m' to server
    send_json(server_socket, {"decrypted_message": m_prime})

    # Receive result from server
    server_data = recv_json(server_socket)
    result = server_data['result']
    print(f"Cliente recebeu resultado do servidor: {result}")

    return shared_key_g_s, m_prime , result