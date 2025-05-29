# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
import socket
import base64
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from utils import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from connections.Connection import Connection
from Commands import Commands

conn_addr = '127.0.0.1'
conn_port = 7777
max_msg_size = 9999


p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2 
PARAMETERS = dh.DHParameterNumbers(p, g).parameters() 

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self,addr=conn_addr,port=conn_port):
        """ Construtor da classe. """
        self.id = input('Insert username\n>')
        if not os.path.exists(f"VAULT_CLI{self.id}"):
            os.makedirs(f"VAULT_CLI{self.id}")
        self.msg_cnt = 0
        self.connection = Connection(addr,port)

        self.client_private_key = PARAMETERS.generate_private_key()
        self.client_public_key = self.client_private_key.public_key()

        self.load_rsa_keys()

    def load_rsa_keys(self):
        """Carrega as chaves RSA a partir dos arquivos .crt e .key"""
        try:
            # Carregar chave privada
            with open(f"projCA/VAULT_CLI{self.id}.key", "rb") as f:
                client_private_key_bytes = f.read()
            
            self.client_rsa_private_key = load_pem_private_key(client_private_key_bytes, password=None)
            
            # Carregar certificado e extrair chave pública
            client_cert = cert_load(f"projCA/VAULT_CLI{self.id}.crt")
            self.client_rsa_public_key = client_cert.public_key()
            
            print(f"RSA keys successfully loaded for user {self.id}")
        except FileNotFoundError as e:
            print(f"Error: Certificate or key file not found for user {self.id}")
            print(f"Make sure files projCA/VAULT_CLI{self.id}.key and projCA/VAULT_CLI{self.id}.crt exist")
            raise e
        except Exception as e:
            print(f"Error loading RSA keys: {e}")
            raise e


    def getClientPublicBytes(self):
        return self.client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def encrypt(self, msg: str) -> bytes:
        """Encrypt a message using AESGCM and include the key in the message"""
        if not msg:
            return b""
            
        aesgcm = AESGCM(self.shared_key)
        nonce = os.urandom(12)
        
        # No associated data
        ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
        
        # Format: nonce (12 bytes) + key (16 bytes) + ciphertext
        return nonce + ciphertext

    

    def encrypt_file(self, file_path: str, file_id: str) -> tuple:
        try:
            aes_key = os.urandom(16)
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)

            with open(f"VAULT_CLI{self.id}/{file_id}.key", 'wb') as k:
                k.write(aes_key)

            with open(file_path, 'rb') as f:
                file_content = f.read()

            ciphertext = aesgcm.encrypt(nonce,file_content, None)

            command_msg = f"file"

            encrypted_command = self.encrypt(command_msg)

            encrypted_data = nonce + ciphertext 

            return encrypted_data, encrypted_command 
        
        except Exception as e: 
            print(f"File encryption failed: {e}")
            return None, None

    def encrypt_replaced_file(self, file_path: str, file_id: str) -> tuple:
        """
        Encripta um arquivo usando uma chave AES existente (file_id.key)
        
        Args:
            file_path: Caminho do arquivo a ser encriptado
            file_id: ID do arquivo para buscar a chave existente
            
        Returns:
            tuple: (encrypted_data, encrypted_command) ou (None, None) em caso de erro
        """
        try:
            # 1. Buscar a chave existente
            key_path = f"VAULT_CLI{self.id}/{file_id}.key"
            if not os.path.exists(key_path):
                print(f"Chave não encontrada para file_id: {file_id}")
                return None, None
            
            print("antes do open")

            with open(key_path, 'rb') as k:
                aes_key = k.read()
                

            # 2. Inicializar AES-GCM
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)  # Novo nonce para cada encriptação

            print("nonce")
            # 3. Ler e encriptar o arquivo
            with open(file_path, 'rb') as f:
                file_content = f.read()

            ciphertext = aesgcm.encrypt(nonce, file_content, None)

            # 4. Preparar comando
            command_msg = "file"
            encrypted_command = self.encrypt(command_msg)

            # 5. Concatenar nonce + ciphertext
            encrypted_data = nonce + ciphertext

            print("alo")

            return encrypted_data, encrypted_command
            
        except Exception as e:
            print(f"Falha ao encriptar arquivo substituído: {e}")
            return None, None

    def encrypt_key(self, file_key: bytes, public_key_pem: str) -> bytes:
        try:

            public_key = serialization.load_pem_public_key(
                    public_key_pem.encode('utf-8'),
            )

            encrypted_file_key = public_key.encrypt(
                    file_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            print("okok ma boy")
            return encrypted_file_key
        except Exception as e:
            print(f"Error encrypting file key: {e}")
            # Print some debug info about the key format
            print(f"Public key PEM first 50 chars: {public_key_pem[:50]}...")
            raise

    def encrypt_file_with_key(self, file_path: str, aes_key: bytes) -> tuple:
        """
        Encripta um arquivo usando uma chave AES específica
        
        Args:
            file_path: Caminho do arquivo a ser encriptado
            aes_key: Chave AES (16 bytes para AES-128)
            
        Returns:
            tuple: (nonce + ciphertext, encrypted_command) ou (None, None) em caso de erro
        """
        try:
            # Verifica se a chave tem tamanho correto
            if len(aes_key) != 16:
                raise ValueError("Chave AES deve ter 16 bytes (AES-128)")
                
            # Inicializa AES-GCM
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)  # Nonce único para cada encriptação

            # Lê e encripta o arquivo
            with open(file_path, 'rb') as f:
                file_content = f.read()

            ciphertext = aesgcm.encrypt(nonce, file_content, None)

            # Prepara comando (opcional, conforme sua implementação)
            command_msg = "file"
            encrypted_command = self.encrypt(command_msg)

            return (nonce + ciphertext), encrypted_command
            
        except Exception as e:
            print(f"Falha na encriptação com chave: {e}")
            return None, None


    def decrypt(self, enc: bytes) -> str:
        """Decrypt a message using AESGCM"""


        if not enc or len(enc) < 29:  # minimum size: nonce (12) + key (16) + ciphertext (1)
            return ""
            
        try:
            nonce = enc[:12]
            ciphertext = enc[12:]
            
            aesgcm = AESGCM(self.shared_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            txt = plaintext.decode()

            return txt
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def decrypt_key(self, encrypted_key: bytes) -> bytes:
        try:
            decrypted_key = self.client_rsa_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_key
        except Exception as e:
            print(f"Error decrypting file key: {e}")
            return None

    def decrypt_file(self, encrypted_data: bytes, file_key: bytes) -> bytes:
       try:
            if len(encrypted_data) < 12:  # minimum size: nonce (12)
                print("Invalid encrypted data format")
                return None
                
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            aesgcm = AESGCM(file_key)
            decrypted_content = aesgcm.decrypt(nonce, ciphertext, None)
            
            return decrypted_content
       except Exception as e:
           print(f"File decryption error: {e}")
           return None


    async def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        
        if self.msg_cnt == 1:
            pkc = self.getClientPublicBytes()  # Bytes
            cli = self.id.encode()             # Bytes

            pkc_len = len(pkc).to_bytes(2)

            return pkc_len + pkc + len(cli).to_bytes(2) + cli
        
        elif self.msg_cnt == 2:
            #print(msg)
            
            gy_bytes, remaining = unpair(msg)
            nonce, remaining = unpair(remaining)
            encrypted_signature, cert_bytes = unpair(remaining)
            
            self.server_public_key = serialization.load_pem_public_key(gy_bytes)
            shared_key = self.client_private_key.exchange(self.server_public_key)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            
            aesgcm = AESGCM(self.shared_key)
            try:
                signature = aesgcm.decrypt(nonce, encrypted_signature, None)
                print("signature decrypted")
            except Exception as e:
                print("signature not decrypted")
                print(e)
                return None
            
            server_cert = x509.load_pem_x509_certificate(cert_bytes)
            ca_cert = cert_load("projCA/VAULT_CA.crt")
            if not valida_certServer(server_cert, ca_cert):
                print("Server certificate validation failed!")
                return None
            print("Server certificate validated successfully.")
    
            server_public_key = server_cert.public_key()
            
            concatenated_bytes = mkpair(
                gy_bytes,
                self.client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            
            server_public_key.verify(
                signature,
                concatenated_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )
            print("signature from server verified")
            
            gx_bytes = self.client_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            concatenated = mkpair(gx_bytes, gy_bytes)
            
            with open(f"projCA/VAULT_CLI{self.id}.key", "rb") as f:
                client_private_key_bytes = f.read() 
            
            client_private_key = load_pem_private_key(client_private_key_bytes, password=None)
                
            signature = client_private_key.sign(
                concatenated,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            aesgcm = AESGCM(self.shared_key)
            nonce = os.urandom(12)
            encrypted_signature = aesgcm.encrypt(nonce, signature, None)
            
            client_cert = cert_load(f"projCA/VAULT_CLI{self.id}.crt")
            cert_bytes = client_cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
            
            response = mkpair(gx_bytes, mkpair(nonce, mkpair(encrypted_signature, cert_bytes)))
            return response
        elif self.msg_cnt == 3:
            rsa_public_key_pem = self.client_rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

            return self.encrypt(rsa_public_key_pem.decode())
        else:
            decrypted_msg = self.decrypt(msg)
            print(f"Received ({self.msg_cnt}): {decrypted_msg}")

            if decrypted_msg:
                if decrypted_msg.startswith("file "):
                    file_path = decrypted_msg.split()[1]
                    file_id = decrypted_msg.split()[2]

                    encrypted_file, encrypted_command = self.encrypt_file(file_path, file_id)
                    encrypted = base64.b64encode(encrypted_file).decode()
                    if encrypted_file and encrypted_command:
                        return self.encrypt(f"encrypted_file 0 {file_id} {encrypted}")
                    else:
                        print(f"failed to encrypt file")
                
                elif decrypted_msg.startswith("public_key"):
                    parts = decrypted_msg.split('\n')
                    file_id = parts[1]
                    target_user = parts[2]
                    public_key = '\n'.join(parts[3:])
                    
                    try:
                        # Lê a chave do arquivo
                        key_path = f"VAULT_CLI{self.id}/{file_id}.key"
                        if os.path.exists(key_path):
                            with open(key_path, 'rb') as k:
                                file_key = k.read()
                            
                            # Encripta a chave com a chave pública do solicitante
                            encrypted = self.encrypt_key(file_key, public_key)
                            encrypted_key = base64.b64encode(encrypted).decode()
                            
                            # Retorna a resposta imediatamente sem esperar input do usuário
                            print(f"Automatically sending key for file {file_id} to user {target_user}")
                            return self.encrypt(f"key\n{target_user}\n{file_id}\n{encrypted_key}")
                        else:
                            print(f"Key file not found: {key_path}")
                            return self.encrypt(f"ERROR: Key file for {file_id} not found")
                    except Exception as e:
                        print(f"Error processing key request: {e}")
                        return self.encrypt(f"ERROR: Failed to process key request: {str(e)}")

                elif decrypted_msg.startswith("content"):
                    parts = decrypted_msg.split('\n')
                    file_id = parts[1]
                    flag = int(parts[2])

                    if flag == 0:
                        with open(f"VAULT_CLI{self.id}/{file_id}.key", 'rb') as k:
                            key = k.read()

                        encrypted_content = base64.b64decode(parts[3])
                        content = self.decrypt_file(encrypted_content, key)

                        print(f"content:\n {content}")
                    elif flag == 1:
                        encrypted_content = base64.b64decode(parts[-1])
                        encrypted_key = base64.b64decode(parts[3])

                        file_key = self.decrypt_key(encrypted_key)
                        if file_key:
                            decrypted_content = self.decrypt_file(encrypted_content, file_key)
                            if decrypted_content:
                                print(f"contents:\n {decrypted_content}")

                            else:
                                print(f"failed to decrypt shared file content for {file_id}")
                        else:
                            print(f"Failed to decrypt key for {file_id}")

                elif decrypted_msg.startswith("encrypt_keys "):
                    parts = decrypted_msg.split(maxsplit=2)
                    if len(parts) < 3:
                        return self.encrypt("ERROR: Invalid encrypt_keys format")
                    
                    file_id = parts[1]
                    keys_json = parts[2]
                    
                    try:
                        public_keys = json.loads(keys_json)
                        responses = []
                        
                        # Lê a chave do arquivo uma vez
                        key_path = f"VAULT_CLI{self.id}/{file_id}.key"
                        if not os.path.exists(key_path):
                            return self.encrypt(f"ERROR: Key file for {file_id} not found")
                        
                        with open(key_path, 'rb') as k:
                            file_key = k.read()
                        
                        # Processa cada chave pública
                        for target_user, public_key_pem in public_keys.items():
                            try:
                                # Encripta a chave com a chave pública de cada membro
                                encrypted = self.encrypt_key(file_key, public_key_pem)
                                encrypted_key = base64.b64encode(encrypted).decode()
                                
                                # Prepara a mensagem para cada usuário
                                response = f"key\n{target_user}\n{file_id}\n{encrypted_key}"
                                responses.append(response)
                                
                                print(f"Prepared key for file {file_id} to user {target_user}")
                                
                            except Exception as e:
                                print(f"Error encrypting for {target_user}: {e}")
                                responses.append(f"ERROR: Failed to encrypt for {target_user}: {str(e)}")
                        
                        
                        combined_response = "multiple_keys:" + "\n---\n".join(responses)
                        return self.encrypt(combined_response)
                        
                    except json.JSONDecodeError:
                        return self.encrypt("ERROR: Invalid JSON in encrypt_keys")
                    except Exception as e:
                        print(f"Error processing keys request: {e}")
                        return self.encrypt(f"ERROR: Failed to process keys request: {str(e)}")


                elif decrypted_msg.startswith("send file "):
                    file_id = decrypted_msg.split()[3]
                    file_path = decrypted_msg.split()[4]
                    flag = int(decrypted_msg.split()[2])

                    print("HELO")
                    
                    if flag == 0:
                        encrypted_file, command = self.encrypt_replaced_file(file_path, file_id)

                        print("antes de content")
                        content = base64.b64encode(encrypted_file).decode()

                        return self.encrypt(f"encrypted_file 1 {file_id} {content}")
                    elif flag == 1:
                        file_key = decrypted_msg.split()[5]

                        key_byts = base64.b64decode(file_key)

                        key = self.decrypt_key(key_byts)

                        encrypted_file, command = self.encrypt_file_with_key(file_path, key)
                        content = base64.b64encode(encrypted_file).decode()


                        return self.encrypt(f"encrypted_file 1 {file_id} {content}")

                elif decrypted_msg.startswith("group file "):
                    parts = decrypted_msg.split()
                    file_id = parts[2]
                    file_path = parts[3]
                    group_id = parts[4]
                    
                    group_encrypted_file, command = self.encrypt_file(file_path, file_id)
                    encrypted_file = base64.b64encode(group_encrypted_file).decode()

                    return self.encrypt(f"group encrypted file {file_id} {group_id} {encrypted_file}")

                   
            while True: 
                print('Input message to send (exit to finish)')
                new_msg = input()
                
                if not new_msg:
                    continue

                if new_msg.lower() == 'exit':
                    return None

                is_valid, validation_msg = Commands.validate(new_msg)
                if not is_valid:
                    print(f"Error: {validation_msg}")
                    continue

                if new_msg.lower().startswith('add '):
                    file_path = new_msg[4:].strip()
                    if not os.path.exists(file_path):
                        print(f"Error: File '{file_path}' does not exist")
                        continue
                    if not os.path.isfile(file_path):
                        print(f"Error: '{file_path}' is not a file")
                        continue


                encrypted_msg = self.encrypt(new_msg)
                #print(f'Sending encrypted message ({len(encrypted_msg)} bytes - {encrypted_msg})')

                return encrypted_msg if len(new_msg) > 0 else None
#
#
# Especificação das abstrações ao comportamento do cliente
#
#

def clientStart():
    """
        Start the event loop
        Returns:
            loop : asyncio.AbstractEventLoop
    """
    return asyncio.get_event_loop()
    

def clientRun(loop):
    """
        Start the behavior of the client
    """
    loop.run_until_complete(tcp_echo_client())
    

async def connectToServer(addr=conn_addr,port=conn_port):
    """
        Connect to the server and start the encryption handshake
    """
    client = Client()
    await client.connection.connect()
    msg = await client.process()
    return msg,client
    

async def normalCommunication(msg,client):
    """
        Run the main while loop to handle requests via client.process() method
    """    
    while msg:
        await client.connection.sendRaw(msg)
        msg = await client.connection.recvRaw()
        if msg :
            msg = await client.process(msg)
        else:
            break

async def endSession(client):
    """
        Send the last command to the server and close the socket
    """
    await client.connection.sendRaw(b'\n')
    print('Socket closed!')
    await client.connection.close()



# Next methods are meant to define the general behavior of the client,
# by which they will not probably need to be changed


async def tcp_echo_client():
    """
        General behavior of the client
    """
    msg,client = await connectToServer()
    await normalCommunication(msg,client)
    await endSession(client)


def run_client():
    """
        Initalize function of the client
    """

    loop = clientStart()
    clientRun(loop)

os.system('clear')

run_client()

