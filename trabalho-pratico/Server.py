# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import os
import json
import base64
from utils import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from connections.Connection import Connection
from acManager.ACmanager import ACmanager 
from typing import Set 
from jsonencrypt import SecureAESGCMJsonCrypto


conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2 
files_are_decrypted = False
PARAMETERS = dh.DHParameterNumbers(p, g).parameters() 
active_users = {}
json_files = [
        'acManager/baseStructure.json',
        'acManager/defaultPermissions.json',
        'acManager/groups.json',
        'acManager/sharedFiles.json',
        'acManager/users.json'
    ]

# Function to decrypt all JSON files (called once at server startup)
class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None,reader=None,writer=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.connection : Connection = Connection(self.addr,conn_port,self.id,reader,writer)

        if not os.path.exists("shared_keys"):
            os.makedirs("shared_keys")
        
        self.client_public_key = None
        self.server_public_key = None
        self.expecting_file = False

        priv_key_path = "projCA/VAULT_SERVER.key" 
        self.json_encrypt = SecureAESGCMJsonCrypto(priv_key_path=priv_key_path)

        global files_are_decrypted
        if not files_are_decrypted:
            for file in json_files:
                if os.path.exists(file):
                    self.json_encrypt.decrypt_json(file)
                    files_are_decrypted = True

    def parseFirstHandshakeMessage(self,msg):
            offset = 0

            pkc_len = int.from_bytes(msg[offset:offset + 2])
            offset += 2
            pkc = msg[offset:offset + pkc_len]
            offset += pkc_len

            id_len = int.from_bytes(msg[offset:offset + 2])
            offset += 2
            self.id = msg[offset:offset + id_len].decode()

            return pkc

    def encrypt(self, msg: str) -> bytes:
        """Encrypt a message using AESGCM and include the key in the message"""
        if not msg:
            return b""
            
        aesgcm = AESGCM(self.shared_key)
        nonce = os.urandom(12)
        
        # No associated data
        ciphertext = aesgcm.encrypt(nonce, msg.encode(), None)
        
        # Format: nonce (12 bytes) + ciphertext
        return nonce + ciphertext


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
    
    async def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        global file_counter

        self.msg_cnt += 1
        

        if self.msg_cnt == 1:

            pkc = self.parseFirstHandshakeMessage(msg)

            self.client_public_key = serialization.load_pem_public_key(pkc)
            client_public_bytes = pkc

            self.server_private_key = PARAMETERS.generate_private_key()
            self.server_public_key = self.server_private_key.public_key()
            
            shared_key = self.server_private_key.exchange(self.client_public_key)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

            
            gy_bytes = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
            concatenated_bytes = mkpair(gy_bytes, client_public_bytes)
        
            with open("projCA/VAULT_SERVER.key", "rb") as f:
                server_private_key_bytes = f.read() 
            
            server_private_key = load_pem_private_key(server_private_key_bytes, password=None)
        
            signature = server_private_key.sign(
                concatenated_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )

            # É preciso encriptar a assinatura com AESGCM
            # para que o cliente possa verificar a assinatura
            # com a chave partilhada. O servidor nesta fase inicial do handshake
            # ainda não tem a chave publica rsa do cliente.
            
            aesgcm = AESGCM(self.shared_key)
            nonce = os.urandom(12)
            encrypted_signature = aesgcm.encrypt(nonce, signature, None)

            server_cert = cert_load("projCA/VAULT_SERVER.crt")
            cert_bytes = server_cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            )
        
            response = mkpair(gy_bytes, mkpair(nonce, mkpair(encrypted_signature, cert_bytes)))
            return response
        
        elif self.msg_cnt == 2:
            #print(msg)
            gx_bytes, remaining = unpair(msg)
            nonce, remaining = unpair(remaining)
            encrypted_signature, cert_bytes = unpair(remaining)
            
            aesgcm = AESGCM(self.shared_key)
            try:
                signature = aesgcm.decrypt(nonce, encrypted_signature, None)
                print("Servidor - Assinatura descriptografada com sucesso!")
            except Exception as e:
                print("Servidor - Erro ao descriptografar a assinatura")
                print(e)
                return None
            
            client_cert = x509.load_pem_x509_certificate(cert_bytes)

            user_id = None 
            for attr in client_cert.subject:
                if attr.oid._name == 'pseudonym':
                    user_id = attr.value
                    break 
            active_users[user_id] = self
            self.user_id = user_id
            self.manager = ACmanager(user_id)

            print(f"Client pseudonym: {user_id}")


            ca_cert = cert_load("projCA/VAULT_CA.crt")

            # Valida o certificado do cliente
            if not valida_certCli(client_cert, ca_cert, self.id):
                print("Servidor - Validação do certificado do cliente falhou!")
                return None
            print("Servidor - Certificado do cliente validado com sucesso.")
            client_public_key = client_cert.public_key()

            concatenated_bytes = mkpair(
                gx_bytes,
                self.server_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            try:
                client_public_key.verify(
                    signature,
                    concatenated_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256()
                )
                print("Servidor - Assinatura do cliente verificada com sucesso!")
            except Exception as e:
                print("Servidor - Erro ao verificar a assinatura do cliente")
                print(e)
                return None

            return b"OK"

        elif self.msg_cnt == 3:
            try:
                decrypted_pem = self.decrypt(msg)
                self.client_rsa_public_key = serialization.load_pem_public_key(decrypted_pem.encode())
      
                pub_keys_dir = "pub_keys"
                os.makedirs(pub_keys_dir, mode=0o700, exist_ok=True)
                
                key_path = f"{pub_keys_dir}/{self.user_id}.key"
                with open(key_path, 'wb') as f:
                    f.write(
                        self.client_rsa_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    )
                os.chmod(key_path, 0o400)  # Somente leitura
                
                return self.encrypt("rsa_key received and stored securely")
                
            except Exception as e:
                print(f"Erro ao processar chave pública: {str(e)}")
                return self.encrypt(f"ERROR: {str(e)}")       



        else:
            txt = self.decrypt(msg)
            
            if txt:
                print('%s : %r' % (self.id, txt))

                file_id = "start"
                if txt.startswith("add "):
                    self.expecting_file = True
                    file_path = txt.split()[1]
                    file_id = self.manager.get_file_id()

                    return self.encrypt(f"file {file_path} {file_id}")

                elif txt.startswith("encrypted_file "):
                    flag = int(txt.split()[1])
                    file_id = txt.split()[2]
                    content = " ".join(txt.split()[3:])
                    if flag == 0:
                        self.manager.add_file(content, file_id)
                        self.expecting_file = False 
                    elif flag == 1:
                        self.manager.replace_content(file_id,content)

                elif txt.startswith("share "):
                    target_user = txt.split()[2]
                    file_id = txt.split()[1]
                    permission = txt.split()[3]
                    if permission == "r":
                        permissions = {
                            "read": True,
                            "write": False
                        }
                    elif permission == "w":
                        permissions = {
                            "read": True, 
                            "write": True
                    }

                    with open(f"pub_keys/{target_user}.key", 'rb') as f:
                        public_key = serialization.load_pem_public_key(
                            f.read(),
                            backend=default_backend()
                        )
                        rsa_public_key_pem = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                ).decode()

                    self.manager.share_file(file_id, target_user, permissions)

                    return self.encrypt(f"public_key\n{file_id}\n{target_user}\n{rsa_public_key_pem}")

                elif txt.startswith("key"):
                    parts = txt.split('\n')
                    target_user = parts[1]
                    file_id = parts[2]
                    encrypted_key = '\n'.join(parts[3:])

                    if not os.path.exists(f"shared_keys/{target_user}"):
                        os.makedirs(f"shared_keys/{target_user}")
                    
                    with open(f"shared_keys/{target_user}/{file_id}.key", 'w') as sk:
                        sk.write(encrypted_key)

                    print(f"Chave encriptada armazenada para file_id: {file_id}")
                    return self.encrypt(f"KEY STORED: Chave para file_id {file_id} armazenada com sucesso")


                elif txt.startswith("multiple_keys:"):
                    # Remove o prefixo e divide as respostas individuais
                    responses = txt[len("multiple_keys:"):].split("\n---\n")
                    results = []
                    
                    for response in responses:
                        if response.startswith("key\n"):
                            # Processa cada resposta de chave individual
                            parts = response.split('\n')
                            if len(parts) < 4:
                                results.append(f"ERROR: Invalid key format in response: {response}")
                                continue
                                
                            target_user = parts[1]
                            file_id = parts[2]
                            encrypted_key = '\n'.join(parts[3:])
                            
                            try:
                                # Cria diretório se não existir
                                os.makedirs(f"shared_keys/{target_user}", exist_ok=True)
                                
                                # Armazena a chave encriptada
                                with open(f"shared_keys/{target_user}/{file_id}.key", 'w') as sk:
                                    sk.write(encrypted_key)
                                
                                results.append(f"KEY STORED: Chave para {file_id} armazenada para {target_user}")
                                print(f"Chave encriptada armazenada para {target_user} (file_id: {file_id})")
                                
                            except Exception as e:
                                error_msg = f"ERROR: Failed to store key for {target_user} ({file_id}): {str(e)}"
                                results.append(error_msg)
                                print(error_msg)
                        
                        elif response.startswith("ERROR:"):
                            results.append(response)
                            print(f"Error in response: {response}")
                    
                    # Retorna um resumo de todas as operações
                    summary = "\n".join(results)
                    return self.encrypt(f"MULTI_KEY_RESULT:\n{summary}")


                elif txt.startswith("read"):
                    file_id = txt.split()[1]
                    print(file_id)
                    content, flag, owner = self.manager.readFile(file_id)
                    print(content)
                    print(flag)

                    if flag == 0:
                        return self.encrypt(f"content\n{file_id}\n{flag}\n{content}")
                    elif flag == 1:
                        with open(f"shared_keys/VAULT_CLI{self.id}/{file_id}.key", 'r') as sk:
                            encrypted_key = sk.read()
                        return self.encrypt(f"content\n{file_id}\n{flag}\n{encrypted_key}\n{content}")
                    elif flag == 2:
                        print(owner)
                        if f"VAULT_CLI{self.id}" == owner:
                            return self.encrypt(f"content\n{file_id}\n0\n{content}")
                        else: 
                            key_path = f"shared_keys/VAULT_CLI{self.id}/{file_id}.key"
                            if os.path.exists(key_path):
                                with open(key_path, 'r') as sk:
                                    encrypted_key = sk.read()
                                return self.encrypt(f"content\n{file_id}\n{1}\n{encrypted_key}\n{content}")

                elif txt.startswith("list "): 
                    parts = txt.split()
                    if len(parts) == 1:
                        # List all files accessible to the active user
                        files = self.manager.list_files()
                    elif len(parts) == 3 and parts[1] == "-u":
                        # List files for a specific user
                        user_id = parts[2]
                        files = self.manager.list_files(option="-u", identifier=user_id)
                    elif len(parts) == 3 and parts[1] == "-g":
                        # List files for a specific group
                        group_id = parts[2]
                        files = self.manager.list_files(option="-g", identifier=group_id)
                    else:
                        return self.encrypt("ERROR: Invalid format for 'list' command")

                    # Format the response
                    response = "Files:\n"
                    if "personal" in files and files["personal"]:
                        response += "Personal Files:\n" + "\n".join(files["personal"]) + "\n"
                    if "shared" in files and files["shared"]:
                        response += "Shared Files:\n" + "\n".join(files["shared"]) + "\n"
                    if "groups" in files and files["groups"]:
                        response += "Group Files:\n"
                        for group_id, group_files in files["groups"].items():
                            response += f"Group {group_id}:\n" + "\n".join(group_files) + "\n"

                    return self.encrypt(response)

                elif txt.startswith("share "):
                    target_user = txt.split()[2]
                    file_id = txt.split()[1]
                    permission = txt.split()[3]
                    if permission == "r":
                        permissions = {
                            "read": True,
                            "write": False
                        }
                    elif permission == "w":
                        permissions = {
                            "read": True, 
                            "write": True
                        }
                    if target_user in active_users:
                        target_worker = active_users[target_user]
                        rsa_public_key_pem = target_worker.client_rsa_public_key.public_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                        self.manager.share_file(file_id, target_user, permissions)

                        return self.encrypt(f"public_key\n{file_id}\n{rsa_public_key_pem.decode()}")
                    else:
                        return self.encrypt("ERROR: User not connected")
                   
                elif txt.startswith("revoke"):
                    parts = txt.split()
                    file_id = parts[1]
                    user_id = parts[2]
                    
                    success = self.manager.revoke(file_id, user_id)
                    if success:
                        return self.encrypt(f"File {file_id} revoked from {user_id}")
                    else:
                        return self.encrypt(f"ERROR: Failed to revoke file {file_id} from {user_id}")

                elif txt.startswith("group create"):
                    group_name = txt.split()[2]
                    group_id = self.manager.createGroup(group_name)
                    return self.encrypt(f"grupo criado como {group_id}")
                
                elif txt.startswith("group delete-user"):
                    parts = txt.split()
                    group_id = parts[2]
                    user_id = parts[3]
                    
                    success = self.manager.groupDeleteUser(group_id, user_id)
                    if success:
                        return self.encrypt(f"User {user_id} removed from group {group_id}")
                    else:
                        return self.encrypt(f"ERROR: Failed to remove user {user_id} from group {group_id}")
                
                elif txt.startswith("group delete"):
                    group_id = txt.split()[2]
                    self.manager.deleteGroup(group_id)
                    return self.encrypt(f"grupo {group_id} apagado")
                
                elif txt.startswith("group list"):
                    groups_info = self.manager.groupList()
                    response = "Grupos:\n"
                    for group in groups_info:
                        response += f"ID: {group['id']}, Name: {group['name']}, Owner: {group['owner']}, "
                        response += f"Is Owner: {group['is_owner']}, Members: {group['member_count']}, Files: {group['file_count']}, "
                        response += f"Permissions: {group['permissions']}\n"
                    return self.encrypt(response)
                
                elif txt.startswith("group add-user"):
                    parts = txt.split()
                    
                    group_id = parts[2]
                    user_id = parts[3]
                    permission = parts[4]
                    
                    if permission == "R":
                        permissions = {
                            "read": True,
                            "write": False
                        }
                    elif permission == "W":
                        permissions = {
                            "read": True, 
                            "write": True
                        }
                    else:
                        return self.encrypt("ERROR: Invalid permission")
                    
                    success = self.manager.groupAddUser(group_id, user_id, permissions)
                    if success:
                        return self.encrypt(f"User {user_id} added to group {group_id} with permissions {permissions}")
                    else:
                        return self.encrypt(f"ERROR: Failed to add user {user_id} to group {group_id}")
                    
                elif txt.startswith("group add"):
                    parts = txt.split()
                    
                    group_id = parts[2]
                    file_path = parts[3]
                    
                    file_id = self.manager.get_group_file_id(group_id)
                    if file_id:
                        return self.encrypt(f"group file {file_id} {file_path} {group_id}")
                    else:
                        return self.encrypt(f"ERROR: Failed to add file to group {group_id}")

                elif txt.startswith("group encrypted file "):
                    file_id = txt.split()[3]
                    group_id = txt.split()[4]
                    encrypted_file = " ".join(txt.split()[5:])

                    self.manager.groupAddFile(file_id, group_id, encrypted_file)

                    answer = self.manager.get_group_members(group_id)
                    encrypted_keys = {}


                    for member in answer:
                        with open(f"pub_keys/{member}.key", 'rb') as f:
                            public_key = serialization.load_pem_public_key(
                                f.read(),
                                backend=default_backend()
                            )
                            rsa_public_key_pem = public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    ).decode()
                        encrypted_keys[member] = rsa_public_key_pem

                    return self.encrypt(f"encrypt_keys {file_id} {json.dumps(encrypted_keys)}")

                elif txt.startswith("details"):
                    file_id = txt.split()[1]
                    details = self.manager.file_details(file_id)
                    return self.encrypt(f"details\n{file_id}\n{details}")
                
                elif txt.startswith("delete"):
                    file_id = txt.split()[1]
                    self.manager.deleteFile(file_id)
                    
                elif txt.startswith("replace"):
                    parts = txt.split()
                    file_id = parts[1]
                    file_path = parts[2]

                    content, flag, owner = self.manager.readFile(file_id)
                    if flag == 0:
                        return self.encrypt(f"send file 0 {file_id} {file_path}")
                    elif flag == 1:
                        with open(f"shared_keys/{file_id}.key", 'r') as f:
                            file_key = f.read()

                        return self.encrypt(f"send file 1 {file_id} {file_path} {file_key}")
                    elif flag == 2:
                        if owner == self.user_id:
                            return self.encrypt(f"send file 0 {file_id} {file_path}")
                        else: 
                            with open(f"shared_keys/{file_id}.key", 'r') as f:
                                file_key = f.read()
                            return self.encrypt(f"send file 1 {file_id} {file_path} {file_key}")
                elif txt.startswith("exitSHUTDOWN"):
                    print("Received shutdown command. Encrypting files and shutting down...")
                    
                    # Encriptar todos os arquivos JSON
                    for file in json_files:
                        if os.path.exists(file):
                            self.json_encrypt.encrypt_json(file)
                            print(f"Encrypted {file}")
                    
                    shutdown_response = self.encrypt("Server shutdown initiated. All files encrypted.")
                    
                    # Agendar o encerramento do servidor após um breve atraso
                    asyncio.create_task(self.connection.shutdown_server())
                    
                    return shutdown_response
                                                

                                         
            return self.encrypt(txt) if len(txt)>0 else None 


def startServer():
    """
        Start the server hosting on 127.0.0.1:7777
    """
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    return loop,server


def requestsLoop(loop,server):
    """
        Serve requests until Ctrl+C is pressed
    """
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

def closeServer(loop,server):

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')


def newConn(reader,writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr,reader,writer)
    return srvwrk

async def mainLoop(srvwrk):
    data = await srvwrk.connection.recvRaw()
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = await srvwrk.process(data)
        if not data: break
        #writer.write(data)
        await srvwrk.connection.sendRaw(data)
        #await writer.drain()
        #data = await reader.read(max_msg_size)
        data = await srvwrk.connection.recvRaw()


async def handle_echo(reader, writer):
    #data = await reader.read(max_msg_size)
    srvwrk = newConn(reader,writer)
    await mainLoop(srvwrk)
    print(f'{srvwrk.id}')
    #writer.close()
    await srvwrk.connection.close()
    if hasattr(srvwrk, "user_id"):
        active_users.pop(srvwrk.user_id, None)

def run_server():
    loop,server = startServer()
    # Serve requests until Ctrl+C is pressed
    requestsLoop(loop,server)
    # Close the server
    closeServer(loop,server)

os.system('clear')

run_server()
