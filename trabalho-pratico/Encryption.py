from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key,Encoding,PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os


class Encryption:
    def __init__(self,id):
        self.id = id
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.g = 2 
        self.parameters = dh.DHParameterNumbers(self.p,self.g).parameters()
        self.sk = self.parameters.generate_private_key()
        self.pk = self.sk.public_key()
        self.sharedKey = None

    def encrypt(self, msg: str) -> bytes:
        """Encrypt a message using AESGCM and include the key in the message"""
        if not msg:
            return b""
            
        aesgcm = AESGCM(self.sk)
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
            
            aesgcm = AESGCM(self.sk)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            txt = plaintext.decode()

            new_msg = txt.upper()

            return new_msg 

        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    def recv(self,msg):
        # Get the message and get client public
        client_public_key = load_pem_public_key(msg)
        # Compute shared key from public client key
        shared_key = self.sk.exchange(client_public_key)
        
        self.sharedKey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
        #print('Kmaster derived')

        return self.pk.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )


    def clientConfirmation(self):
        #print(f'Client confirmation : {msg}')
        return 'Welcome to SAH server'.encode()


    def process(self, msg,msg_cnt):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        #self.msg_cnt += 1

        if msg_cnt == 1:
            temp = self.recv(msg)
            return temp


        elif msg_cnt == 2:
            return self.clientConfirmation()


        else: 
        #
        # ALTERAR AQUI COMPORTAMENTO DO SERVIDOR
        #        
            txt = self.decrypt(msg)
            print('%s : %r' % (self.id,txt))
        
            return self.encrypt(txt) if len(txt)>0 else None
