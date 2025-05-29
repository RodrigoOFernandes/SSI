import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import rsa

class SecureAESGCMJsonCrypto:
    def __init__(self, key_file='jsonkey.key', cert_path="projCA/VAULT_SERVER.crt", priv_key_path=None):
        self.key_file = key_file
        self.cert_path = cert_path
        self.priv_key_path = priv_key_path
        self.backend = default_backend()
        
        # Carrega a chave RSA pública do certificado
        self.rsa_public_key = self._load_rsa_public_key()
        # Carrega a chave privada se existir (para descriptografia)
        self.rsa_private_key = self._load_rsa_private_key() if priv_key_path else None

    def _load_rsa_public_key(self):
        """Carrega a chave RSA pública do certificado X.509."""
        with open(self.cert_path, "rb") as cert_file:
            cert = load_pem_x509_certificate(cert_file.read(), self.backend)
            return cert.public_key()

    def _load_rsa_private_key(self):
        """Carrega a chave RSA privada do servidor."""
        with open(self.priv_key_path, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=self.backend
            )

    def _encrypt_aes_key(self, aes_key):
        """Encripta a chave AES com RSA-OAEP."""
        return self.rsa_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def _decrypt_aes_key(self, encrypted_key):
        """Descriptografa a chave AES com RSA usando a chave privada."""
        if not self.rsa_private_key:
            raise ValueError("Chave privada não disponível para descriptografia")
            
        return self.rsa_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def _generate_or_load_key(self):
        """Gera ou carrega a chave AES, encriptando-a com RSA se for nova."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                encrypted_key = f.read()
                # Descriptografa a chave apenas em memória
                return self._decrypt_aes_key(encrypted_key)
        else:
            aes_key = os.urandom(32)  # AES-256
            encrypted_key = self._encrypt_aes_key(aes_key)
            with open(self.key_file, "wb") as f:
                f.write(encrypted_key)
            return aes_key

    def encrypt_json(self, json_file):
        """Criptografa um JSON no local com AES-GCM."""
        iv = os.urandom(12)
        aes_key = self._generate_or_load_key()

        with open(json_file, "rb") as f:
            plaintext = f.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(json_file, "wb") as f:
            f.write(iv + encryptor.tag + ciphertext)

    def decrypt_json(self, json_file):
        """Descriptografa um JSON no local com AES-GCM."""
        aes_key = self._generate_or_load_key()

        with open(json_file, "rb") as f:
            data = f.read()
            iv, tag, ciphertext = data[:12], data[12:28], data[28:]

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(json_file, "wb") as f:
            f.write(plaintext)

def main():
    json_files = [
        'acManager/baseStructure.json',
        'acManager/defaultPermissions.json',
        'acManager/groups.json',
        'acManager/sharedFiles.json',
        'acManager/users.json'
    ]

    # Adiciona o caminho para a chave privada apenas para descriptografia
    priv_key_path = "projCA/VAULT_SERVER.key" if input("Usar chave privada para descriptografia? [y/n]: ").strip().lower() == 'y' else None
    
    crypto = SecureAESGCMJsonCrypto(priv_key_path=priv_key_path)

    action = input("Operação [e]ncrypt/[d]ecrypt: ").strip().lower()
    try:
        if action == 'e':
            print("Encriptando arquivos...")
            for file in json_files:
                if os.path.exists(file):
                    crypto.encrypt_json(file)
                    print(f"✓ {file} encriptado")
        elif action == 'd':
            print("Descriptando arquivos...")
            for file in json_files:
                if os.path.exists(file):
                    crypto.decrypt_json(file)
                    print(f"✓ {file} descriptado")
        else:
            print("Opção inválida")
    except Exception as e:
        print(f"Erro: {str(e)}")
        print("Certifique-se que:")
        print("- O certificado VAULT_SERVER.crt está no caminho correto")
        print("- A chave privada está disponível para descriptografia (se necessário)")
        print("- Os arquivos não estão corrompidos")

if __name__ == "__main__":
    main()
