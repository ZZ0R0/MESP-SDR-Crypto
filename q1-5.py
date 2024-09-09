import os
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("Crypto App")

        # Generate RSA Keys
        self.label = Label(master, text="1. Generate RSA Keys")
        self.label.pack()
        
        self.generate_rsa_button = Button(master, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.generate_rsa_button.pack()

        # Generate AES Key
        self.label = Label(master, text="2. Generate AES Key")
        self.label.pack()
        
        self.generate_aes_button = Button(master, text="Generate AES Key", command=self.generate_aes_key)
        self.generate_aes_button.pack()

        # Encrypt AES Key
        self.label = Label(master, text="3. Encrypt AES Key")
        self.label.pack()
        
        self.encrypt_aes_button = Button(master, text="Encrypt AES Key", command=self.encrypt_aes_key)
        self.encrypt_aes_button.pack()

        # Decrypt AES Key
        self.label = Label(master, text="4. Decrypt AES Key")
        self.label.pack()
        
        self.decrypt_aes_button = Button(master, text="Decrypt AES Key", command=self.decrypt_aes_key)
        self.decrypt_aes_button.pack()

        # AES Encryption and Decryption
        self.label = Label(master, text="5. AES Encryption/Decryption")
        self.label.pack()

        self.message_entry = Entry(master)
        self.message_entry.pack()

        self.encrypt_message_button = Button(master, text="Encrypt Message", command=self.encrypt_message)
        self.encrypt_message_button.pack()
        
        self.decrypt_message_button = Button(master, text="Decrypt Message", command=self.decrypt_message)
        self.decrypt_message_button.pack()

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open("rsa.priv", "wb") as priv_file:
            priv_file.write(private_key)
        with open("rsa.pub", "wb") as pub_file:
            pub_file.write(public_key)
        
        messagebox.showinfo("Info", "RSA Keys generated and saved as rsa.priv and rsa.pub")

    def generate_aes_key(self):
        aes_key = os.urandom(32)
        with open("aes.key", "wb") as aes_file:
            aes_file.write(aes_key)
        
        messagebox.showinfo("Info", "AES Key generated and saved as aes.key")

    def encrypt_aes_key(self):
        pub_key_path = filedialog.askopenfilename(title="Select RSA Public Key File")
        if not pub_key_path:
            return
        
        with open("aes.key", "rb") as aes_file:
            aes_key = aes_file.read()
        
        with open(pub_key_path, "rb") as pub_file:
            public_key = RSA.import_key(pub_file.read())
        
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        with open("encrypted_aes.key", "wb") as enc_file:
            enc_file.write(encrypted_aes_key)
        
        messagebox.showinfo("Info", "AES Key encrypted and saved as encrypted_aes.key")

    def decrypt_aes_key(self):
        priv_key_path = filedialog.askopenfilename(title="Select RSA Private Key File")
        enc_key_path = filedialog.askopenfilename(title="Select Encrypted AES Key File")
        if not priv_key_path or not enc_key_path:
            return
        
        with open(priv_key_path, "rb") as priv_file:
            private_key = RSA.import_key(priv_file.read())
        
        with open(enc_key_path, "rb") as enc_file:
            encrypted_aes_key = enc_file.read()
        
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        dest_path = filedialog.asksaveasfilename(title="Save Decrypted AES Key As")
        if not dest_path:
            return
        
        with open(dest_path, "wb") as dec_file:
            dec_file.write(decrypted_aes_key)
        
        messagebox.showinfo("Info", "AES Key decrypted and saved")

    def encrypt_message(self):
        key_path = filedialog.askopenfilename(title="Select AES Key File")
        if not key_path:
            return
        
        with open(key_path, "rb") as key_file:
            aes_key = key_file.read()
        
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        plaintext = self.message_entry.get().encode()
        ciphertext = iv + cipher.encrypt(plaintext)
        
        enc_message_path = filedialog.asksaveasfilename(title="Save Encrypted Message As")
        if not enc_message_path:
            return
        
        with open(enc_message_path, "wb") as enc_file:
            enc_file.write(ciphertext)
        
        messagebox.showinfo("Info", "Message encrypted and saved")

    def decrypt_message(self):
        key_path = filedialog.askopenfilename(title="Select AES Key File")
        enc_message_path = filedialog.askopenfilename(title="Select Encrypted Message File")
        if not key_path or not enc_message_path:
            return
        
        with open(key_path, "rb") as key_file:
            aes_key = key_file.read()
        
        with open(enc_message_path, "rb") as enc_file:
            ciphertext = enc_file.read()
        
        iv = ciphertext[:16]
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext[16:]).decode()
        
        messagebox.showinfo("Info", f"Decrypted message: {plaintext}")

if __name__ == "__main__":
    root = Tk()
    app = CryptoApp(root)
    root.mainloop()
