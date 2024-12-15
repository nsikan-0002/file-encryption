#!/bin/python3

import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# Generate a Fernet key from a user-provided key
def generate_key(user_key):
    key = hashlib.sha256(user_key.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Encryption/Decryption Tool')
        self.configure(bg='#2c3e50')
        self.key = None
        self.cipher_suite = None

        # Initialize the GUI
        self.init_ui()

    def init_ui(self):
        # Create widgets
        self.key_entry = tk.Entry(self, width=50, bg='#ecf0f1', fg='#34495e')
        self.key_entry.insert(0, 'Enter encryption key...')

        self.text_input = tk.Text(self, height=10, width=50, bg='#ecf0f1', fg='#34495e')
        self.text_input.insert(tk.END, 'Enter text here...')

        self.encrypt_button = tk.Button(self, text='Encrypt Text', command=self.encrypt_text, bg='#3498db', fg='white')
        self.decrypt_button = tk.Button(self, text='Decrypt Text', command=self.decrypt_text, bg='#e74c3c', fg='white')
        self.encrypt_file_button = tk.Button(self, text='Encrypt File', command=self.encrypt_file, bg='#2ecc71', fg='white')
        self.decrypt_file_button = tk.Button(self, text='Decrypt File', command=self.decrypt_file, bg='#f39c12', fg='white')
        
        self.result_display = tk.Text(self, height=10, width=50, bg='#ecf0f1', fg='#34495e')
        self.result_display.insert(tk.END, 'Result will be displayed here...')
        self.result_display.config(state=tk.DISABLED)

        # Layout
        self.key_entry.pack(pady=5)
        self.text_input.pack(pady=10)
        self.encrypt_button.pack(pady=5)
        self.decrypt_button.pack(pady=5)
        self.result_display.pack(pady=10)
        self.encrypt_file_button.pack(pady=5)
        self.decrypt_file_button.pack(pady=5)

    def set_cipher_suite(self):
        user_key = self.key_entry.get()
        if user_key:
            key = generate_key(user_key)
            self.cipher_suite = Fernet(key)
        else:
            messagebox.showwarning("Input Error", "Please enter a valid encryption key.")
            self.cipher_suite = None

    def encrypt_text(self):
        self.set_cipher_suite()
        if self.cipher_suite:
            plain_text = self.text_input.get("1.0", tk.END).strip()
            if not plain_text:
                messagebox.showwarning("Input Error", "Please enter some text to encrypt.")
                return

            encrypted_text = self.cipher_suite.encrypt(plain_text.encode())
            self.result_display.config(state=tk.NORMAL)
            self.result_display.delete("1.0", tk.END)
            self.result_display.insert(tk.END, encrypted_text.decode())
            self.result_display.config(state=tk.DISABLED)

    def decrypt_text(self):
        self.set_cipher_suite()
        if self.cipher_suite:
            encrypted_text = self.text_input.get("1.0", tk.END).strip()
            if not encrypted_text:
                messagebox.showwarning("Input Error", "Please enter the encrypted text to decrypt.")
                return

            try:
                decrypted_text = self.cipher_suite.decrypt(encrypted_text.encode()).decode()
                self.result_display.config(state=tk.NORMAL)
                self.result_display.delete("1.0", tk.END)
                self.result_display.insert(tk.END, decrypted_text)
                self.result_display.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Failed to decrypt text: {str(e)}")

    def encrypt_file(self):
        self.set_cipher_suite()
        if self.cipher_suite:
            file_path = filedialog.askopenfilename()
            if not file_path:
                return

            try:
                with open(file_path, "rb") as file:
                    file_data = file.read()

                encrypted_data = self.cipher_suite.encrypt(file_data)
                encrypted_file_path = file_path + ".encrypted"

                with open(encrypted_file_path, "wb") as file:
                    file.write(encrypted_data)

                messagebox.showinfo("Success", f"File encrypted successfully and saved as {encrypted_file_path}")
            except Exception as e:
                messagebox.showerror("Encryption Error", f"Failed to encrypt file: {str(e)}")

    def decrypt_file(self):
        self.set_cipher_suite()
        if self.cipher_suite:
            file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
            if not file_path:
                return

            try:
                with open(file_path, "rb") as file:
                    encrypted_data = file.read()

                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                decrypted_file_path = file_path.replace(".encrypted", ".decrypted")

                with open(decrypted_file_path, "wb") as file:
                    file.write(decrypted_data)

                messagebox.showinfo("Success", f"File decrypted successfully and saved as {decrypted_file_path}")
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Failed to decrypt file: {str(e)}")

if __name__ == '__main__':
    app = CryptoApp()
    app.mainloop()
