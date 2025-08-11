import os, json, base64, sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QSpinBox, QFileDialog, QMessageBox,
    QStackedWidget
)
from stegano import lsb
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

# ---------------- Config Limits ----------------
MAX_SPLITS = 16         # maximum recipients allowed
MAX_TEXT_LEN = 1000     # maximum message length in characters

# ---------------- Utilities ----------------
def split_contiguous(s: str, n: int):
    """Split string s into n contiguous parts as evenly as possible.
       Earlier parts get +1 char when len(s) % n != 0.
       Example: s='abcdefgh', n=2 -> ['abcd','efgh']"""
    L = len(s)
    if n <= 0:
        return []
    if n > L:
        # If n > L, produce exactly L non-empty parts (each 1 char)
        n = L
    base = L // n
    extra = L % n
    parts = []
    start = 0
    for i in range(n):
        size = base + (1 if i < extra else 0)
        parts.append(s[start:start+size])
        start += size
    return parts

# ---------------- Crypto helpers ----------------
def generate_rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub

def save_private_key_txt(private_key, path_txt):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Save as .txt (per requirement), contents are standard PEM
    with open(path_txt, "wb") as f:
        f.write(pem)

def load_private_key_from_txt(path_txt):
    with open(path_txt, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)

def rsa_oaep_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        asympad.OAEP(
            mgf=asympad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_oaep_decrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        asympad.OAEP(
            mgf=asympad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_gcm_encrypt(plaintext: bytes):
    key = urandom(32)      # 256-bit key
    nonce = urandom(12)    # 96-bit nonce
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return key, nonce, ct, encryptor.tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ---------------- Stego helpers ----------------
def embed_json_in_image(cover_image_path: str, output_image_path: str, obj: dict):
    payload = json.dumps(obj, separators=(",", ":"))
    secret = lsb.hide(cover_image_path, payload)
    secret.save(output_image_path)

def extract_json_from_image(image_path: str) -> dict:
    s = lsb.reveal(image_path)
    if s is None:
        raise ValueError("No hidden payload found in image.")
    return json.loads(s)

# ---------------- GUI Pages ----------------
class ModeSelectPage(QWidget):
    def __init__(self, on_encrypt, on_decrypt):
        super().__init__()
        layout = QVBoxLayout()
        title = QLabel("InvisiKey — Choose Mode")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        layout.addWidget(title)

        btn_row = QHBoxLayout()
        enc_btn = QPushButton("Encrypt")
        dec_btn = QPushButton("Decrypt")
        enc_btn.setMinimumHeight(40)
        dec_btn.setMinimumHeight(40)
        enc_btn.clicked.connect(on_encrypt)
        dec_btn.clicked.connect(on_decrypt)
        btn_row.addWidget(enc_btn)
        btn_row.addWidget(dec_btn)

        layout.addLayout(btn_row)
        layout.addStretch(1)
        self.setLayout(layout)

class EncryptPage(QWidget):
    def __init__(self):
        super().__init__()
        self.image_paths = []  # multiple cover images

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Sender — Encrypt & Embed (one chunk per image)"))

        self.msg = QTextEdit()
        self.msg.setPlaceholderText(f"Enter the secret message… (max {MAX_TEXT_LEN} chars)")
        layout.addWidget(self.msg)

        row = QHBoxLayout()
        row.addWidget(QLabel(f"Recipients / Splits (n, max {MAX_SPLITS}):"))
        self.nspin = QSpinBox()
        self.nspin.setMinimum(1)
        self.nspin.setMaximum(MAX_SPLITS)
        row.addWidget(self.nspin)
        row.addStretch(1)
        layout.addLayout(row)

        self.pick_btn = QPushButton("Select n Cover Images (PNG/BMP)")
        self.pick_btn.clicked.connect(self.select_images)
        layout.addWidget(self.pick_btn)

        self.img_label = QLabel("No images selected")
        layout.addWidget(self.img_label)

        self.go_btn = QPushButton("Generate Private Keys (TXT), Encrypt & Embed (one image per chunk)")
        self.go_btn.clicked.connect(self.do_encrypt_embed)
        layout.addWidget(self.go_btn)

        layout.addStretch(1)
        self.setLayout(layout)

    def select_images(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Cover Images", "", "Images (*.png *.bmp)")
        if paths:
            self.image_paths = paths
            self.img_label.setText(f"Selected {len(paths)} images")

    def do_encrypt_embed(self):
        try:
            message = self.msg.toPlainText()
            if not message:
                QMessageBox.warning(self, "Missing", "Enter a secret message.")
                return

            if len(message) > MAX_TEXT_LEN:
                QMessageBox.warning(
                    self, "Too Long",
                    f"Message exceeds max length of {MAX_TEXT_LEN} characters."
                )
                return

            n = self.nspin.value()
            if n < 1 or n > MAX_SPLITS:
                QMessageBox.warning(
                    self, "Invalid Splits",
                    f"Number of recipients must be between 1 and {MAX_SPLITS}."
                )
                return

            if len(self.image_paths) != n:
                QMessageBox.warning(
                    self, "Image Count Mismatch",
                    f"You selected {len(self.image_paths)} images, but splits = {n}.\n"
                    f"Select exactly one cover image per chunk."
                )
                return

            if n > len(message):
                QMessageBox.warning(
                    self, "Invalid Splits",
                    "Recipients (n) cannot exceed message length for contiguous split."
                )
                return

            # Contiguous split into n parts
            chunks = split_contiguous(message, n)

            os.makedirs("keys", exist_ok=True)
            os.makedirs("outputs", exist_ok=True)

            for i, (chunk, cover_path) in enumerate(zip(chunks, self.image_paths)):
                user = f"user{i+1}"
                priv, pub = generate_rsa_keypair()

                # Save ONLY private key as .txt (PEM text)
                priv_path = os.path.join("keys", f"{user}_private_key.txt")
                save_private_key_txt(priv, priv_path)

                # Hybrid encrypt this chunk
                key, nonce, ct, tag = aes_gcm_encrypt(chunk.encode("utf-8"))
                ekey = rsa_oaep_encrypt(pub, key)

                # Single-chunk payload for this image
                payload = {
                    "chunk": {
                        "user": user,
                        "ekey": base64.b64encode(ekey).decode(),
                        "nonce": base64.b64encode(nonce).decode(),
                        "ct": base64.b64encode(ct).decode(),
                        "tag": base64.b64encode(tag).decode(),
                    }
                }

                # Output file: outputs/output_chunk_{i+1}.png
                out_name = f"output_chunk_{i+1}.png"
                out_path = os.path.join("outputs", out_name)
                embed_json_in_image(cover_path, out_path, payload)

            QMessageBox.information(
                self, "Success",
                f"Embedded {n} chunks into {n} images under ./outputs.\n"
                f"Saved {n} private keys in ./keys as .txt files."
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption/embedding failed:\n{e}")

class DecryptPage(QWidget):
    def __init__(self):
        super().__init__()
        self.image_path = None
        self.private_key = None

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Receiver — Extract & Decrypt (one image holds one chunk)"))

        self.pick_img_btn = QPushButton("Upload Stego Image (PNG/BMP)")
        self.pick_img_btn.clicked.connect(self.select_image)
        layout.addWidget(self.pick_img_btn)

        self.img_label = QLabel("No image uploaded")
        layout.addWidget(self.img_label)

        self.pick_key_btn = QPushButton("Upload Your Private Key (.txt)")
        self.pick_key_btn.clicked.connect(self.select_key)
        layout.addWidget(self.pick_key_btn)

        self.key_label = QLabel("No key uploaded")
        layout.addWidget(self.key_label)

        self.go_btn = QPushButton("Extract & Decrypt")
        self.go_btn.clicked.connect(self.do_extract_decrypt)
        layout.addWidget(self.go_btn)

        layout.addStretch(1)
        self.setLayout(layout)

    def select_image(self):
        p, _ = QFileDialog.getOpenFileName(self, "Upload Stego Image", "", "Images (*.png *.bmp)")
        if p:
            self.image_path = p
            self.img_label.setText(f"Uploaded: {os.path.basename(p)}")

    def select_key(self):
        p, _ = QFileDialog.getOpenFileName(self, "Upload Private Key", "", "Key Files (*.txt)")
        if p:
            try:
                self.private_key = load_private_key_from_txt(p)
                self.key_label.setText(f"Key: {os.path.basename(p)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load key:\n{e}")

    def do_extract_decrypt(self):
        try:
            if not self.image_path:
                QMessageBox.warning(self, "Missing", "Upload a stego image first.")
                return
            if not self.private_key:
                QMessageBox.warning(self, "Missing", "Upload your private key (.txt).")
                return

            payload = extract_json_from_image(self.image_path)

            # Expect exactly one chunk in this image
            entry = payload.get("chunk")
            if not entry:
                QMessageBox.warning(self, "Invalid Payload", "No single chunk found in this image.")
                return

            ekey  = base64.b64decode(entry["ekey"])
            nonce = base64.b64decode(entry["nonce"])
            ct    = base64.b64decode(entry["ct"])
            tag   = base64.b64decode(entry["tag"])

            try:
                key = rsa_oaep_decrypt(self.private_key, ekey)
            except Exception:
                QMessageBox.warning(self, "Key Mismatch", "This private key doesn't match the image payload.")
                return

            pt  = aes_gcm_decrypt(key, nonce, ct, tag)
            msg = pt.decode("utf-8")
            user_label = entry.get("user", "unknown")
            QMessageBox.information(
                self, "Decrypted",
                f"Matched: {user_label}\n\nYour message chunk:\n{msg}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Extraction/decryption failed:\n{e}")

# ---------------- Main Window ----------------
class InvisiKeyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("InvisiKey — Secure Multi-Key Steganography")
        self.setGeometry(200, 200, 760, 560)

        self.stack = QStackedWidget()
        self.mode_page = ModeSelectPage(self.goto_encrypt, self.goto_decrypt)
        self.encrypt_page = EncryptPage()
        self.decrypt_page = DecryptPage()

        self.stack.addWidget(self.mode_page)    # index 0
        self.stack.addWidget(self.encrypt_page) # index 1
        self.stack.addWidget(self.decrypt_page) # index 2

        self.setCentralWidget(self.stack)

    def goto_encrypt(self):
        self.stack.setCurrentIndex(1)

    def goto_decrypt(self):
        self.stack.setCurrentIndex(2)

# ---------------- Run ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = InvisiKeyApp()
    win.show()
    sys.exit(app.exec_())
