import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout,
    QLineEdit, QFileDialog, QWidget, QSpinBox, QTextEdit, QMessageBox
)
from stegano import lsb
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PrivateFormat, NoEncryption, PublicFormat
)
from cryptography.hazmat.primitives import padding

# Function to generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Function to save RSA keys
def save_rsa_keys(private_key, public_key, user_id):
    os.makedirs("keys", exist_ok=True)
    private_key_path = f"keys/{user_id}_private_key.pem"
    public_key_path = f"keys/{user_id}_public_key.pem"

    with open(private_key_path, "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key_path, public_key_path

# Function to encrypt data using public key
def encrypt_data(public_key, data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    encrypted_data = public_key.encrypt(
        padded_data,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_data

# Function to decrypt data using private key
def decrypt_data(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(
        encrypted_data,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return unpadded_data.decode()

# Embed data into image
def embed_data_in_image(image_path, output_path, data):
    secret_image = lsb.hide(image_path, data.decode('latin1'))
    secret_image.save(output_path)

# Extract data from image
def extract_data_from_image(image_path):
    return lsb.reveal(image_path).encode('latin1')

# GUI Application
class SteganographyApp(QMainWindow):
    def _init_(self):
        super()._init_()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Multi-Key Steganography App")
        self.setGeometry(200, 200, 600, 400)

        # Layout
        layout = QVBoxLayout()

        # Sender Section
        self.sender_label = QLabel("Sender Section")
        layout.addWidget(self.sender_label)

        self.data_input = QTextEdit()
        self.data_input.setPlaceholderText("Enter the secret message here...")
        layout.addWidget(self.data_input)

        self.num_users_label = QLabel("Number of Users:")
        layout.addWidget(self.num_users_label)

        self.num_users_input = QSpinBox()
        self.num_users_input.setMinimum(1)
        layout.addWidget(self.num_users_input)

        self.image_path_btn = QPushButton("Select Image to Embed Data")
        self.image_path_btn.clicked.connect(self.select_image_path)
        layout.addWidget(self.image_path_btn)

        self.image_path_label = QLabel("No image selected")
        layout.addWidget(self.image_path_label)

        self.generate_keys_btn = QPushButton("Generate Keys and Embed Data")
        self.generate_keys_btn.clicked.connect(self.generate_keys_and_embed)
        layout.addWidget(self.generate_keys_btn)

        # Receiver Section
        self.receiver_label = QLabel("\nReceiver Section")
        layout.addWidget(self.receiver_label)

        self.upload_image_btn = QPushButton("Upload Image with Embedded Data")
        self.upload_image_btn.clicked.connect(self.upload_image)
        layout.addWidget(self.upload_image_btn)

        self.image_uploaded_label = QLabel("No image uploaded")
        layout.addWidget(self.image_uploaded_label)

        self.upload_key_btn = QPushButton("Upload Private Key")
        self.upload_key_btn.clicked.connect(self.upload_private_key)
        layout.addWidget(self.upload_key_btn)

        self.key_uploaded_label = QLabel("No key uploaded")
        layout.addWidget(self.key_uploaded_label)

        self.extract_btn = QPushButton("Extract and Decrypt Data")
        self.extract_btn.clicked.connect(self.extract_and_decrypt)
        layout.addWidget(self.extract_btn)

        # Set central widget
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def select_image_path(self):
        image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.png *.jpg *.bmp)")
        if image_path:
            self.image_path = image_path
            self.image_path_label.setText(f"Selected: {os.path.basename(image_path)}")

    def generate_keys_and_embed(self):
        try:
            data = self.data_input.toPlainText()
            num_users = self.num_users_input.value()
            chunks = [data[i::num_users] for i in range(num_users)]
            concatenated_data = ""

            self.encrypted_chunks = []
            self.user_ids = []

            for i, chunk in enumerate(chunks):
                user_id = f"user{i+1}"
                private_key, public_key = generate_rsa_key_pair()
                save_rsa_keys(private_key, public_key, user_id)

                encrypted_chunk = encrypt_data(public_key, chunk)
                self.encrypted_chunks.append(encrypted_chunk)
                self.user_ids.append(user_id)

                concatenated_data += encrypted_chunk.decode('latin1') + "|"

            concatenated_data = concatenated_data.strip("|")
            output_image_path = "output_image.png"
            embed_data_in_image(self.image_path, output_image_path, concatenated_data.encode('latin1'))
            QMessageBox.information(self, "Success", "Data embedded successfully into a single image!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to embed data: {str(e)}")

    def upload_image(self):
        image_path, _ = QFileDialog.getOpenFileName(self, "Upload Image", "", "Images (*.png *.jpg *.bmp)")
        if image_path:
            self.uploaded_image_path = image_path
            self.image_uploaded_label.setText(f"Uploaded: {os.path.basename(image_path)}")

    def upload_private_key(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Upload Private Key", "", "Key Files (*.pem)")
        if key_path:
            with open(key_path, "rb") as key_file:
                self.private_key = load_pem_private_key(key_file.read(), password=None)
            self.key_uploaded_label.setText(f"Uploaded: {os.path.basename(key_path)}")

    def extract_and_decrypt(self):
        try:
            concatenated_data = extract_data_from_image(self.uploaded_image_path).decode('latin1')
            encrypted_chunks = concatenated_data.split("|")

            for i, encrypted_chunk in enumerate(encrypted_chunks):
                try:
                    decrypted_data = decrypt_data(self.private_key, encrypted_chunk.encode('latin1'))
                    QMessageBox.information(self, "Decrypted Data", f"Decrypted Data: {decrypted_data}")
                    return
                except Exception:
                    continue

            QMessageBox.warning(self, "Error", "Private key does not match any encrypted chunk!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt data: {str(e)}")

# Run the Application
if _name_ == "_main_":
    app = QApplication([])
    window = SteganographyApp()
    window.show()
    app.exec_()
