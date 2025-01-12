# **InvisiKey**  
**Secure, Multi-Key Steganography with Image Embedding**  

InvisiKey is an advanced GUI-based application that integrates Access Control Lists (ACL), RSA encryption, and steganography to securely transmit secret messages by embedding encrypted data into image files, providing multi-layer security through encryption and data-hiding techniques, where each message can be split into n parts, with each part encrypted using n separate private keys for added security, ensuring secure decryption only for authorized users.

---

### **Features**  
- **Multi-User Encryption**: Message is split into **n** parts, each encrypted with a different RSA key.  
- **Steganography**: Securely hides the encrypted message in an image using the Least Significant Bit (LSB) method.  
- **RSA Encryption**: Ensures only authorized users with the corresponding private keys can decrypt their part of the message.  
- **User-Friendly GUI**: Built with **PyQt5** for a simple and intuitive user interface.  

---

### **How It Works**  

1. **Sender's Process**:  
   - **Message Splitting**: The sender enters the secret message, which is then divided into **n** parts based on the number of intended recipients. Each part contains a portion of the message.  
   - **RSA Key Pair Generation**: For each part of the message, an **RSA public-private key pair** is generated. The **public key** is used for encrypting each part of the message, while the corresponding **private key** will be needed for decryption.  
   - **Message Encryption**: Each part of the message is encrypted using the corresponding public key.  
   - **Embedding**: All encrypted message parts are concatenated and embedded into a single image using the **LSB (Least Significant Bit)** method of steganography. This image is then ready for transmission.

2. **Receiver's Process**:  
   - **Image Upload**: The receiver uploads the image containing the hidden encrypted message.  
   - **Private Key Upload**: The receiver needs to upload their corresponding **private key** to decrypt their part of the message.  
   - **Message Decryption**: Once the private key is provided, the system decrypts the corresponding encrypted chunk and retrieves the part of the original message.  
   - The receiver can continue to decrypt their part of the message until all parts are recovered and the full message is reconstructed.

---

### **Technologies**  
- **Python**  
- **PyQt5**  
- **Cryptography (RSA encryption)**  
- **Stegano (Image Steganography)**  

---

### ***Important Notes**
Display Server Required: This application is built with a GUI using PyQt5, which requires a display server to run. It will not work on GitHub or in typical online editors that do not support GUI applications. Please run it on a local machine or server with a proper display environment (e.g., X11, Wayland for Linux, or any system that supports GUI applications).

---

### **Setup**  

1. Clone the repository:  
   git clone https://github.com/ARDcreates/InvisiKey.git
   cd InvisiKey
  

2. Install dependencies:  
   pip install -r requirements.txt


3. Run the application:  
   python InvisiKey.py

---

### **License**  
**Apache License 2.0**
