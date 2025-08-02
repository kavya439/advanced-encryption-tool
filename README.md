# advanced-encryption-tool

The Advanced Encryption Tool is a user-friendly desktop application built with Python’s Tkinter library and the cryptography package. It allows users to securely encrypt and decrypt files using symmetric encryption (AES via Fernet), manage encryption keys, and perform all actions through an interactive graphical user interface. This tool is ideal for users who want strong file security without needing command-line knowledge or complex setup.

The interface is clean and structured with clear sections for Key Management, File Selection, and Encryption/Decryption Actions. The application’s main functionality revolves around the Fernet module from the cryptography library, which implements AES encryption with URL-safe Base64-encoded keys.

How It Works
Encryption Key Generation and Management:

Upon starting, the tool does not have a key loaded. Users can:

Generate a new key: A secure 32-byte key is generated using Fernet and displayed in a scrollable text area.

Save the key to a .key file for reuse.

Load a key from a previously saved file to use for encryption or decryption.

The loaded key is essential for performing any cryptographic operations.

File Selection:

Users can browse and select a file from their computer that they want to encrypt or decrypt. The file path is shown in a read-only entry box, ensuring clarity about the target file.

File Encryption:

Once a file and key are selected, clicking "Encrypt File" reads the file content in binary, encrypts it using the Fernet object initialized with the key, and saves the encrypted version as a new file with the .encrypted extension. This ensures the original file remains untouched while producing a secure copy.

File Decryption:

Similarly, users can decrypt a previously encrypted file by selecting it and clicking "Decrypt File". The app reads the file, decrypts it with the loaded key, and restores the original content. If the encrypted file has the .encrypted suffix, it is removed during the restoration process, ensuring proper file naming.

Status and Feedback:

The application provides real-time feedback through a status bar at the bottom, showing current actions and results. Additionally, all critical steps (key generation, encryption, file saving) are accompanied by message boxes to confirm success or alert on errors.

Key Features:

Symmetric AES encryption with Fernet

Save/load keys securely

Encrypt and decrypt any file

Simple, clean Tkinter GUI

No command-line usage needed

Real-time status updates

Security Note:

The security of encrypted files is tightly linked to the encryption key. If the key is lost, the encrypted data cannot be recovered. Users are encouraged to save their keys securely in external storage or password managers.

This application offers a perfect balance between strong encryption practices and usability, making it a powerful tool for both technical and non-technical users who need to secure their data with minimal effort.
