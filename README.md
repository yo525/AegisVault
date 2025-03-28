# **AegisVault: Secure File Storage and Management**
![Apache-2.0 License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)     ![Python Version](https://img.shields.io/badge/python-3.13%2B-green.svg)
![none](https://img.shields.io/github/languages/code-size/yo525/AegisVault)

![](/assets/AegisVault.png)

AegisVault is a secure file storage and management system designed to protect your sensitive data from unauthorized access. With its robust encryption and decryption mechanisms, AegisVault ensures that your files remain confidential and secure.

## Table of Contents

- [Files](#files)
- [Features](#features)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [How it Works](#how-it-works)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [Security Disclosure](#security-disclosure)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## **Files**
- [AegisVault.py](AegisVault.py) --> Main core. AegisVault itself.
- [AegisVault.txt](AegisVault.txt) --> AegisVault Database, this is where all data will be securely stored.

## **Features**

- **End-to-End Encryption**: AegisVault uses advanced encryption algorithms to protect your files, both in transit and at rest.
- **File and Directory Encryption**: Encrypt files and directories with ease, keeping your sensitive data secure.
- **File Management**: AegisVault provides a user-friendly interface to manage your files, including adding, deleting, and downloading files.
- **Backup and Restore**: AegisVault allows you to create backups of your files and restore them in case of data loss or corruption.
- **Data Integrity**: Verify the integrity of your encrypted data using *Hash-based Message Authentication Code* (HMAC).
- **User-friendly interface**: AegisVault features a simple and intuitive interface, making it easy to use for users of all skill levels.

## **Requirements**

- **Python 3.x**: AegisVault requires Python 3.x to run.
- **pip** (Python package installer)

## **Getting Started**

1. Clone the repository: `git clone https://github.com/yo525/AegisVault.git`
2. Enter to the directory: `cd AegisVault`
3. Install the dependencies: `pip install -r requirements.txt`
4. Run the application: `python AegisVault.py`
5. Enter your password and enjoy. *The default password is `password`*

## **How it Works**

1.  **Initialization**: When you first run AegisVault, you will be prompted to set a password (*The default password is `password`, this can later be change*). This password will be used to encrypt and decrypt your files.
2.  **Data Encryption**: Add files and directories to AegisVault, which will encrypt them using AES.
3.  **Data Storage**: Store the encrypted data in a secure text file, protected by your password.
4.  **Data Retrieval**: Enter your password to access your encrypted data, which will be decrypted using AES.
5.  **Data Verification**: Verify the integrity of the decrypted data using a HMAC.
6.  **Data Management**: Manage your encrypted data using the AegisVault interface.
7.  **Backup and Restore**: Backup and restore your encrypted data using secure files.

By following these steps, AegisVault provides a secure and easy-to-use solution for protecting your sensitive data.

## **Security**

AegisVault uses advanced encryption algorithms to protect your files, including:

- **AES-256-GCM**: AegisVault uses the AES-256-GCM encryption algorithm to encrypt and decrypt your files.
- **Scrypt**: AegisVault uses the Scrypt key derivation function to derive a secure key from your password.
- **SHA3-512**: AegisVault uses the SHA3-512 hash function to verify the integrity of your files.
- **Token_Bytes**: AegisVault uses the token_bytes function from the python standard secrets library to create unique, randomly generated salts for the encryption process.

## **Contributing**

AegisVault is an open-source project, and contributions are welcome. If you would like to contribute to AegisVault, please fork the repository and submit a pull request.

## **License**

AegisVault is licensed under the Apache-2.0 license. See the [LICENSE](LICENSE) file for more information.

## Security Disclosure

**Important**: AegisVault is a non-externally tested software, and as such, it may contain security vulnerabilities or flaws. Although it utilizes the AES encryption algorithm, which is considered secure, the implementation and overall security of AegisVault have not been thoroughly vetted by external experts. Therefore, we strongly advise using AegisVault with caution and at your own risk. By using AegisVault, you acknowledge that you understand and accept the potential risks associated with using a non-externally tested cryptographic application.

## **Acknowledgments**

- Special thanks to the developers of the `easygui` and `pycryptodome` libraries, which are used in AegisVault.

## Contact

- **Author:** yo525
- **Email:** [yo525@proton.me](mailto:yo525@proton.me)
-   **GitHub:** [yo525](https://github.com/yo525)

Feel free to reach out for any questions or feedback!
