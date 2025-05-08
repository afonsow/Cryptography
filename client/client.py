import asyncio
import os
import platform
import json


from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


conn_port = 7777
max_msg_size = 9999


class Client:

    def __init__(self, sckt=None):
        self.sckt = sckt
        self.msg_cnt = 0
        self.derived_key = None
        self.iv = None
        self.id = None


async def menu(reader, writer, enc_key, iv, client_id, flag):
    """ Main menu """

    while True:

        ## Exit if exit is chosen in the previous menu
        if flag == 1:
            break

        print("\n=== Messaging Menu ===")
        print("1. Send message")
        print("2. View all messages")
        print("3. View new messages")
        print("4. Read a message")
        print("5. Delete a message")
        print("6. Exit")
        option = input("Choose an option: ").strip()

        if option == "1":
            await send_message(client_id, reader, writer, enc_key, iv)
        elif option == "2":
            await view_messages("all", client_id, reader, writer, enc_key, iv)
        elif option == "3":
            await view_messages("new", client_id, reader, writer, enc_key, iv)
        elif option == "4":
            message_id = input("Enter the message ID to read: ").strip()
            await read_message(message_id, client_id, reader, writer, enc_key, iv)
        elif option == "5":
            message_id = input("Enter the message ID to delete: ").strip()
            await delete_message(message_id, client_id, reader, writer, enc_key, iv)
        elif option == "6":
            print("Exiting.")
            break
        else:
            clear_terminal()
            print("Invalid option. Try again.")


async def send_message(client_id, reader, writer, enc_key, iv):
    """ Server communication to send a message """

    destiny_id = input("Recipient ID: ").strip()
    subject = input("Subject (max 50 chars): ").strip()
    while len(subject) > 50:
        print("Message subject must be under 50 chars.")
        subject = input("Subject (max 50 chars): ").strip()
    content = input("Content: ").strip()
    password = input("Input password: ").strip()

    ## Load user's private key
    private_key_filename = f"{client_id}_private_key_pem"
    with open(private_key_filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode("utf-8"),
            backend=default_backend()
        )

    # Create the message to sign
    message_to_sign = f"{client_id}:{destiny_id}:{subject}:{content}".encode()

    # Generate the signature
    signature = private_key.sign(
        message_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Prepare the message with the signature
    message = {
        "type": "send",
        "origin_id": client_id,
        "destiny_id": destiny_id,
        "subject": subject,
        "content": content,
        "signature": signature.hex()  # Convert signature to hex for easier storage
    }

    ## Encrypt and send the message
    encrypted_message = encrypt_message(json.dumps(message), enc_key, iv)
    writer.write(encrypted_message)
    await writer.drain()

    ## server feedback
    enc_ack = await reader.read(max_msg_size)
    ack = decrypt_message(enc_ack, enc_key, iv)
    clear_terminal()
    print(ack)


async def view_messages(view_type, client_id, reader, writer, enc_key, iv):
    """ Server commmunication to view all messages """

    # Request the message content
    request = {"type": view_type, "client_id": client_id}
    writer.write(encrypt_message(json.dumps(request), enc_key, iv))
    await writer.drain()

    # Receive and decrypt the response
    response = await reader.read(max_msg_size)
    messages = json.loads(decrypt_message(response, enc_key, iv))

    clear_terminal()
    if messages:
        if view_type == "all":
            print("All messages for you:\n")
        if view_type == "new":
            print("New messages for you:\n")
        for msg in messages:
            print(msg)
    else:
        print("No messages for you were found.")


async def read_message(message_id, client_id, reader, writer, enc_key, iv):
    """ Server communication to read a message """

    # Request the message content
    request = {"type": "read", "client_id": client_id, "msg_id": message_id}
    writer.write(encrypt_message(json.dumps(request), enc_key, iv))
    await writer.drain()

    # Receive and decrypt the response
    enc_response = await reader.read(max_msg_size)
    response = decrypt_message(enc_response, enc_key, iv)
    if response == "Message not found.":
        clear_terminal()
        print("Your message was not found")
        return None

    if response == "You do not have the permission to read this message.":
        clear_terminal()
        print(response)
        return None

    message = json.loads(response.encode())

    # Request the sender's certificate from the server
    cert_request = {"type": "get_certificate", "origin_id": message["origin_id"]}
    writer.write(encrypt_message(json.dumps(cert_request), enc_key, iv))
    await writer.drain()

    # Receive and decrypt the certificate
    enc_cert_response = await reader.read(max_msg_size)
    cert_response = decrypt_message(enc_cert_response, enc_key, iv)
    if cert_response == "Certificate not found.":
        clear_terminal()
        print("Could not verify the sender's identity. Certificate missing.")
        return None

    # Load the sender's certificate
    sender_cert = x509.load_pem_x509_certificate(cert_response.encode(), default_backend())
    sender_public_key = sender_cert.public_key()

    # Verify the signature
    try:
        message_to_verify = f"{message['origin_id']}:{message['destiny_id']}:{message['subject']}:{message['content']}".encode()
        sender_public_key.verify(
            bytes.fromhex(message["signature"]),  # Convert the hex-encoded signature back to bytes
            message_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        clear_terminal()
        print("\nMessage authenticity verified!")
    except Exception as e:
        clear_terminal()
        print("\nFailed to verify the message's authenticity. The signature is invalid.")
        print(f"Error: {e}")
        return None

    # Display the message content
    print("\nMessage Content:")
    for key, value in message.items():
        if key != "signature":  # Skip the signature field for display
            print(f"{key}: {value}")


async def delete_message(message_id, client_id, reader, writer, enc_key, iv):
    """ Server communication to delete a message"""

    ## Request to delete the message
    request = {"type": "delete", "client_id": client_id, "msg_id": message_id}
    writer.write(encrypt_message(json.dumps(request), enc_key, iv))
    await writer.drain()

    ## Server feedback
    response = await reader.read(max_msg_size)
    clear_terminal()
    print(decrypt_message(response, enc_key, iv))


def clear_terminal():
    """ Function to clear the terminal """

    if platform.system() == "Windows":
        os.system("cls")  # Clear command for Windows
    else:
        os.system("clear")


async def secure_client(reader, writer):
    """ Key derivation through Diffie-Hellman """

    # Receive the DH parameters (p and g) from the server
    p_bytes = await reader.read(128)  # Adjust size as needed
    g_bytes = await reader.read(128)  # Adjust size as needed

    p = int.from_bytes(p_bytes, 'big')
    g = int.from_bytes(g_bytes, 'big')

    # Generate DH parameters using received p and g
    parameters = dh.DHParameterNumbers(p, g).parameters()

    # Generate client's private key and public key
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()

    # Send client's public key to the server
    writer.write(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    await writer.drain()

    # Receive server's public key
    server_public_key_bytes = await reader.read(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Compute shared key
    shared_key = client_private_key.exchange(server_public_key)

    # Derive the encryption key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    return derived_key


def encrypt_message(message: str, key: bytes, iv: bytes):
    """ Encrypt the message with AES-GCM using the derived key and an IV received from the server """

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    msg = ciphertext + encryptor.tag
    return msg


def decrypt_message(payload: bytes, key: bytes, iv: bytes):
    """ Decrypt encrypted messages to string type """

    ## Separate tag from message
    tag = payload[-16:]
    ciphertext = payload[:-16]

    dec = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = dec.update(ciphertext) + dec.finalize()
    return plaintext.decode()


async def register_user(reader, writer, enc_key, iv):
    """ Server communication to register a user """

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    confirm_password = input("Confirm password: ").strip()

    ## check if passwords match
    if password != confirm_password:
        clear_terminal()
        print("Passwords do not match")
        print_login()
        return 0

    ## send username
    writer.write(encrypt_message(username, enc_key, iv))
    await writer.drain()

    ## server feedback
    ack = await reader.read(max_msg_size)
    if ack.decode() == "User already registered":
        clear_terminal()
        print(ack.decode())
        return 0

    ## send password
    writer.write(encrypt_message(password, enc_key, iv))
    await writer.drain()

    ## server feedback
    ack = await reader.read(max_msg_size)
    if ack.decode() == "User registered successfully!":
        clear_terminal()
        print(ack.decode())

    ## Receive encrypted private key from server
    enc_private_key = await reader.read(max_msg_size)
    private_key_pem = decrypt_message(enc_private_key, enc_key, iv)

    # Write the PEM-formatted private key to the file
    filename = f"{username}_private_key_pem"
    with open(filename, "w") as file:
        file.write(private_key_pem)

    print(f"Private key saved to {filename}\nEncrypted with your password")


async def login_user(reader, writer, enc_key, iv):
    """ Server communication to log in """

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    ## send username
    writer.write(encrypt_message(username, enc_key, iv))
    await writer.drain()

    response = await reader.read(max_msg_size)
    if response.decode() == "Username not found.":
        clear_terminal()
        print(response.decode())
        print_login()
        return None

    ## send password
    writer.write(encrypt_message(password, enc_key, iv))
    await writer.drain()

    ## server feedback
    response = await reader.read(max_msg_size)
    if response.decode() == "Login successful!":
        clear_terminal()
        print("Welcome", username)
        return username
    else:
        clear_terminal()
        print(response.decode())
        print_login()
        return None


def print_login():
    """ Function to print login menu """

    print("\n=== User Management System ===")
    print("1. Register User")
    print("2. Login")
    print("3. Exit")


async def tcp_echo_client():
    """ Main function """

    ## Open server communicatioin
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)

    ## Get encryption key and IV
    enc_key = await secure_client(reader, writer)
    iv = await reader.read(16)

    ## print login menu
    clear_terminal()
    print_login()

    ## flag just to guarantee that the program ends when exit is pressed in login menu
    flag = 0

    ## login menu
    while True:

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            writer.write(choice.encode())
            await writer.drain()
            await register_user(reader, writer, enc_key, iv)
            print_login()
        elif choice == "2":
            writer.write(choice.encode())
            await writer.drain()
            client.id = await login_user(reader, writer, enc_key, iv)
        elif choice == "3":
            print("Goodbye!")
            flag = 1
            break
        else:
            clear_terminal()
            print("Invalid choice. Please try again.")
            print_login()

        ## break only after login
        if client.id is not None:
            break

    ## main menu
    await menu(reader, writer, enc_key, iv, client.id, flag)

    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.new_event_loop()
    loop.run_until_complete(tcp_echo_client())
    loop.close()
    print('Client finished!')


run_client()
