#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain

        """
        self.username = username
        self.conn = {}
        self.max_skip = max_skip
        self.i = 1

    def add_connection(self, username, chain_key_send, chain_key_recv):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the username
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        self.conn[username] = {}
        self.conn[username]["keySend"] = chain_key_send
        self.conn[username]["keyRecive"] = chain_key_recv
        self.conn[username]["i"] = 1
        self.conn[username]["skiped"] = {}
    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.conn[username]["i"] .to_bytes(4, byteorder='big'),  # You can specify a salt if needed
            backend=default_backend(),
            info=None
        )

        sendingKey = self.conn[username]["keySend"]
        derived_key = hkdf.derive(sendingKey)
        self.conn[username]["keySend"] = derived_key[:32]
        self.conn[username]["i"] += 1

        cipher = AESGCM(derived_key[32:])
        iv = secrets.token_bytes(12)
        encriptedMessage = cipher.encrypt(iv, message.encode('utf-8'), None)

        return self.conn[username]["i"]-1, iv, encriptedMessage

    def receive_message(self, username, message):
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and a header data

        Returns a plaintext (str)

        """
        if message[0] < self.conn[username]["i"]:
            decrKey = self.conn[username]["skiped"][message[0]]
            del self.conn[username]["skiped"][message[0]]

        while message[0] >= self.conn[username]["i"]:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=self.conn[username]["i"] .to_bytes(4, byteorder='big'),  # You can specify a salt if needed
                backend=default_backend(),
                info = None
            )
            recKey = self.conn[username]["keyRecive"]
            derived_key = hkdf.derive(recKey)
            self.conn[username]["keyRecive"] = derived_key[:32]
            decrKey = derived_key[32:]
            if message[0] != self.conn[username]["i"]:
                self.conn[username]["skiped"][self.conn[username]["i"]] = decrKey
                if(len(self.conn[username]["skiped"].keys()) > self.max_skip):
                    min_key = min(map(int, self.conn[username]["skiped"].keys()))
                    del self.conn[username]["skiped"][str(min_key)]
            self.conn[username]["i"] += 1

        cipher = AESGCM(decrKey)
        plaintext = cipher.decrypt(message[1], message[2], None)
        return plaintext.decode('utf-8')
