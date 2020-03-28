# import from Lockwise data from JSON
# virtualenv -p python2.7 <dir>
# pip install PyFxA syncclient cryptography
#
# based on https://gist.github.com/rfk/916d9ca684f862b1c1030c685a5a4d19

import os
import time
import json
import random
import string
import getpass
import hmac
import hashlib
import base64
import uuid
from binascii import hexlify

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import fxa.core
import fxa.crypto
import syncclient.client

CRYPTO_BACKEND = default_backend()

EMAIL = raw_input("Email: ")
PASSWORD = getpass.getpass("Password: ")

# Below here is all the mechanics of uploading them to the sync server.

def main(import_file_name):
    creds = login()
    upload_password_records(import_file_name, *creds)


def login():
    client = fxa.core.Client()
    print "Signing in as", EMAIL, "..."
    session = client.login(EMAIL, PASSWORD, keys=True)
    try:
        status = session.get_email_status()
        while not status["verified"]:
            print "Please click through the confirmation email."
            if raw_input("Hit enter when done, or type 'resend':").strip() == "resend":
                session.resend_email_code()
            status = session.get_email_status()
        assertion = session.get_identity_assertion("https://token.services.mozilla.com/")
        _, kB = session.fetch_keys()
    finally:
        session.destroy_session()
    return assertion, kB


def upload_password_records(import_file_name, assertion, kB):
    # Connect to sync.
    xcs = hexlify(hashlib.sha256(kB).digest()[:16])
    client = syncclient.client.SyncClient(assertion, xcs)
    # Fetch /crypto/keys.
    raw_sync_key = fxa.crypto.derive_key(kB, "oldsync", 64)
    root_key_bundle = KeyBundle(
        raw_sync_key[:32],
        raw_sync_key[32:],
    )
    keys_bso = client.get_record("crypto", "keys")
    keys = root_key_bundle.decrypt_bso(keys_bso)
    default_key_bundle = KeyBundle(
      base64.b64decode(keys["default"][0]),
      base64.b64decode(keys["default"][1]),
    )
    # load entries
    records = []
    with open(import_file_name) as import_file:
        records = json.load(import_file)
    
    count = len(records)
    i = 1;
    for r in records:
        r['id'] = '{%s}' % (uuid.uuid4(),)
        print "Uploading", i, "of", count
        i += 1
        er = default_key_bundle.encrypt_bso(r)
        assert default_key_bundle.decrypt_bso(er) == r
        client.put_record("passwords", er)
    print "Done!"


class KeyBundle:
    """A little helper class to hold a sync key bundle."""

    def __init__(self, enc_key, mac_key):
        self.enc_key = enc_key
        self.mac_key = mac_key

    def decrypt_bso(self, data):
        payload = json.loads(data["payload"])

        mac = hmac.new(self.mac_key, payload["ciphertext"], hashlib.sha256)
        if mac.hexdigest() != payload["hmac"]:
            raise ValueError("hmac mismatch: %r != %r" % (mac.hexdigest(), payload["hmac"]))

        iv = base64.b64decode(payload["IV"])
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=CRYPTO_BACKEND
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(payload["ciphertext"]))
        plaintext += decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return json.loads(plaintext)


    def encrypt_bso(self, data):
        plaintext = json.dumps(data)

        padder = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=CRYPTO_BACKEND
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        ciphertext += encryptor.finalize()

        b64_ciphertext = base64.b64encode(ciphertext)
        mac = hmac.new(self.mac_key, b64_ciphertext, hashlib.sha256).hexdigest()

        return {
            "id": data["id"],
            "payload": json.dumps({
                "ciphertext": b64_ciphertext,
                "IV": base64.b64encode(iv),
                "hmac": mac,
            })
        }


if __name__ == "__main__":
    import sys
    import_file_name = sys.argv[1]
    main(import_file_name)
