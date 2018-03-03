"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError

def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()

    def upload(self, name, value):

    	# create hashed filename 
        uid = path_join(self.username, cryptographic_hash(name, "SHA256"))

    	# generate ciphertext c1 using sym key enc
    	sym_key1 = self.crypto.get_random_bytes(16)
    	iv = self.crypto.get_random_bytes(16)
    	c1 = self.crypto.symmetric_encrypt(value, sym_key1, "AES", "CBC", iv)

    	# create mac tag 
    	sym_key2 = self.crypto.get_random_bytes(16)
    	mac_tag = self.crypto.message_authentication_code(c1 + uid, sym_key2, "SHA256")

    	# upload the key, value, for sym enc
		self.storage_server.put(uid, c1 + iv + mac_tag)


		# generate ciphertext c2 using asym key enc
    	asym_k = self.public_key_server.get_public_key(self.username)
    	c2 = self.crypto.asymmetric_encrypt(sym_key1 + sym_key2, asym_k)
    	s2 = self.crypto.asymmetric_sign(c2, self.private_key)

    	# upload the key, value, for asym enc
    	self.storage_server.put(uid + "key", c2 + s2)

    def download(self, name):
        uid = self.resolve(path_join(self.username, cryptographic_hash(name, "SHA256")))
        
        resp = self.storage_server.get(uid)
        if resp is None:
            return None
        return resp[7:]

    def share(self, user, name):
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.put(sharename,
                                "[POINTER] " + path_join(self.username, name))
        return sharename

    def receive_share(self, from_username, newname, message):
        my_id = path_join(self.username, newname)
        self.storage_server.put(my_id, "[POINTER] " + message)

    def revoke(self, user, name):
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

if __name__ == "__main__":
    # A basic unit test suite for the insecure Client to demonstrate
    # its functions.
    from servers import PublicKeyServer, StorageServer
    from crypto import Crypto

    print("Initializing servers and clients...")
    pks = PublicKeyServer()
    server = StorageServer()
    crypto = Crypto()
    alice = Client(server, pks, crypto, "alice")
    bob = Client(server, pks, crypto, "bob")
    carol = Client(server, pks, crypto, "carol")
    dave = Client(server, pks, crypto, "dave")

    print("Testing client put and share...")
    alice.upload("a", "b")

    m = alice.share("bob", "a")
    bob.receive_share("alice", "q", m)

    m = bob.share("carol", "q")
    carol.receive_share("bob", "w", m)

    m = alice.share("dave", "a")
    dave.receive_share("alice", "e", m)

    print("Testing Bob, Carol, and Dave getting their new shares...")
    assert bob.download("q") == "b"
    assert carol.download("w") == "b"
    assert dave.download("e") == "b"

    print("Revoking Bob...")
    alice.revoke("bob", "a")
    dave.upload("e", "c")

    print("Testing Bob, Carol, and Dave getting their shares...")
    assert alice.download("a") == "c"
    assert bob.download("q") != "c"
    assert carol.download("w") != "c"
    assert dave.download("e") == "c"

    print("Testing restarting PKS and clients...")
    pks2 = PublicKeyServer()
    alice2 = Client(server, pks2, crypto, "alice")
    bob2 = Client(server, pks2, crypto, "bob")
    assert alice2.private_key.publickey() == bob2.pks.get_public_key("alice")

    crypto._remove_keyfile("alice")
    crypto._remove_keyfile("bob")
    crypto._remove_keyfile("carol")
    crypto._remove_keyfile("dave")
    print("Basic tests passed.")
