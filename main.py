import secrets
from hashlib import sha256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class DiffieHellman:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.private_key = secrets.randbelow(prime)
        self.public_key = pow(generator, self.private_key, prime)

    def generate_shared_key(self, other_public_key):
        shared_key = pow(other_public_key, self.private_key, self.prime)
        return sha256(str(shared_key).encode()).hexdigest()

# Generate hash value
def hash_value(value):
    return sha256(str(value).encode()).hexdigest()

# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Sign message
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Simulate eavesdropper
def eavesdrop(alice_public_key, bob_public_key):
    # Eavesdropper can only obtain public keys, cannot compute shared key
    print("Eavesdropper: Alice's Public Key:", alice_public_key)
    print("Eavesdropper: Bob's Public Key:", bob_public_key)

# Common parameters
prime = 23 # Common prime (P)
generator = 5 # Common generator (G)

# Alice and Bob each generate their own public and private keys
alice = DiffieHellman(prime, generator)
bob = DiffieHellman(prime, generator)

# Generate RSA key pair
alice_private_key, alice_rsa_public_key = generate_rsa_keys()
bob_private_key, bob_rsa_public_key = generate_rsa_keys()

# Alice signs her public key and sends it to Bob
alice_signature = sign_message(alice_private_key, str(alice.public_key).encode())

# Bob signs his public key and sends it to Alice
bob_signature = sign_message(bob_private_key, str(bob.public_key).encode())

# Eavesdropper intercepts public keys
eavesdrop(alice.public_key, bob.public_key)

# Verify the integrity of public keys
alice_public_key_hash = hash_value(alice.public_key)
bob_public_key_hash = hash_value(bob.public_key)

# Transmit public keys and hash values
transmitted_alice_public_key = alice.public_key
transmitted_alice_public_key_hash = alice_public_key_hash
transmitted_bob_public_key = bob.public_key
transmitted_bob_public_key_hash = bob_public_key_hash

# Verify Alice's public key
if verify_signature(alice_rsa_public_key, str(transmitted_alice_public_key).encode(), alice_signature):
    print("Alice's identity verified.")
else:
    print("Alice's identity verification failed.")

# Verify Bob's public key
if verify_signature(bob_rsa_public_key, str(transmitted_bob_public_key).encode(), bob_signature):
    print("Bob's identity verified.")
else:
    print("Bob's identity verification failed.")

# Verify the integrity of public keys
if hash_value(transmitted_alice_public_key) == transmitted_alice_public_key_hash:
    print("Alice's public key integrity verified.")
else:
    print("Alice's public key integrity verification failed.")

if hash_value(transmitted_bob_public_key) == transmitted_bob_public_key_hash:
    print("Bob's public key integrity verified.")
else:
    print("Bob's public key integrity verification failed.")

# Alice and Bob generate shared keys
alice_shared_key = alice.generate_shared_key(transmitted_bob_public_key)
bob_shared_key = bob.generate_shared_key(transmitted_alice_public_key)

# Compute hash value of shared key
alice_shared_key_hash = hash_value(alice_shared_key)
bob_shared_key_hash = hash_value(bob_shared_key)

# Verify the integrity of shared keys
if alice_shared_key_hash == bob_shared_key_hash:
    print("Shared key integrity verified.")
else:
    print("Shared key integrity verification failed.")

print("Alice's Shared Key:", alice_shared_key)
print("Bob's Shared Key:", bob_shared_key)
