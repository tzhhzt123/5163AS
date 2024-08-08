import secrets
from hashlib import sha256

class DiffieHellman:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.private_key = secrets.randbelow(prime)
        self.public_key = pow(generator, self.private_key, prime)

    def generate_shared_key(self, other_public_key):
        shared_key = pow(other_public_key, self.private_key, self.prime)
        return sha256(str(shared_key).encode()).hexdigest()

# 生成哈希值
def hash_value(value):
    return sha256(str(value).encode()).hexdigest()

# 模拟窃听者
def eavesdrop(alice_public_key, bob_public_key):
    # 窃听者只能获得公钥，无法计算共享密钥
    print("Eavesdropper: Alice's Public Key:", alice_public_key)
    print("Eavesdropper: Bob's Public Key:", bob_public_key)

# 公共参数
prime = 23 # 公共素数（P）
generator = 5 # 公共基数（G）

# Alice和Bob各自生成自己的公钥和私钥
alice = DiffieHellman(prime, generator)
bob = DiffieHellman(prime, generator)

# 窃听者截获公钥
eavesdrop(alice.public_key, bob.public_key)

# 计算公钥的哈希值
alice_public_key_hash = hash_value(alice.public_key)
bob_public_key_hash = hash_value(bob.public_key)

# 传输公钥和哈希值
transmitted_alice_public_key = alice.public_key
transmitted_alice_public_key_hash = alice_public_key_hash
transmitted_bob_public_key = bob.public_key
transmitted_bob_public_key_hash = bob_public_key_hash

# 验证公钥的完整性
if hash_value(transmitted_alice_public_key) == transmitted_alice_public_key_hash:
    print("Alice's public key integrity verified.")
else:
    print("Alice's public key integrity verification failed.")

if hash_value(transmitted_bob_public_key) == transmitted_bob_public_key_hash:
    print("Bob's public key integrity verified.")
else:
    print("Bob's public key integrity verification failed.")

# Alice和Bob生成共享密钥
alice_shared_key = alice.generate_shared_key(transmitted_bob_public_key)
bob_shared_key = bob.generate_shared_key(transmitted_alice_public_key)

# 计算共享密钥的哈希值
alice_shared_key_hash = hash_value(alice_shared_key)
bob_shared_key_hash = hash_value(bob_shared_key)

# 验证共享密钥的完整性
if alice_shared_key_hash == bob_shared_key_hash:
    print("Shared key integrity verified.")
else:
    print("Shared key integrity verification failed.")

print("Alice's Shared Key:", alice_shared_key)
print("Bob's Shared Key:", bob_shared_key)
