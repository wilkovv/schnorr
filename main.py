import hashlib
from random import randint
from gmpy2 import powmod
from gmpy2 import c_mod
import base64


def generate_keys(prime_p, prime_q, alpha):
    # Private key s is a random number in {1,2,...,q}
    s = randint(1, prime_q)
    # The corresponding public key v is the number v = (α^(-s))(mod p)
    v = powmod(alpha, -s, prime_p)
    return [s, v]


def verify_signature(signature, m, v, KAC):
    # Protocol for signature verification

    # To verify the signature (e,y) for message m and public key v compute x_prim = (α^y*v^e)(mod p) and check that
    # e = h(x_prim,m) (signature test)

    x = (powmod(KAC.alpha, signature[1], KAC.prime_p) * powmod(v, signature[0], KAC.prime_p)) % KAC.prime_p
    e = hashlib.sha3_256()
    e.update(base64.encodebytes(bytes(str(x) + m, 'utf-8')))
    e = int(e.hexdigest(), 16)
    if signature[0] == e:
        print("Matching signature")
        return True
    return False


class KeyAuthenticationCenter:
    def __init__(self):
        # Primes p and q such that q | p-1, q >= 2^140, p >= 2^512
        self.prime_p = 9577748167875408109244668211897286239738971407508842709054038040792717107945316333840095997902553044168521922675575493393957059719087386309634012792081801
        self.prime_q = 371230549142457678652894116740204893013138426647629562366435582976461903408733191234112247980719110239089997002929282689688258128646797918978062511321
        # α ∈ Zp with order q, i.e.  α^q = 1 (mod p) α =/= 1
        alpha = 2
        while powmod(alpha, self.prime_q, self.prime_p) != 1:
            alpha += 1
        self.alpha = alpha;
        # A one-way hash function h (sha3_256)
        # KAC's own private and public key
        [self.s, self.v] = generate_keys(self.prime_p, self.prime_q, self.alpha)

    def registration(self, identification_string, pub_key):
        # Protocol for signature generation

        # 1. Preprocessing. Pick a random number r ∈ {1,...q} and compute x = α^r(mod p)
        r = randint(1, self.prime_q)
        x = powmod(self.alpha, r, self.prime_p)

        # 2. Compute e = h(x,m) ∈ {0,...,2^t-1}, for sha3_256 t = 256
        e = hashlib.sha3_256()
        e.update(base64.encodebytes(bytes(str(x) + identification_string + str(pub_key), 'utf-8')))
        e = int(e.hexdigest(), 16)

        # 3. Compute y = r + se(mod q) and output the signature (e,y)
        y = c_mod(r + self.s * e, self.prime_q)
        signature = [e, y]

        return signature


if __name__ == '__main__':
    # Creation of key authentication center
    KAC = KeyAuthenticationCenter()

    # Alice herself generates secret and public key by knowing KAC's p,q and α
    [alice_s, alice_v] = generate_keys(KAC.prime_p, KAC.prime_q, KAC.alpha)

    # Alice registers in KAC and gets in response signature of her identification string I and public key v (I,v)
    alice_I = "Alice:Adress:ID-Number"
    signature = KAC.registration(alice_I, alice_v)

    # The identification protocol

    # 1. Initiation A sends to B its identification string I and its public key v. B checks v by verifying KAC's
    # signature transmitted by A
    message = alice_I+str(alice_v)
    verify_signature(signature,message,KAC.v, KAC)

    # 2. Preprocessing A picks a random number r ∈ {1,...,q-1}, computes x=alfa^r(mod p), and sends x to B
    r = randint(1, KAC.prime_q)
    x = powmod(KAC.alpha, r, KAC.prime_p)

    # 3. B sends a random number e ∈ {0,...,2^t-1} to A (t - security number, for sha3_256 t = 256)
    t = 256
    e = randint(0, pow(2, t) - 1)

    # 4. A sends to B y = r + se(mod q)
    y = c_mod(r + alice_s * e, KAC.prime_q)

    # 5. B checks that x = (α^y * v^e)(mod p) and accepts A's proof of identity if equality holds
    x_prim = (powmod(KAC.alpha, y, KAC.prime_p) * powmod(alice_v, e, KAC.prime_p)) % KAC.prime_p

    if x_prim == x:
        print("Identification successful")
