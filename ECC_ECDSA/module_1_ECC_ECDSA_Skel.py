import math
import random
import warnings
import hashlib

# Euclidean algorithm for gcd computation
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

# Modular inversion computation
def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

# Function to map a message to a bit string
def hash_message_to_bits(msg):
    h = hashlib.sha256()
    h.update(msg.encode())
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits

# Function to map a truncated bit string to an integer modulo q
def bits_to_int(h_as_bits, q):
    val = 0
    len = int(math.log(q, 2) + 1)
    for i in range(len):
        val = val * 2
        if(h_as_bits[i] == '1'):
            val = val + 1
    return val % q

# An elliptic curve is represented as an object of type Curve. 
# Note that for this lab, we use the short Weierstrass form of representation.
class Curve(object):

    def __init__(self, a, b, p, P_x, P_y, q):
        self.a = a
        self.b = b
        self.p = p
        self.P_x = P_x
        self.P_y = P_y
        self.q = q

    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.p == 0

    def on_curve(self, x, y):
        return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

    def is_equal(self, other):
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p

# A point at infinity on an elliptic curve is represented separately as an object of type PointInf. 
# We make this distinction between a point at infinity and a regular point purely for the ease of implementation.
class PointInf(object):

    def __init__(self, curve):
        self.curve = curve

    def is_equal(self, other):
        if not isinstance(other, PointInf):
            return False
        return self.curve.is_equal(other.curve)

    def negate(self):
        # Write a function that negates a PointInf object.        
        # Ths is an optional extension and is not evaluated
        raise NotImplementedError()

    def double(self):
        # Write a function that doubles a PointInf object.
        return self

    def add(self, other):
        # Write a function that adds a Point object (or a PointInf object) to a PointInf object. 
        # See below for the description of a Point object
        # Make sure to output the correct kind of object depending on whether "other" is a Point object or a PointInf object 
        return other


# A point on an elliptic curve is represented as an object of type Point. 
# Note that for this lab, we will use the affine coordinates-based representation of a point on an elliptic curve.
class Point(object):

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.p
        self.on_curve = True
        if not self.curve.on_curve(self.x, self.y):
            warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve))
            self.on_curve = False

    def is_equal(self, other):
        if not isinstance(other, Point):
            return False
        return self.curve.is_equal(other.curve) and self.x == other.x and self.y == other.y

    def negate(self):
        # Write a function that negates a Point object and returns the resulting Point object
        # Ths is an optional extension and is not evaluated
        raise NotImplementedError()

    def double(self):
        # Write a function that doubles a Point object and returns the resulting Point object
        lmd = ((3 * (self.x ** 2) + self.curve.a) * mod_inv(2 * self.y, self.p)) % self.p
        xprm = (lmd ** 2 - 2 * self.x) % self.p
        yprm = -(self.y + lmd * (xprm - self.x)) % self.p
        return Point(self.curve, xprm, yprm)

    def add(self, other):
        # Write a function that adds a Point object (or a PointInf object) to the current Point object and returns the resulting Point object
        if isinstance(other, PointInf):
            return self
        elif self.x == other.x:
            if self.y == other.y:
                return self.double()
            else: #P + (-P) = O
                return PointInf(self.curve)

        lmd = ((self.y - other.y) * mod_inv(self.x - other.x, self.p)) % self.p
        xprm = (lmd ** 2 - self.x - other.x) % self.p
        yprm = -(self.y + lmd * (xprm - self.x)) % self.p
        return Point(self.curve, xprm, yprm)

    def scalar_multiply(self, scalar):
        # Write a function that performs a scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int or long
        # Your function need not be "constant-time"
        sc = scalar % self.curve.q
        if sc == 0:
            return PointInf(self.curve)
        elif sc == 1:
            return self
        cur = self
        for bit in bin(sc)[3:]:
            cur = cur.double()
            if bit == '1':
                cur = cur.add(self)
        return cur

    def scalar_multiply_Montgomery_Ladder(self, scalar):
        # Write a function that performs a "constant-time" scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int or long
        # Implement an elementary timer to check that your implementation is indeed constant-time
        # This is not graded but is an extension for your to try out on your own
        raise NotImplementedError()


# The parameters for an ECDSA scheme are represented as an object of type ECDSA_Params
class ECDSA_Params(object):
    def __init__(self, a, b, p, P_x, P_y, q):
        self.p = p
        self.q = q
        self.curve = Curve(a, b, p, P_x, P_y, q)
        self.P = Point(self.curve, P_x, P_y)


def KeyGen(params):
    # Write a function that takes as input an ECDSA_Params object and outputs the key pair (x, Q)
    x = random.randrange(1, params.q)
    pub = params.P.scalar_multiply(x)
    return (x, pub)

def Sign_FixedNonce(params, k, x, msg):
    # Write a function that takes as input an ECDSA_Params object, a fixed nonce k, a signing key x, and a message msg, and outputs a signature (r, s)
    h = hash_message_to_bits(msg)
    h, pPrm = bits_to_int(h, params.q), params.P.scalar_multiply(k)
    r = pPrm.x % params.q
    s = (mod_inv(k, params.q) * (h + x * r)) % params.q
    return (r, s)

def Sign(params, x, msg):
    # Write a function that takes as input an ECDSA_Params object, a signing key x, and a message msg, and outputs a signature (r, s)
    # The nonce is to be generated uniformly at random in the appropriate range
    k = random.randrange(1, params.q)
    return Sign_FixedNonce(params, k, x, msg)

def Verify(params, Q, msg, r, s):
    # Write a function that takes as input an ECDSA_Params object, a verification key Q, a message msg, and a signature (r, s)
    # The output should be either 0 (indicating failure) or 1 (indicating success)
    #if r < 1 or r > params.q - 1 or s < 1 or s > params.q or not isinstance(r, int) or not isinstance(s, int):
    if r < 1 or r > params.q - 1 or s < 1 or s > params.q:
        return 0
    w, h = mod_inv(s, params.q) % params.q, hash_message_to_bits(msg)
    h = bits_to_int(h, params.q)
    u1, u2 = (w * h) % params.q, (w * r) % params.q
    z = params.P.scalar_multiply(u1)
    z = z.add(Q.scalar_multiply(u2))
    if z.x % params.q == r:
        return 1
    else:
        return 0

from module_1_ECC_ECDSA_tests import run_tests
run_tests(ECDSA_Params, Point, KeyGen, Sign, Sign_FixedNonce, Verify)
