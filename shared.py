import random
import math
import json
import socket
import threading


def miller_rabin(n, k=20):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


def generate_rsa_keys(bits=256):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = pow(e, -1, phi)
    return {'e': e, 'd': d, 'n': n, 'p': p, 'q': q}


def rsa_encrypt(message, e, n):
    return pow(message, e, n)


def rsa_decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)


def generate_random_prime_qi():
    while True:
        q = random.randint(5, 10000)
        if miller_rabin(q, 10):
            return q


def send_msg(sock, data):
    raw = json.dumps(data, separators=(',', ':')) + '\n'
    sock.sendall(raw.encode('utf-8'))


class MsgReceiver:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''

    def recv(self):
        while b'\n' not in self.buf:
            try:
                chunk = self.sock.recv(8192)
            except (ConnectionError, OSError):
                return None
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b'\n', 1)
        return json.loads(line.decode('utf-8'))
