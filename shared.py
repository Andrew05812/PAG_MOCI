"""
shared.py — Общие криптографические и сетевые утилиты для протокола электронного голосования.

Содержит:
- Ручной ГПСЧ (LCG — линейный конгруэнтный генератор) — БЕЗ библиотек random/os
- Тест Миллера-Рабина для проверки простоты чисел
- Генерацию RSA-ключей (для центра и избирателей)
- RSA шифрование/расшифрование
- Генерацию случайного простого qi для затенения бюллетеня
- Сетевые функции для отправки/приёма JSON-сообщений по TCP

ВСЯ генерация чисел реализована вручную — не используются random, os.urandom
или любые другие библиотечные ГСЧ.
"""

import json
import socket
import threading
import time


# ==============================================================================
# Ручной ГПСЧ — Линейный конгруэнтный генератор (LCG)
# ==============================================================================
# Формула: state = (a * state + c) mod m
# Параметры из Numerical Recipes (Knuth):
#   a = 6364136223846793005
#   c = 1442695040888963407
#   m = 2^64 (переполнение 64-битного целого)
# Начальное значение (seed) формируется из системного времени и ID потока
# ==============================================================================

class LCG:
    """Линейный конгруэнтный генератор псевдослучайных чисел (ручная реализация)."""

    _A = 6364136223846793005
    _C = 1442695040888963407
    _MOD = 1 << 64

    def __init__(self, seed=None):
        if seed is None:
            seed = (int(time.perf_counter_ns()) * 1000003
                    + threading.get_ident() * 1000000007) % self._MOD
        self._state = seed % self._MOD
        if self._state == 0:
            self._state = 1

    def next_int(self):
        """Следующее псевдослучайное целое (0 .. 2^64-1)."""
        self._state = (self._A * self._state + self._C) % self._MOD
        return self._state

    def getrandbits(self, bits):
        """Генерация псевдослучайного числа заданной битности."""
        result = 0
        remaining = bits
        while remaining > 0:
            chunk = min(remaining, 64)
            val = self.next_int()
            result = (result << chunk) | (val & ((1 << chunk) - 1))
            remaining -= chunk
        return result

    def randrange(self, lo, hi):
        """Псевдослучайное целое в диапазоне [lo, hi)."""
        if lo >= hi:
            raise ValueError("lo >= hi")
        span = hi - lo
        bit_len = span.bit_length()
        while True:
            val = self.getrandbits(bit_len)
            if val < span:
                return lo + val

    def randint(self, lo, hi):
        """Псевдослучайное целое в диапазоне [lo, hi]."""
        return self.randrange(lo, hi + 1)


_lcg = LCG()


def gcd(a, b):
    """Вычисление НОД(a,b) алгоритмом Евклида (без библиотек)."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Расширенный алгоритм Евклида: возвращает (g, x, y), где g=НОД(a,b) и a*x+b*y=g."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def mod_inverse(e, phi):
    """Вычисление обратного по модулю: d ≡ e^(-1) (mod phi) расширенным алгоритмом Евклида."""
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(f"Обратного элемента не существует: НОД({e},{phi})={g}")
    return x % phi


def miller_rabin(n, k=20):
    """Тест Миллера-Рабина: возвращает True если n вероятно простое, False если составное."""
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
        a = _lcg.randrange(2, n - 1)
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
    """Генерация случайного простого числа заданной битности (ручной ГПСЧ)."""
    while True:
        n = _lcg.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


# ==============================================================================
# Генерация RSA-ключей
# ==============================================================================
# RSA: n = p * q (модуль), phi = (p-1)(q-1) (функция Эйлера)
# Открытый ключ: (e, n) — для шифрования и проверки подписи
# Секретный ключ: (d, n) — для расшифрования и создания подписи
# e * d ≡ 1 (mod phi) — обратимость шифрования
# ==============================================================================

def generate_rsa_keys(bits=256):
    """
    Генерация пары RSA-ключей.
    Возвращает словарь: e (открытая экспонента), d (секретная), n (модуль), p, q.
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    return {'e': e, 'd': d, 'n': n, 'p': p, 'q': q}


# ==============================================================================
# RSA шифрование и расшифрование
# ==============================================================================
# Шифрование: c = m^e mod n (открытым ключом получателя)
# Расшифрование: m = c^d mod n (секретным ключом получателя)
# Создание подписи: s = m^d mod n (секретным ключом отправителя)
# Проверка подписи: m = s^e mod n (открытым ключом отправителя)
# ==============================================================================

def rsa_encrypt(message, e, n):
    """RSA шифрование / создание подписи: message^e mod n."""
    return pow(message, e, n)


def rsa_decrypt(ciphertext, d, n):
    """RSA расшифрование / проверка подписи: ciphertext^d mod n."""
    return pow(ciphertext, d, n)


# ==============================================================================
# Генерация qi — случайного простого числа >= 5 для затенения бюллетеня
# ==============================================================================
# Затенение: ti = b * qi, где b — голос (1, 2 или 3), qi — случайное простое >= 5
# Это скрывает конкретное значение голоса от центра при приёме бюллетеня
# (центр видит только fi = ti^e mod n и не может извлечь ti без d)
# ==============================================================================

def generate_random_prime_qi():
    """Генерация случайного простого числа qi из диапазона [5, 10000] (ручной ГПСЧ)."""
    while True:
        q = _lcg.randint(5, 10000)
        if miller_rabin(q, 10):
            return q


# ==============================================================================
# Сетевые утилиты — отправка и приём JSON-сообщений по TCP
# ==============================================================================
# Протокол: каждое сообщение — одна строка JSON, завершается символом \n
# Это позволяет разделять поток байтов на отдельные сообщения
# ==============================================================================

def send_msg(sock, data):
    """Отправка JSON-сообщения через TCP-сокет (одна строка + \\n)."""
    raw = json.dumps(data, separators=(',', ':')) + '\n'
    sock.sendall(raw.encode('utf-8'))


class MsgReceiver:
    """Приёмник JSON-сообщений по TCP. Буферизует данные и разбирает по символу \\n."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b''

    def recv(self):
        """Блокирующий приём одного JSON-сообщения. Возвращает dict или None при разрыве."""
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
