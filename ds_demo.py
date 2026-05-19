"""
ds_demo.py — Демонстрация цифровой подписи (ЭЦП) RSA между двумя сторонами.

Графическая визуализация протокола «Вызов-Ответ» (Challenge-Response):
  1) Генерация ключей: каждая сторона генерирует свою пару RSA-ключей (e, d, n).
  2) Обмен открытыми ключами: Сервер и Клиент посылают друг другу (e, n).
  3) Сервер отправляет случайный challenge → Клиент подписывает его
     своим секретным ключом d → Сервер проверяет подпись открытым ключом Клиента.
  4) Клиент отправляет запрос → Сервер подписывает ответ своим d →
     Клиент проверяет подпись открытым ключом Сервера.

Все криптографические операции реализованы вручную (без библиотек):
  - Миллера-Рабин для генерации простых чисел
  - Алгоритм Евклида для НОД
  - Расширенный алгоритм Евклида для обратного по модулю
"""

import tkinter as tk
from tkinter import ttk, font as tkfont
import random


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Обратного элемента не существует")
    return x % phi


def miller_rabin(n, k=20):
    if n < 2:
        return False
    if n in (2, 3):
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
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = mod_inverse(e, phi)
    return {'e': e, 'd': d, 'n': n, 'p': p, 'q': q}


def rsa_sign(message, d, n):
    return pow(message, d, n)


def rsa_verify(signature, e, n):
    return pow(signature, e, n)


COLORS = {
    'bg': '#1a1a2e',
    'panel': '#16213e',
    'accent': '#0f3460',
    'server': '#e94560',
    'client': '#00b4d8',
    'success': '#2ecc71',
    'fail': '#e74c3c',
    'arrow_send': '#f39c12',
    'arrow_recv': '#9b59b6',
    'text': '#ecf0f1',
    'dim': '#7f8c8d',
    'highlight': '#f1c40f',
}


class DSDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("Демонстрация ЭЦП RSA — Вызов-Ответ (Challenge-Response)")
        self.root.configure(bg=COLORS['bg'])
        self.root.geometry("1280x800")
        self.root.minsize(1100, 700)

        self.server_keys = None
        self.client_keys = None
        self.challenge = None
        self.client_signature = None
        self.server_response = None
        self.server_signature = None
        self.step = 0

        self._build_ui()

    def _build_ui(self):
        bold = tkfont.Font(family='Consolas', size=11, weight='bold')
        title_font = tkfont.Font(family='Consolas', size=16, weight='bold')
        step_font = tkfont.Font(family='Consolas', size=10, weight='bold')
        small_font = tkfont.Font(family='Consolas', size=9)
        key_font = tkfont.Font(family='Consolas', size=9)

        title = tk.Label(self.root, text="Электронная цифровая подпись (ЭЦП) RSA",
                         font=title_font, bg=COLORS['bg'], fg=COLORS['highlight'])
        title.pack(pady=(8, 0))

        subtitle = tk.Label(self.root, text="Протокол аутентификации «Вызов-Ответ» (Challenge-Response)",
                            font=bold, bg=COLORS['bg'], fg=COLORS['text'])
        subtitle.pack(pady=(0, 6))

        canvas_frame = tk.Frame(self.root, bg=COLORS['bg'])
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.canvas = tk.Canvas(canvas_frame, bg=COLORS['bg'], highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        bottom = tk.Frame(self.root, bg=COLORS['panel'], bd=2, relief=tk.RIDGE)
        bottom.pack(fill=tk.X, padx=10, pady=(0, 10))

        btn_row = tk.Frame(bottom, bg=COLORS['panel'])
        btn_row.pack(pady=8)

        self.btn_step = tk.Button(btn_row, text="▶ Следующий шаг", font=bold,
                                  bg=COLORS['accent'], fg='white', activebackground=COLORS['server'],
                                  command=self._next_step, width=20, height=2)
        self.btn_step.pack(side=tk.LEFT, padx=8)

        self.btn_reset = tk.Button(btn_row, text="⟲ Сброс", font=bold,
                                   bg='#636e72', fg='white', activebackground='#2d3436',
                                   command=self._reset, width=12, height=2)
        self.btn_reset.pack(side=tk.LEFT, padx=8)

        self.lbl_step = tk.Label(bottom, text="Шаг 0 / 7  —  Нажмите «Следующий шаг» для начала",
                                 font=step_font, bg=COLORS['panel'], fg=COLORS['dim'])
        self.lbl_step.pack(pady=(0, 4))

        self.lbl_status = tk.Label(bottom, text="", font=small_font,
                                   bg=COLORS['panel'], fg=COLORS['success'])
        self.lbl_status.pack(pady=(0, 6))

    def _draw_person(self, x, y, name, color, keys_text=""):
        c = self.canvas
        head_r = 22
        body_len = 50

        c.create_oval(x - head_r, y - head_r, x + head_r, y + head_r,
                      fill=color, outline='white', width=2)
        c.create_line(x, y + head_r, x, y + head_r + body_len,
                      fill=color, width=3)
        c.create_line(x - 30, y + head_r + 20, x + 30, y + head_r + 20,
                      fill=color, width=3)
        c.create_line(x, y + head_r + body_len, x - 25, y + head_r + body_len + 35,
                      fill=color, width=3)
        c.create_line(x, y + head_r + body_len, x + 25, y + head_r + body_len + 35,
                      fill=color, width=3)

        c.create_text(x, y - head_r - 14, text=name, fill=color,
                      font=('Consolas', 13, 'bold'))

        if keys_text:
            c.create_text(x, y + head_r + body_len + 60, text=keys_text,
                          fill=COLORS['text'], font=('Consolas', 9), justify=tk.CENTER,
                          width=300)

    def _draw_arrow(self, x1, y1, x2, y2, color, label="", sublabel=""):
        c = self.canvas
        c.create_line(x1, y1, x2, y2, fill=color, width=2, arrow=tk.LAST,
                      arrowshape=(12, 14, 5))
        mx = (x1 + x2) // 2
        my = (y1 + y2) // 2
        if label:
            c.create_text(mx, my - 14, text=label, fill=COLORS['highlight'],
                          font=('Consolas', 10, 'bold'))
        if sublabel:
            c.create_text(mx, my + 10, text=sublabel, fill=COLORS['dim'],
                          font=('Consolas', 8))

    def _draw_verification_box(self, x, y, text, color):
        c = self.canvas
        w = max(len(text) * 7 + 20, 280)
        h = 36
        c.create_rectangle(x - w // 2, y - h // 2, x + w // 2, y + h // 2,
                           fill=COLORS['panel'], outline=color, width=2)
        c.create_text(x, y, text=text, fill=color, font=('Consolas', 10, 'bold'))

    def _short(self, val):
        s = str(val)
        if len(s) > 18:
            return s[:9] + "..." + s[-6:]
        return s

    def _draw_scene(self):
        c = self.canvas
        c.delete("all")

        w = c.winfo_width()
        h = c.winfo_height()
        if w < 100:
            w = 1280
        if h < 100:
            h = 600

        sx = w // 4
        cx = 3 * w // 4
        py = 130

        server_label = "Сервер\n(Избирком)"
        client_label = "Клиент\n(Избиратель)"

        sk = ""
        ck = ""
        if self.server_keys:
            sk = (f"Закрытый ключ: d = {self._short(self.server_keys['d'])}\n"
                  f"Открытый ключ: (e = {self.server_keys['e']}, n = {self._short(self.server_keys['n'])})")
        if self.client_keys:
            ck = (f"Закрытый ключ: d = {self._short(self.client_keys['d'])}\n"
                  f"Открытый ключ: (e = {self.client_keys['e']}, n = {self._short(self.client_keys['n'])})")

        self._draw_person(sx, py, server_label, COLORS['server'], sk)
        self._draw_person(cx, py, client_label, COLORS['client'], ck)

        arrow_y1 = 260
        arrow_y2 = 260

        mid_x = (sx + cx) // 2
        verify_y = 420

        if self.step >= 1:
            self._draw_arrow(cx, arrow_y1, sx, arrow_y2, COLORS['arrow_send'],
                             "Открытый ключ (e, n)",
                             "Клиент → Сервер")

        if self.step >= 2:
            self._draw_arrow(sx, arrow_y1 + 40, cx, arrow_y2 + 40, COLORS['arrow_recv'],
                             "Открытый ключ (e, n)",
                             "Сервер → Клиент")

        if self.step >= 3:
            ch_text = f"Challenge = {self.challenge}"
            self._draw_arrow(sx, arrow_y1 + 80, cx, arrow_y2 + 80, COLORS['arrow_send'],
                             ch_text,
                             "Сервер → Клиент: случайный вызов")

        if self.step >= 4:
            sig_text = f"Signature = {self._short(self.client_signature)}"
            self._draw_arrow(cx, arrow_y1 + 120, sx, arrow_y2 + 120, COLORS['arrow_recv'],
                             sig_text,
                             "Клиент → Сервер: sig = challenge^d_client mod n_client")

        if self.step >= 5:
            verified = rsa_verify(self.client_signature, self.client_keys['e'], self.client_keys['n'])
            if verified == self.challenge:
                vcolor = COLORS['success']
                vtext = f"✓ Подпись верна: sig^e_client mod n_client = {verified} = challenge"
            else:
                vcolor = COLORS['fail']
                vtext = f"✗ Подпись НЕ верна: sig^e_client mod n_client ≠ challenge"
            self._draw_verification_box(mid_x, verify_y, vtext, vcolor)

        if self.step >= 6:
            resp_text = f"Response = {self.server_response}"
            sig_text2 = f"Sig = {self._short(self.server_signature)}"
            self._draw_arrow(sx, arrow_y1 + 160, cx, arrow_y2 + 160, COLORS['arrow_send'],
                             f"{resp_text}  |  {sig_text2}",
                             "Сервер → Клиент: sig = response^d_server mod n_server")

        if self.step >= 7:
            verified2 = rsa_verify(self.server_signature, self.server_keys['e'], self.server_keys['n'])
            if verified2 == self.server_response:
                vcolor2 = COLORS['success']
                vtext2 = f"✓ Подпись сервера верна: sig^e_server mod n_server = {verified2} = response"
            else:
                vcolor2 = COLORS['fail']
                vtext2 = f"✗ Подпись сервера НЕ верна"
            self._draw_verification_box(mid_x, verify_y + 50, vtext2, vcolor2)

        legend_y = h - 60
        c.create_text(mid_x, legend_y,
                      text="Синяя стрелка ← Сервер отправляет    |    Фиолетовая стрелка ← Клиент отправляет",
                      fill=COLORS['dim'], font=('Consolas', 9))
        c.create_text(mid_x, legend_y + 18,
                      text="Подпись: sig = message^d mod n  |  Проверка: sig^e mod n == message",
                      fill=COLORS['dim'], font=('Consolas', 9))

    def _next_step(self):
        if self.step == 0:
            self.server_keys = generate_rsa_keys(bits=256)
            self.client_keys = generate_rsa_keys(bits=256)
            self.step = 1
            self.lbl_status.config(text="Ключи сгенерированы. Клиент отправляет свой открытый ключ Серверу.",
                                   fg=COLORS['success'])
            self.lbl_step.config(text="Шаг 1 / 7  —  Клиент → Сервер: отправка открытого ключа (e, n)")

        elif self.step == 1:
            self.step = 2
            self.lbl_status.config(text="Сервер отправляет свой открытый ключ Клиенту.",
                                   fg=COLORS['success'])
            self.lbl_step.config(text="Шаг 2 / 7  —  Сервер → Клиент: отправка открытого ключа (e, n)")

        elif self.step == 2:
            self.challenge = random.randrange(1000, 999999)
            self.step = 3
            self.lbl_status.config(text="Сервер генерирует случайный challenge и отправляет Клиенту.",
                                   fg=COLORS['arrow_send'])
            self.lbl_step.config(text="Шаг 3 / 7  —  Сервер → Клиент: случайный challenge")

        elif self.step == 3:
            self.client_signature = rsa_sign(self.challenge, self.client_keys['d'], self.client_keys['n'])
            self.step = 4
            self.lbl_status.config(
                text=f"Клиент подписывает challenge: sig = challenge^d_client mod n_client = {self._short(self.client_signature)}",
                fg=COLORS['arrow_recv'])
            self.lbl_step.config(text="Шаг 4 / 7  —  Клиент → Сервер: подпись challenge")

        elif self.step == 4:
            verified = rsa_verify(self.client_signature, self.client_keys['e'], self.client_keys['n'])
            if verified == self.challenge:
                self.step = 5
                self.lbl_status.config(
                    text=f"✓ Подпись Клиента проверена: sig^e_client mod n_client = {verified} = challenge",
                    fg=COLORS['success'])
                self.lbl_step.config(text="Шаг 5 / 7  —  Сервер проверяет подпись Клиента")
            else:
                self.step = 5
                self.lbl_status.config(text="✗ Подпись НЕ верна!", fg=COLORS['fail'])
                self.lbl_step.config(text="Шаг 5 / 7  —  Проверка подписи: ОШИБКА")

        elif self.step == 5:
            self.server_response = random.randrange(1000, 999999)
            self.server_signature = rsa_sign(self.server_response, self.server_keys['d'], self.server_keys['n'])
            self.step = 6
            self.lbl_status.config(
                text=f"Сервер подписывает ответ: sig = response^d_server mod n_server = {self._short(self.server_signature)}",
                fg=COLORS['arrow_send'])
            self.lbl_step.config(text="Шаг 6 / 7  —  Сервер → Клиент: подписанный ответ")

        elif self.step == 6:
            verified2 = rsa_verify(self.server_signature, self.server_keys['e'], self.server_keys['n'])
            if verified2 == self.server_response:
                self.step = 7
                self.lbl_status.config(
                    text=f"✓ Подпись Сервера проверена: sig^e_server mod n_server = {verified2} = response. Аутентификация обоюдная!",
                    fg=COLORS['success'])
                self.lbl_step.config(text="Шаг 7 / 7  —  Клиент проверяет подпись Сервера — ГОТОВО")
            else:
                self.step = 7
                self.lbl_status.config(text="✗ Подпись сервера НЕ верна!", fg=COLORS['fail'])
                self.lbl_step.config(text="Шаг 7 / 7  —  Проверка подписи: ОШИБКА")

        elif self.step >= 7:
            self.lbl_status.config(text="Демонстрация завершена. Нажмите «Сброс» для повтора.",
                                   fg=COLORS['highlight'])
            return

        self._draw_scene()

    def _reset(self):
        self.server_keys = None
        self.client_keys = None
        self.challenge = None
        self.client_signature = None
        self.server_response = None
        self.server_signature = None
        self.step = 0
        self.lbl_step.config(text="Шаг 0 / 7  —  Нажмите «Следующий шаг» для начала")
        self.lbl_status.config(text="", fg=COLORS['success'])
        self._draw_scene()


if __name__ == '__main__':
    root = tk.Tk()
    app = DSDemo(root)
    root.update_idletasks()
    root.after(100, app._draw_scene)
    root.mainloop()
