"""
ds_demo_client.py — Клиентская часть демонстрации ЭЦП RSA по сети.

Запуск: python ds_demo_client.py <IP_сервера> [порт]

Протокол «Вызов-Ответ» (Challenge-Response) между двумя компьютерами:
  1) Сервер и Клиент генерируют RSA-ключи
  2) Сервер отправляет свой открытый ключ (e, n) → Клиент
  3) Клиент отправляет свой открытый ключ (e, n) → Сервер
  4) Сервер генерирует challenge → Клиент
  5) Клиент подписывает challenge (sig = challenge^d_client mod n_client) → Сервер
  6) Сервер проверяет подпись: sig^e_client mod n_client == challenge
  7) Сервер подписывает ответ (sig = response^d_server mod n_server) → Клиент
  8) Клиент проверяет подпись сервера: sig^e_server mod n_server == response

Все криптографические операции и ГПСЧ реализованы вручную (без random, os.urandom).
"""

import tkinter as tk
from tkinter import ttk
import socket
import threading
import queue
from shared import generate_rsa_keys, LCG, send_msg, MsgReceiver


class DSDemoClient:
    def __init__(self, root, host='127.0.0.1', port=9000):
        self.root = root
        self.root.title("Демонстрация ЭЦП — Клиент")
        self.root.geometry("750x650")
        self.root.configure(bg='#1a1a2e')

        self.host = host
        self.port = port
        self.keys = None
        self.server_pub_e = None
        self.server_pub_n = None
        self.sock = None
        self.receiver = None
        self.q = queue.Queue()
        self.connected = False

        self._build_ui()
        self._poll()

    def _build_ui(self):
        top = tk.Frame(self.root, bg='#1a1a2e')
        top.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(top, text="КЛИЕНТ (Сторона Б)", font=('Consolas', 14, 'bold'),
                 bg='#1a1a2e', fg='#00b4d8').pack()

        conn_frame = tk.LabelFrame(self.root, text="Подключение", font=('Consolas', 10, 'bold'),
                                   bg='#16213e', fg='#ecf0f1', bd=2)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)

        row1 = tk.Frame(conn_frame, bg='#16213e')
        row1.pack(pady=3, padx=5, fill=tk.X)

        tk.Label(row1, text="IP сервера:", bg='#16213e', fg='#ecf0f1',
                 font=('Consolas', 10)).pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value=self.host)
        tk.Entry(row1, textvariable=self.host_var, width=16,
                 font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        tk.Label(row1, text="Порт:", bg='#16213e', fg='#ecf0f1',
                 font=('Consolas', 10)).pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value=str(self.port))
        tk.Entry(row1, textvariable=self.port_var, width=8,
                 font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        tk.Button(row1, text="Подключиться", font=('Consolas', 10, 'bold'),
                  bg='#0f3460', fg='white', command=self._connect).pack(side=tk.LEFT, padx=10)

        self.lbl_conn = tk.Label(conn_frame, text="Ожидание подключения...", bg='#16213e',
                                 fg='#f39c12', font=('Consolas', 10))
        self.lbl_conn.pack(pady=3)

        keys_frame = tk.LabelFrame(self.root, text="Ключи RSA клиента", font=('Consolas', 10, 'bold'),
                                   bg='#16213e', fg='#ecf0f1', bd=2)
        keys_frame.pack(fill=tk.X, padx=10, pady=5)

        self.lbl_keys = tk.Label(keys_frame, text="Ключи не сгенерированы", bg='#16213e',
                                 fg='#7f8c8d', font=('Consolas', 9), justify=tk.LEFT)
        self.lbl_keys.pack(pady=5, padx=5, anchor=tk.W)

        log_frame = tk.LabelFrame(self.root, text="Протокол ЭЦП (Журнал)", font=('Consolas', 10, 'bold'),
                                  bg='#16213e', fg='#ecf0f1', bd=2)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log = tk.Text(log_frame, bg='#0d1117', fg='#ecf0f1', font=('Consolas', 10),
                           wrap=tk.WORD, state=tk.DISABLED, bd=0)
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self._log("Готов к подключению. Укажите IP сервера и нажмите «Подключиться».")

    def _log(self, text):
        self.q.put(lambda: self._log_safe(text))

    def _log_safe(self, text):
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _schedule(self, fn):
        self.q.put(fn)

    def _poll(self):
        while not self.q.empty():
            try:
                fn = self.q.get_nowait()
                fn()
            except Exception:
                pass
        self.root.after(50, self._poll)

    def _short(self, val):
        s = str(val)
        if len(s) > 20:
            return s[:10] + "..." + s[-7:]
        return s

    def _connect(self):
        self.host = self.host_var.get()
        self.port = int(self.port_var.get())

        self.keys = generate_rsa_keys(256)
        self._schedule(lambda: self.lbl_keys.config(
            text=(f"Открытый ключ:  e = {self.keys['e']},  n = {self._short(self.keys['n'])}\n"
                  f"Секретный ключ:  d = {self._short(self.keys['d'])}"),
            fg='#2ecc71'))
        self._log(f"Ключи RSA сгенерированы (256 бит)")
        self._log(f"  e = {self.keys['e']},  n = {self._short(self.keys['n'])}")

        t = threading.Thread(target=self._do_connect, daemon=True)
        t.start()

    def _do_connect(self):
        try:
            self._schedule(lambda: self.lbl_conn.config(
                text=f"Подключение к {self.host}:{self.port} ...", fg='#f39c12'))
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.connected = True
            self._schedule(lambda: self.lbl_conn.config(
                text=f"Подключено к {self.host}:{self.port}", fg='#2ecc71'))
            self._log(f"Подключено к серверу {self.host}:{self.port}")

            self.receiver = MsgReceiver(self.sock)
            self._recv_loop()
        except Exception as ex:
            self._log(f"Ошибка подключения: {ex}")
            self._schedule(lambda: self.lbl_conn.config(
                text=f"Ошибка: {ex}", fg='#e74c3c'))

    def _recv_loop(self):
        while self.connected:
            msg = self.receiver.recv()
            if msg is None:
                self._log("Сервер отключился.")
                self.connected = False
                break
            self._handle(msg)

    def _handle(self, msg):
        t = msg.get('type')

        if t == 'server_pubkey':
            self.server_pub_e = msg['e']
            self.server_pub_n = msg['n']
            self._log(f"← Получен открытый ключ сервера: e={self.server_pub_e}, n={self._short(self.server_pub_n)}")

            send_msg(self.sock, {'type': 'client_pubkey',
                                 'e': self.keys['e'], 'n': self.keys['n']})
            self._log(f"→ Отправлен открытый ключ клиента серверу: e={self.keys['e']}, n={self._short(self.keys['n'])}")
            self._log(f"  Обмен ключами завершён!")

        elif t == 'challenge':
            challenge = msg['challenge']
            self._log(f"← Получен challenge от сервера: {self._short(challenge)}")

            sig = pow(challenge, self.keys['d'], self.keys['n'])
            self._log(f"→ Подпись challenge: sig = challenge^d_client mod n_client = {self._short(sig)}")

            send_msg(self.sock, {'type': 'client_signature', 'signature': sig})
            self._log(f"→ Подпись отправлена серверу")

        elif t == 'server_signed_response':
            response = msg['response']
            sig = msg['signature']
            self._log(f"← Получен подписанный ответ сервера:")
            self._log(f"   response = {self._short(response)}")
            self._log(f"   signature = {self._short(sig)}")
            self._log(f"  Проверка: sig^e_server mod n_server")

            verified = pow(sig, self.server_pub_e, self.server_pub_n)
            if verified == response:
                self._log(f"  ✓ ПОДПИСЬ СЕРВЕРА ВЕРНА: sig^e_server mod n_server = {self._short(verified)} = response")
                self._log(f"  Аутентификация сервера успешна!")
                self._log(f"═══════════════════════════════════════")
                self._log(f"  Взаимная аутентификация успешно завершена!")
                self._log(f"═══════════════════════════════════════")
                send_msg(self.sock, {'type': 'verification_result', 'success': True})
            else:
                self._log(f"  ✗ ПОДПИСЬ СЕРВЕРА НЕ ВЕРНА: sig^e_server mod n_server = {self._short(verified)} ≠ response")
                send_msg(self.sock, {'type': 'verification_result', 'success': False})

        else:
            self._log(f"← Неизвестное сообщение: {t}")


if __name__ == '__main__':
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
    root = tk.Tk()
    app = DSDemoClient(root, host, port)
    root.mainloop()
