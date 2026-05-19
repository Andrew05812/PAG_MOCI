"""
ds_demo_server.py — Серверная часть демонстрации ЭЦП RSA по сети.

Запуск: python ds_demo_server.py [порт]

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


_server_lcg = LCG()


class DSDemoServer:
    def __init__(self, root, port=9000):
        self.root = root
        self.root.title("Демонстрация ЭЦП — Сервер")
        self.root.geometry("750x650")
        self.root.configure(bg='#1a1a2e')

        self.port = port
        self.keys = None
        self.client_pub_e = None
        self.client_pub_n = None
        self.challenge = None
        self.server_sig = None
        self.server_response = None
        self.sock = None
        self.conn = None
        self.receiver = None
        self.q = queue.Queue()
        self.connected = False

        self._build_ui()
        self._poll()

    def _build_ui(self):
        top = tk.Frame(self.root, bg='#1a1a2e')
        top.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(top, text="СЕРВЕР (Сторона А)", font=('Consolas', 14, 'bold'),
                 bg='#1a1a2e', fg='#e94560').pack()

        conn_frame = tk.LabelFrame(self.root, text="Подключение", font=('Consolas', 10, 'bold'),
                                   bg='#16213e', fg='#ecf0f1', bd=2)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)

        row = tk.Frame(conn_frame, bg='#16213e')
        row.pack(pady=5, padx=5, fill=tk.X)

        tk.Label(row, text="Порт:", bg='#16213e', fg='#ecf0f1',
                 font=('Consolas', 10)).pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value=str(self.port))
        tk.Entry(row, textvariable=self.port_var, width=8,
                 font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        tk.Button(row, text="Запустить сервер", font=('Consolas', 10, 'bold'),
                  bg='#0f3460', fg='white', command=self._start_server).pack(side=tk.LEFT, padx=10)

        self.lbl_conn = tk.Label(conn_frame, text="Ожидание запуска...", bg='#16213e',
                                 fg='#f39c12', font=('Consolas', 10))
        self.lbl_conn.pack(pady=3)

        keys_frame = tk.LabelFrame(self.root, text="Ключи RSA сервера", font=('Consolas', 10, 'bold'),
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

        self._log("Готов к запуску. Нажмите «Запустить сервер».")

    def _log(self, text, tag=None):
        self.q.put(lambda: self._log_safe(text, tag))

    def _log_safe(self, text, tag=None):
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

    def _start_server(self):
        self.port = int(self.port_var.get())
        self.keys = generate_rsa_keys(256)
        self.lbl_keys.config(
            text=(f"Открытый ключ:  e = {self.keys['e']},  n = {self._short(self.keys['n'])}\n"
                  f"Секретный ключ:  d = {self._short(self.keys['d'])}"),
            fg='#2ecc71')
        self._log(f"Ключи RSA сгенерированы (256 бит)")
        self._log(f"  e = {self.keys['e']},  n = {self._short(self.keys['n'])}")

        t = threading.Thread(target=self._listen, daemon=True)
        t.start()

    def _listen(self):
        self._schedule(lambda: self.lbl_conn.config(
            text=f"Слушаю порт {self.port} ...", fg='#f39c12'))
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('0.0.0.0', self.port))
            self.sock.listen(1)
            self._log(f"Сервер слушает порт {self.port}, ожидание клиента...")
            self.conn, addr = self.sock.accept()
            self.connected = True
            self._schedule(lambda: self.lbl_conn.config(
                text=f"Клиент подключён: {addr[0]}:{addr[1]}", fg='#2ecc71'))
            self._log(f"Клиент подключён: {addr[0]}:{addr[1]}")

            send_msg(self.conn, {'type': 'server_pubkey',
                                 'e': self.keys['e'], 'n': self.keys['n']})
            self._log(f"→ Отправлен открытый ключ сервера клиенту: e={self.keys['e']}, n={self._short(self.keys['n'])}")

            self.receiver = MsgReceiver(self.conn)
            self._recv_loop()
        except Exception as ex:
            self._log(f"Ошибка: {ex}")

    def _recv_loop(self):
        while self.connected:
            msg = self.receiver.recv()
            if msg is None:
                self._log("Клиент отключился.")
                self.connected = False
                break
            self._handle(msg)

    def _handle(self, msg):
        t = msg.get('type')

        if t == 'client_pubkey':
            self.client_pub_e = msg['e']
            self.client_pub_n = msg['n']
            self._log(f"← Получен открытый ключ клиента: e={self.client_pub_e}, n={self._short(self.client_pub_n)}")
            self._log(f"  Обмен ключами завершён!")

            self.challenge = _server_lcg.getrandbits(128)
            self._log(f"→ Генерация challenge: {self._short(self.challenge)}")
            send_msg(self.conn, {'type': 'challenge', 'challenge': self.challenge})
            self._log(f"→ Challenge отправлен клиенту")

        elif t == 'client_signature':
            sig = msg['signature']
            self._log(f"← Получена подпись клиента: sig = {self._short(sig)}")
            self._log(f"  Проверка: sig^e_client mod n_client")
            verified = pow(sig, self.client_pub_e, self.client_pub_n)
            if verified == self.challenge:
                self._log(f"  ✓ ПОДПИСЬ ВЕРНА: sig^e_client mod n_client = {self._short(verified)} = challenge")
                self._log(f"  Аутентификация клиента успешна!")

                self.server_response = _server_lcg.getrandbits(128)
                self.server_sig = pow(self.server_response, self.keys['d'], self.keys['n'])
                self._log(f"→ Генерация ответа: response = {self._short(self.server_response)}")
                self._log(f"→ Подпись ответа: sig = response^d_server mod n_server = {self._short(self.server_sig)}")
                send_msg(self.conn, {'type': 'server_signed_response',
                                     'response': self.server_response,
                                     'signature': self.server_sig})
                self._log(f"→ Подписанный ответ отправлен клиенту")
            else:
                self._log(f"  ✗ ПОДПИСЬ НЕ ВЕРНА: sig^e_client mod n_client = {self._short(verified)} ≠ challenge")
                self._log(f"  Аутентификация ОТКЛОНЕНА!")

        elif t == 'verification_result':
            ok = msg.get('success', False)
            if ok:
                self._log(f"← Клиент подтвердил: подпись сервера ВЕРНА")
                self._log(f"═══════════════════════════════════════")
                self._log(f"  Взаимная аутентификация успешно завершена!")
                self._log(f"═══════════════════════════════════════")
            else:
                self._log(f"← Клиент: подпись сервера НЕ верна!")

        else:
            self._log(f"← Неизвестное сообщение: {t}")


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    root = tk.Tk()
    app = DSDemoServer(root, port)
    root.mainloop()
