import tkinter as tk
from tkinter import ttk
import socket
import threading
import queue
import random
from shared import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    send_msg, MsgReceiver
)


class VotingServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Избирком — Центр электронного голосования")
        self.root.geometry("1150x880")
        self.root.minsize(950, 700)

        self.center_keys = None
        self.registered_voters = {}
        self.received_ballots = {}
        self.client_sockets = {}
        self.client_threads = {}

        self.counting_done = False
        self.count_r = None
        self.count_P = None
        self.count_R = None
        self.count_F = None

        self.server_socket = None
        self.running = False
        self.q = queue.Queue()

        self._build_gui()
        self._poll()

    def _poll(self):
        while not self.q.empty():
            fn = self.q.get_nowait()
            try:
                fn()
            except tk.TclError:
                pass
        self.root.after(50, self._poll)

    def _schedule(self, fn):
        self.q.put(fn)

    def _txt(self, parent, height=8):
        f = ttk.Frame(parent)
        f.pack(fill=tk.BOTH, expand=True, padx=3, pady=2)
        t = tk.Text(f, height=height, wrap=tk.WORD, font=('Consolas', 9))
        sb = ttk.Scrollbar(f, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        return t

    def _log(self, w, msg):
        def _do():
            w.insert(tk.END, msg + "\n")
            w.see(tk.END)
        self._schedule(_do)

    def _build_gui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # --- Tab 1: Setup ---
        t1 = ttk.Frame(nb)
        nb.add(t1, text=" Настройка и регистрация ")

        sf = ttk.LabelFrame(t1, text="Настройки сервера")
        sf.pack(fill=tk.X, padx=5, pady=5)

        row1 = ttk.Frame(sf)
        row1.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(row1, text="IP:").pack(side=tk.LEFT)
        self.ip_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(row1, textvariable=self.ip_var, width=14).pack(side=tk.LEFT, padx=3)
        ttk.Label(row1, text="Порт:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="9999")
        ttk.Entry(row1, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=3)
        ttk.Button(row1, text="Запустить сервер", command=self._start_server).pack(side=tk.LEFT, padx=8)
        ttk.Button(row1, text="Остановить", command=self._stop_server).pack(side=tk.LEFT, padx=3)
        self.srv_status = ttk.Label(row1, text="Сервер не запущен", foreground='red')
        self.srv_status.pack(side=tk.LEFT, padx=10)

        kf = ttk.LabelFrame(t1, text="Ключи избиркома")
        kf.pack(fill=tk.X, padx=5, pady=5)
        kr = ttk.Frame(kf)
        kr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(kr, text="Сгенерировать ключи RSA (1024 бит)", command=self._gen_keys).pack(side=tk.LEFT, padx=3)
        self.key_status = ttk.Label(kr, text="Ключи не сгенерированы", foreground='red')
        self.key_status.pack(side=tk.LEFT, padx=10)
        self.key_log = self._txt(kf, height=6)

        rf = ttk.LabelFrame(t1, text="Зарегистрированные избиратели")
        rf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        cols = ("ID", "Открытый ключ e", "Открытый ключ n", "Статус")
        self.voter_tree = ttk.Treeview(rf, columns=cols, show='headings', height=6)
        for c in cols:
            self.voter_tree.heading(c, text=c)
            self.voter_tree.column(c, width=180 if c != "ID" else 50)
        self.voter_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self.reg_log = self._txt(rf, height=6)

        # --- Tab 2: Voting ---
        t2 = ttk.Frame(nb)
        nb.add(t2, text=" Голосование ")

        bf = ttk.LabelFrame(t2, text="Таблица зашифрованных бюллетеней (публикация)")
        bf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        bcols = ("ID избирателя", "fi (зашифрованный бюллетень)")
        self.ballot_tree = ttk.Treeview(bf, columns=bcols, show='headings', height=6)
        for c in bcols:
            self.ballot_tree.heading(c, text=c)
            self.ballot_tree.column(c, width=400)
        self.ballot_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self.vote_log = self._txt(t2, height=8)

        # --- Tab 3: Counting ---
        t3 = ttk.Frame(nb)
        nb.add(t3, text=" Подсчёт и проверка ")

        cr = ttk.Frame(t3)
        cr.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(cr, text="Подсчитать голоса", command=self._count_votes).pack(side=tk.LEFT, padx=5)
        self.cnt_status = ttk.Label(cr, text="Ожидание", foreground='red')
        self.cnt_status.pack(side=tk.LEFT, padx=10)

        self.cnt_log = self._txt(t3, height=20)

    # ==================== Server controls ====================

    def _start_server(self):
        if self.running:
            self._log(self.vote_log, "Сервер уже запущен!")
            return
        if self.center_keys is None:
            self._log(self.vote_log, "ОШИБКА: Сначала сгенерируйте ключи избиркома!")
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            self._log(self.vote_log, "ОШИБКА: Неверный номер порта!")
            return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.ip_var.get(), port))
        except OSError as e:
            self._log(self.vote_log, f"ОШИБКА привязки: {e}")
            return
        self.server_socket.listen(10)
        self.running = True
        self.srv_status.configure(text=f"Сервер работает :{port}", foreground='green')
        self._log(self.vote_log, f"Сервер запущен на {self.ip_var.get()}:{port}")

        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _stop_server(self):
        self.running = False
        for s in self.client_sockets.values():
            try:
                s.close()
            except OSError:
                pass
        self.client_sockets.clear()
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.srv_status.configure(text="Сервер остановлен", foreground='red')

    def _accept_loop(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            cid = f"{addr[0]}:{addr[1]}"
            self.client_sockets[cid] = conn
            self._log(self.vote_log, f"Подключение: {cid}")
            try:
                send_msg(conn, {
                    'type': 'center_key',
                    'e': self.center_keys['e'],
                    'n': self.center_keys['n']
                })
            except (ConnectionError, OSError):
                continue
            t = threading.Thread(target=self._handle_client, args=(conn, cid), daemon=True)
            self.client_threads[cid] = t
            t.start()

    def _handle_client(self, conn, cid):
        recv = MsgReceiver(conn)
        while self.running:
            try:
                msg = recv.recv()
            except Exception:
                break
            if msg is None:
                self._log(self.vote_log, f"Отключение: {cid}")
                break
            self._dispatch(msg, conn, cid)
        try:
            conn.close()
        except OSError:
            pass
        self.client_sockets.pop(cid, None)

    def _dispatch(self, msg, conn, cid):
        t = msg.get('type')
        if t == 'register':
            self._on_register(msg, conn)
        elif t == 'signature':
            self._on_signature(msg, conn)
        elif t == 'vote_request':
            self._on_vote_request(msg, conn)
        elif t == 'vote_response':
            self._on_vote_response(msg, conn)
        elif t == 'get_table':
            self._on_get_table(conn)
        elif t == 'get_results':
            self._on_get_results(conn)

    # ==================== Registration ====================

    def _on_register(self, msg, conn):
        vid = msg['voter_id']
        pub_e = msg['pub_e']
        pub_n = msg['pub_n']

        self._log(self.reg_log, f"--- Запрос регистрации от избирателя {vid} ---")

        if vid in self.registered_voters:
            self._log(self.reg_log, f"  ОТКАЗ: Избиратель {vid} уже зарегистрирован!")
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': f'Избиратель {vid} уже зарегистрирован!'})
            except (ConnectionError, OSError):
                pass
            return

        challenge = random.getrandbits(128)
        self.registered_voters[vid] = {
            'pub_e': pub_e, 'pub_n': pub_n,
            'challenge': challenge, 'authenticated': False
        }

        self._log(self.reg_log, f"  Получен открытый ключ: e={pub_e}, n={pub_n}")
        self._log(self.reg_log, f"  Отправлен вызов (challenge): {challenge}")

        try:
            send_msg(conn, {'type': 'challenge', 'challenge': challenge})
        except (ConnectionError, OSError):
            pass

    def _on_signature(self, msg, conn):
        vid = msg['voter_id']
        signature = msg['signature']

        if vid not in self.registered_voters:
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': 'Избиратель не найден!'})
            except (ConnectionError, OSError):
                pass
            return

        info = self.registered_voters[vid]
        challenge = info['challenge']
        pub_e = info['pub_e']
        pub_n = info['pub_n']

        self._log(self.reg_log, f"--- Проверка подписи избирателя {vid} ---")
        self._log(self.reg_log, f"  signature = {signature}")

        verified = rsa_encrypt(signature, pub_e, pub_n) == challenge
        self._log(self.reg_log, f"  signature^e mod n = {rsa_encrypt(signature, pub_e, pub_n)}")
        self._log(self.reg_log, f"  challenge        = {challenge}")
        self._log(self.reg_log, f"  Результат: {'УСПЕШНО' if verified else 'НЕУДАЧА'}")

        if verified:
            info['authenticated'] = True
            self._update_voter_tree(vid, pub_e, pub_n, "Зарегистрирован ✓")
        else:
            del self.registered_voters[vid]
            self._update_voter_tree(vid, pub_e, pub_n, "Ошибка аутентификации ✗")

        try:
            send_msg(conn, {'type': 'auth_result', 'success': verified,
                            'message': 'Аутентификация успешна!' if verified else
                            'Аутентификация не пройдена! Подпись неверна.'})
        except (ConnectionError, OSError):
            pass

    # ==================== Voting ====================

    def _on_vote_request(self, msg, conn):
        vid = msg['voter_id']

        self._log(self.vote_log, f"--- Запрос голосования от избирателя {vid} ---")

        if vid not in self.registered_voters:
            self._log(self.vote_log, f"  ОТКАЗ: Избиратель {vid} не зарегистрирован!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': f'Избиратель {vid} не зарегистрирован!'})
            except (ConnectionError, OSError):
                pass
            return

        if not self.registered_voters[vid]['authenticated']:
            self._log(self.vote_log, f"  ОТКАЗ: Аутентификация не пройдена!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Аутентификация не пройдена!'})
            except (ConnectionError, OSError):
                pass
            return

        if vid in self.received_ballots:
            self._log(self.vote_log, f"  ОТКАЗ: Избиратель {vid} уже проголосовал! Двойное голосование!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': f'Избиратель {vid} уже голосовал! Двойное голосование!'})
            except (ConnectionError, OSError):
                pass
            return

        challenge = random.getrandbits(128)
        self.registered_voters[vid]['vote_challenge'] = challenge

        self._log(self.vote_log, f"  Аутентификация: отправлен вызов {challenge}")

        try:
            send_msg(conn, {'type': 'vote_challenge', 'challenge': challenge})
        except (ConnectionError, OSError):
            pass

    def _on_vote_response(self, msg, conn):
        vid = msg['voter_id']
        signature = msg['signature']
        fi = msg['fi']

        if vid not in self.registered_voters:
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Избиратель не найден!'})
            except (ConnectionError, OSError):
                pass
            return

        info = self.registered_voters[vid]
        challenge = info.get('vote_challenge')
        if challenge is None:
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Нет активного запроса!'})
            except (ConnectionError, OSError):
                pass
            return

        pub_e = info['pub_e']
        pub_n = info['pub_n']

        self._log(self.vote_log, f"--- Проверка подписи при голосовании (избиратель {vid}) ---")
        self._log(self.vote_log, f"  signature = {signature}")

        verified = rsa_encrypt(signature, pub_e, pub_n) == challenge
        self._log(self.vote_log, f"  signature^e mod n = {rsa_encrypt(signature, pub_e, pub_n)}")
        self._log(self.vote_log, f"  challenge        = {challenge}")
        self._log(self.vote_log, f"  Результат: {'УСПЕШНО' if verified else 'НЕУДАЧА'}")

        if verified:
            if vid in self.received_ballots:
                self._log(self.vote_log, f"  ОТКАЗ: Двойное голосование!")
                try:
                    send_msg(conn, {'type': 'vote_result', 'success': False,
                                    'message': 'Двойное голосование!'})
                except (ConnectionError, OSError):
                    pass
                return

            self.received_ballots[vid] = fi
            self._log(self.vote_log, f"  Бюллетень принят: fi = {fi}")
            self._update_ballot_tree()

            try:
                send_msg(conn, {'type': 'vote_result', 'success': True,
                                'message': 'Голос принят!'})
            except (ConnectionError, OSError):
                pass
        else:
            self._log(self.vote_log, f"  ОТКАЗ: Аутентификация не пройдена! Голос отклонён.")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Аутентификация не пройдена! Подпись неверна.'})
            except (ConnectionError, OSError):
                pass

        info.pop('vote_challenge', None)

    # ==================== Table & Results ====================

    def _on_get_table(self, conn):
        ballots = [[vid, fi] for vid, fi in sorted(self.received_ballots.items())]
        try:
            send_msg(conn, {
                'type': 'table',
                'ballots': ballots,
                'center_e': self.center_keys['e'],
                'center_n': self.center_keys['n']
            })
        except (ConnectionError, OSError):
            pass

    def _on_get_results(self, conn):
        if not self.counting_done:
            try:
                send_msg(conn, {'type': 'error', 'message': 'Подсчёт ещё не выполнен!'})
            except (ConnectionError, OSError):
                pass
            return
        ballots = [[vid, fi] for vid, fi in sorted(self.received_ballots.items())]
        try:
            send_msg(conn, {
                'type': 'results',
                'r': self.count_r,
                'P': self.count_P,
                'R': self.count_R,
                'F': self.count_F,
                'ballots': ballots,
                'center_e': self.center_keys['e'],
                'center_n': self.center_keys['n']
            })
        except (ConnectionError, OSError):
            pass

    # ==================== Counting ====================

    def _count_votes(self):
        w = self.cnt_log
        if self.center_keys is None:
            self._log(w, "ОШИБКА: Ключи избиркома не сгенерированы!")
            return
        if not self.received_ballots:
            self._log(w, "ОШИБКА: Нет бюллетеней!")
            return

        self._schedule(lambda: w.delete('1.0', tk.END))

        n_c = self.center_keys['n']
        d_c = self.center_keys['d']
        e_c = self.center_keys['e']

        self._log(w, "=== Подсчёт голосов ===\n")

        self._log(w, "Шаг 1: F = произведение всех fi mod n")
        F = 1
        for vid, fi in sorted(self.received_ballots.items()):
            self._log(w, f"  fi({vid}) = {fi}")
            F = (F * fi) % n_c
        self.count_F = F
        self._log(w, f"\n  F = {F}\n")

        self._log(w, "Шаг 2: Q = F^d mod n  (расшифровка секретным ключом)")
        Q = rsa_decrypt(F, d_c, n_c)
        self._log(w, f"  Q = {Q}\n")

        self._log(w, "Шаг 3: Факторизация Q = 2^r * 3^P * R")
        temp = Q
        r = 0
        while temp > 0 and temp % 2 == 0:
            r += 1
            temp //= 2
        P = 0
        while temp > 0 and temp % 3 == 0:
            P += 1
            temp //= 3
        R = temp

        self.count_r = r
        self.count_P = P
        self.count_R = R
        self.counting_done = True

        N = len(self.received_ballots)
        abstained = N - r - P

        self._log(w, f"  r (За)           = {r}")
        self._log(w, f"  P (Против)       = {P}")
        self._log(w, f"  Воздержались     = {abstained}")
        self._log(w, f"  R (контрольное)  = {R}")
        self._log(w, f"  R % 2 == 0? {R % 2 == 0}")
        self._log(w, f"  R % 3 == 0? {R % 3 == 0}")

        self._log(w, f"\nПроверка: 2^{r} * 3^{P} * {R} = {(2 ** r) * (3 ** P) * R}")
        self._log(w, f"Q = {Q}")
        self._log(w, f"Совпадение: {((2 ** r) * (3 ** P) * R) == Q}\n")

        self._log(w, "=" * 50)
        self._log(w, "         РЕЗУЛЬТАТЫ ГОЛОСОВАНИЯ")
        self._log(w, "=" * 50)
        self._log(w, f"  За:            {r}")
        self._log(w, f"  Против:        {P}")
        self._log(w, f"  Воздержались:  {abstained}")
        self._log(w, f"  Контрольное R: {R}")
        self._log(w, "=" * 50)

        self._schedule(lambda: self.cnt_status.configure(
            text="Подсчёт выполнен ✓", foreground='green'))

    # ==================== Key generation ====================

    def _gen_keys(self):
        self._log(self.key_log, "Генерация RSA-ключей избиркома (1024 бит)...")
        self.root.update()
        self.center_keys = generate_rsa_keys(1024)
        self._log(self.key_log, f"Открытый ключ: e={self.center_keys['e']}")
        self._log(self.key_log, f"  n={self.center_keys['n']}")
        self._log(self.key_log, f"Секретный ключ: d={self.center_keys['d']}")
        self._log(self.key_log, f"  n={self.center_keys['n']}")
        self._schedule(lambda: self.key_status.configure(
            text="Ключи сгенерированы ✓", foreground='green'))

    # ==================== Tree updates ====================

    def _update_voter_tree(self, vid, pub_e, pub_n, status):
        def _do():
            self.voter_tree.insert('', tk.END, values=(vid, pub_e, pub_n, status))
        self._schedule(_do)

    def _update_ballot_tree(self):
        def _do():
            for item in self.ballot_tree.get_children():
                self.ballot_tree.delete(item)
            for vid, fi in sorted(self.received_ballots.items()):
                self.ballot_tree.insert('', tk.END, values=(vid, fi))
        self._schedule(_do)


if __name__ == "__main__":
    import sys
    root = tk.Tk()
    app = VotingServer(root)
    if "--auto" in sys.argv:
        app._gen_keys()
        root.update()
        app._start_server()
    root.mainloop()
