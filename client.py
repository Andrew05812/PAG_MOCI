import tkinter as tk
from tkinter import ttk
import socket
import threading
import queue
from shared import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    generate_random_prime_qi, send_msg, MsgReceiver
)


class VotingClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Избиратель — Клиент электронного голосования")
        self.root.geometry("1100x880")
        self.root.minsize(900, 700)

        self.sock = None
        self.recv = None
        self.connected = False
        self.q = queue.Queue()

        self.center_pub_e = None
        self.center_pub_n = None

        self.voter_keys = None
        self.registered = False
        self.voted = False

        self.prepared_fi = None
        self.prepared_qi = None
        self.prepared_vote = None

        self.pending_action = None
        self.attacker_keys = None
        self.stored_results = None

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
        t = tk.Text(f, height=height, wrap=tk.WORD, font=("Consolas", 9))
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

        t1 = ttk.Frame(nb)
        nb.add(t1, text=" Подключение и регистрация ")

        cf = ttk.LabelFrame(t1, text="Подключение к серверу (Избирком)")
        cf.pack(fill=tk.X, padx=5, pady=5)
        cr = ttk.Frame(cf)
        cr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(cr, text="IP сервера:").pack(side=tk.LEFT)
        self.srv_ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(cr, textvariable=self.srv_ip, width=16).pack(side=tk.LEFT, padx=3)
        ttk.Label(cr, text="Порт:").pack(side=tk.LEFT)
        self.srv_port = tk.StringVar(value="9999")
        ttk.Entry(cr, textvariable=self.srv_port, width=8).pack(side=tk.LEFT, padx=3)
        ttk.Button(cr, text="Подключиться", command=self._connect).pack(side=tk.LEFT, padx=8)
        ttk.Button(cr, text="Отключиться", command=self._disconnect).pack(side=tk.LEFT, padx=3)
        self.conn_status = ttk.Label(cr, text="Не подключено", foreground="red")
        self.conn_status.pack(side=tk.LEFT, padx=10)

        kf = ttk.LabelFrame(t1, text="Ключи избирателя")
        kf.pack(fill=tk.X, padx=5, pady=5)
        kr = ttk.Frame(kf)
        kr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(kr, text="ID избирателя:").pack(side=tk.LEFT)
        self.vid_var = tk.IntVar(value=1)
        ttk.Spinbox(kr, from_=1, to=99, textvariable=self.vid_var, width=5).pack(side=tk.LEFT, padx=3)
        ttk.Button(kr, text="Сгенерировать ключи RSA (512 бит)", command=self._gen_keys).pack(side=tk.LEFT, padx=8)
        self.key_status = ttk.Label(kr, text="Ключи не сгенерированы", foreground="red")
        self.key_status.pack(side=tk.LEFT, padx=10)
        self.key_log = self._txt(kf, height=5)

        rf = ttk.LabelFrame(t1, text="Регистрация (аутентификация)")
        rf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        rr = ttk.Frame(rf)
        rr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(rr, text="Зарегистрироваться", command=self._register).pack(side=tk.LEFT, padx=5)
        self.reg_status = ttk.Label(rr, text="Не зарегистрирован", foreground="red")
        self.reg_status.pack(side=tk.LEFT, padx=10)
        self.reg_log = self._txt(rf, height=8)

        t2 = ttk.Frame(nb)
        nb.add(t2, text=" Голосование ")

        vf = ttk.LabelFrame(t2, text="Выбор голоса")
        vf.pack(fill=tk.X, padx=5, pady=5)
        vr = ttk.Frame(vf)
        vr.pack(fill=tk.X, padx=5, pady=3)
        self.vote_var = tk.IntVar(value=2)
        ttk.Radiobutton(vr, text="За (b=2)", variable=self.vote_var, value=2).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(vr, text="Против (b=3)", variable=self.vote_var, value=3).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(vr, text="Воздержался (b=1)", variable=self.vote_var, value=1).pack(side=tk.LEFT, padx=5)

        bf = ttk.LabelFrame(t2, text="Формирование и отправка бюллетеня")
        bf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        br = ttk.Frame(bf)
        br.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(br, text="Подготовить бюллетень", command=self._prepare_ballot).pack(side=tk.LEFT, padx=5)
        ttk.Button(br, text="Отправить голос", command=self._send_vote).pack(side=tk.LEFT, padx=5)
        self.vote_btn_status = ttk.Label(br, text="Голос не отправлен", foreground="red")
        self.vote_btn_status.pack(side=tk.LEFT, padx=10)
        self.vote_log = self._txt(bf, height=10)

        tf = ttk.LabelFrame(t2, text="Таблица бюллетеней (с сервера)")
        tf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tr = ttk.Frame(tf)
        tr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(tr, text="Обновить таблицу", command=self._get_table).pack(side=tk.LEFT, padx=5)
        tcols = ("ID", "fi")
        self.table_tree = ttk.Treeview(tf, columns=tcols, show="headings", height=4)
        for c in tcols:
            self.table_tree.heading(c, text=c)
            self.table_tree.column(c, width=400)
        self.table_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        t3 = ttk.Frame(nb)
        nb.add(t3, text=" Проверка подсчёта ")
        ttk.Label(t3, text="Проверка на стороне избирателя с помощью открытого ключа центра и опубликованных данных",
                  font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=8, pady=5)
        vrf = ttk.Frame(t3)
        vrf.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(vrf, text="Получить результаты с сервера", command=self._get_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(vrf, text="Выполнить проверку", command=self._verify).pack(side=tk.LEFT, padx=5)
        self.vrf_status = ttk.Label(vrf, text="Ожидание", foreground="red")
        self.vrf_status.pack(side=tk.LEFT, padx=10)
        self.vrf_log = self._txt(t3, height=22)

        t4 = ttk.Frame(nb)
        nb.add(t4, text=" Злоумышленник ")
        ttk.Label(t4, text="Имитация атаки: злоумышленник пытается зарегистрироваться / проголосовать под чужим ID",
                  font=("Arial", 10, "bold"), foreground="red").pack(anchor=tk.W, padx=8, pady=5)

        af = ttk.LabelFrame(t4, text="Настройки злоумышленника")
        af.pack(fill=tk.X, padx=5, pady=5)
        ar = ttk.Frame(af)
        ar.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(ar, text="Целевой ID:").pack(side=tk.LEFT)
        self.atk_target = tk.IntVar(value=1)
        ttk.Spinbox(ar, from_=1, to=99, textvariable=self.atk_target, width=5).pack(side=tk.LEFT, padx=3)
        ttk.Button(ar, text="Сгенерировать ключи злоумышленника", command=self._gen_attacker_keys).pack(side=tk.LEFT, padx=8)
        self.atk_key_status = ttk.Label(ar, text="Ключи не сгенерированы", foreground="red")
        self.atk_key_status.pack(side=tk.LEFT, padx=10)

        abr = ttk.LabelFrame(t4, text="Атака")
        abr.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        abr_row = ttk.Frame(abr)
        abr_row.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(abr_row, text="Попытка регистрации", command=self._attacker_register).pack(side=tk.LEFT, padx=5)
        ttk.Button(abr_row, text="Попытка голосования", command=self._attacker_vote).pack(side=tk.LEFT, padx=5)
        self.atk_log = self._txt(abr, height=14)

    # ==================== Connection ====================

    def _connect(self):
        if self.connected:
            self._log(self.reg_log, "Уже подключено!")
            return
        try:
            port = int(self.srv_port.get())
        except ValueError:
            self._log(self.reg_log, "ОШИБКА: Неверный порт!")
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.srv_ip.get(), port))
            self.recv = MsgReceiver(self.sock)
            self.connected = True
            self.conn_status.configure(text="Подключено", foreground="green")
            self._log(self.reg_log, f"Подключено к {self.srv_ip.get()}:{port}")
        except ConnectionError as e:
            self._log(self.reg_log, f"ОШИБКА подключения: {e}")
            return
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _disconnect(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.recv = None
        self.conn_status.configure(text="Не подключено", foreground="red")

    def _recv_loop(self):
        while self.connected:
            try:
                msg = self.recv.recv()
            except Exception:
                break
            if msg is None:
                self._log(self.reg_log, "Соединение разорвано.")
                self._schedule(lambda: self._disconnect())
                break
            self._handle_msg(msg)

    def _handle_msg(self, msg):
        t = msg.get("type")
        if t == "center_key":
            self._on_center_key(msg)
        elif t == "challenge":
            self._on_challenge(msg)
        elif t == "auth_result":
            self._on_auth_result(msg)
        elif t == "vote_challenge":
            self._on_vote_challenge(msg)
        elif t == "vote_result":
            self._on_vote_result(msg)
        elif t == "table":
            self._on_table(msg)
        elif t == "results":
            self._on_results(msg)
        elif t == "error":
            self._on_error(msg)

    def _on_center_key(self, msg):
        self.center_pub_e = msg["e"]
        self.center_pub_n = msg["n"]
        self._log(self.reg_log, f"Получен открытый ключ центра: e={msg['e']}, n={msg['n']}")

    def _gen_keys(self):
        vid = self.vid_var.get()
        self._log(self.key_log, f"Генерация RSA-ключей избирателя {vid} (512 бит)...")
        self.root.update()
        self.voter_keys = generate_rsa_keys(512)
        self._log(self.key_log, f"Открытый ключ: e={self.voter_keys['e']}")
        self._log(self.key_log, f"  n={self.voter_keys['n']}")
        self._log(self.key_log, f"Секретный ключ: d={self.voter_keys['d']}")
        vid2 = self.vid_var.get()
        self._schedule(lambda v=vid2: self.key_status.configure(
            text=f"Ключи готовы (ID={v})", foreground="green"))

    def _register(self):
        if not self.connected:
            self._log(self.reg_log, "ОШИБКА: Сначала подключитесь к серверу!")
            return
        if self.voter_keys is None:
            self._log(self.reg_log, "ОШИБКА: Сначала сгенерируйте ключи!")
            return
        if self.registered:
            self._log(self.reg_log, "Вы уже зарегистрированы!")
            return
        vid = self.vid_var.get()
        self.pending_action = "register"
        self._log(self.reg_log, f"--- Регистрация избирателя {vid} ---")
        self._log(self.reg_log, "Отправка открытого ключа на сервер...")
        try:
            send_msg(self.sock, {
                "type": "register",
                "voter_id": vid,
                "pub_e": self.voter_keys["e"],
                "pub_n": self.voter_keys["n"]
            })
        except (ConnectionError, OSError) as e:
            self._log(self.reg_log, f"ОШИБКА: {e}")

    def _on_challenge(self, msg):
        challenge = msg["challenge"]
        vid = self.vid_var.get()

        if self.pending_action == "register":
            w = self.reg_log
            self._log(w, f"Получен challenge от центра: {challenge}")
            keys = self.voter_keys
            if keys is None:
                self._log(w, "ОШИБКА: Нет ключей!")
                return
            sig = rsa_encrypt(challenge, keys["d"], keys["n"])
            self._log(w, f"Подпись секретным ключом: signature = {sig}")
            try:
                send_msg(self.sock, {"type": "signature", "voter_id": vid, "signature": sig})
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

        elif self.pending_action == "vote":
            w = self.vote_log
            self._log(w, f"Получен challenge: {challenge}")
            keys = self.voter_keys
            if keys is None:
                self._log(w, "ОШИБКА: Нет ключей!")
                return
            sig = rsa_encrypt(challenge, keys["d"], keys["n"])
            self._log(w, f"Подпись: signature = {sig}")
            try:
                send_msg(self.sock, {
                    "type": "vote_response",
                    "voter_id": vid,
                    "signature": sig,
                    "fi": self.prepared_fi
                })
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

        elif self.pending_action == "atk_register":
            w = self.atk_log
            self._log(w, f"Получен challenge: {challenge}")
            if self.attacker_keys is None:
                self._log(w, "ОШИБКА: Нет ключей злоумышленника!")
                return
            sig = rsa_encrypt(challenge, self.attacker_keys["d"], self.attacker_keys["n"])
            self._log(w, f"Злоумышленник подписывает СВОИМ ключом: {sig}")
            self._log(w, "Отправка подписи (сервер проверит ключом настоящего избирателя)...")
            target = self.atk_target.get()
            try:
                send_msg(self.sock, {"type": "signature", "voter_id": target, "signature": sig})
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

        elif self.pending_action == "atk_vote":
            w = self.atk_log
            self._log(w, f"Получен challenge: {challenge}")
            if self.attacker_keys is None:
                self._log(w, "ОШИБКА: Нет ключей!")
                return
            sig = rsa_encrypt(challenge, self.attacker_keys["d"], self.attacker_keys["n"])
            self._log(w, f"Злоумышленник подписывает СВОИМ ключом: {sig}")
            atk_vote_val = self.vote_var.get()
            qi_atk = generate_random_prime_qi()
            ti_atk = atk_vote_val * qi_atk
            fi_atk = rsa_encrypt(ti_atk, self.center_pub_e, self.center_pub_n)
            self._log(w, f"Сформирован бюллетень: qi={qi_atk}, ti={ti_atk}, fi={fi_atk}")
            target = self.atk_target.get()
            try:
                send_msg(self.sock, {
                    "type": "vote_response",
                    "voter_id": target,
                    "signature": sig,
                    "fi": fi_atk
                })
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

    def _on_vote_challenge(self, msg):
        self._on_challenge(msg)

    def _on_auth_result(self, msg):
        success = msg["success"]
        message = msg["message"]
        if self.pending_action == "register":
            w = self.reg_log
        elif self.pending_action == "atk_register":
            w = self.atk_log
        else:
            w = self.reg_log
        self._log(w, f"Результат аутентификации: {message}")
        if success and self.pending_action == "register":
            self.registered = True
            self._schedule(lambda: self.reg_status.configure(text="Зарегистрирован", foreground="green"))
        elif success and self.pending_action == "atk_register":
            self._log(w, "ВНИМАНИЕ: Злоумышленник прошёл регистрацию (был первым)!")
        elif not success and self.pending_action == "atk_register":
            self._log(w, "ОЖИДАЕМО: Подпись злоумышленника не совпадает с ключом настоящего избирателя.")
            self._log(w, "АТАКА ОТРАЖЕНА!")
        self.pending_action = None

    def _prepare_ballot(self):
        w = self.vote_log
        if self.center_pub_e is None:
            self._log(w, "ОШИБКА: Нет открытого ключа центра!")
            return
        if not self.registered:
            self._log(w, "ОШИБКА: Сначала зарегистрируйтесь!")
            return
        if self.voted:
            self._log(w, "Вы уже проголосовали!")
            return
        b = self.vote_var.get()
        qi = generate_random_prime_qi()
        ti = b * qi
        fi = rsa_encrypt(ti, self.center_pub_e, self.center_pub_n)
        self.prepared_fi = fi
        self.prepared_qi = qi
        self.prepared_vote = b
        vn = {2: "За", 3: "Против", 1: "Воздержался"}[b]
        self._log(w, "--- Подготовка бюллетеня ---")
        self._log(w, f"Голос: b = {b} ({vn})")
        self._log(w, f"Случайное простое qi = {qi} (qi >= 5)")
        self._log(w, f"Затенение: ti = b * qi = {b} * {qi} = {ti}")
        self._log(w, "Шифрование RSA (ключ центра):")
        self._log(w, f"  fi = ti^e mod n = {ti}^{self.center_pub_e} mod n")
        self._log(w, f"  fi = {fi}")
        self._log(w, "Бюллетень готов.")

    def _send_vote(self):
        w = self.vote_log
        if not self.connected:
            self._log(w, "ОШИБКА: Нет подключения!")
            return
        if not self.registered:
            self._log(w, "ОШИБКА: Сначала зарегистрируйтесь!")
            return
        if self.voted:
            self._log(w, "Вы уже проголосовали!")
            return
        if self.prepared_fi is None:
            self._log(w, "ОШИБКА: Сначала подготовьте бюллетень!")
            return
        vid = self.vid_var.get()
        self.pending_action = "vote"
        self._log(w, "--- Отправка голоса ---")
        self._log(w, f"Запрос голосования (ID={vid})...")
        try:
            send_msg(self.sock, {"type": "vote_request", "voter_id": vid})
        except (ConnectionError, OSError) as e:
            self._log(w, f"ОШИБКА: {e}")

    def _on_vote_result(self, msg):
        success = msg["success"]
        message = msg["message"]
        if self.pending_action == "vote":
            w = self.vote_log
        elif self.pending_action == "atk_vote":
            w = self.atk_log
        else:
            w = self.vote_log
        self._log(w, f"Результат: {message}")
        if success and self.pending_action == "vote":
            self.voted = True
            self._schedule(lambda: self.vote_btn_status.configure(text="Голос отправлен", foreground="green"))
        elif not success and self.pending_action == "atk_vote":
            self._log(w, "ОЖИДАЕМО: Злоумышленник не знает секретный ключ настоящего избирателя.")
            self._log(w, "АТАКА ОТРАЖЕНА!")
        self.pending_action = None

    def _get_table(self):
        if not self.connected:
            return
        try:
            send_msg(self.sock, {"type": "get_table"})
        except (ConnectionError, OSError):
            pass

    def _on_table(self, msg):
        ballots = msg["ballots"]
        if "center_e" in msg:
            self.center_pub_e = msg["center_e"]
        if "center_n" in msg:
            self.center_pub_n = msg["center_n"]
        def _do():
            for item in self.table_tree.get_children():
                self.table_tree.delete(item)
            for vid, fi in ballots:
                self.table_tree.insert("", tk.END, values=(vid, fi))
        self._schedule(_do)

    def _get_results(self):
        if not self.connected:
            self._log(self.vrf_log, "ОШИБКА: Нет подключения!")
            return
        try:
            send_msg(self.sock, {"type": "get_results"})
        except (ConnectionError, OSError) as e:
            self._log(self.vrf_log, f"ОШИБКА: {e}")

    def _on_results(self, msg):
        self.stored_results = msg
        w = self.vrf_log
        self._schedule(lambda: w.delete("1.0", tk.END))
        self._log(w, "Получены результаты:")
        self._log(w, f"  r (За)      = {msg['r']}")
        self._log(w, f"  P (Против)  = {msg['P']}")
        self._log(w, f"  R (контр.)  = {msg['R']}")
        self._log(w, f"  F           = {msg['F']}")
        self._log(w, f"  Бюллетеней  = {len(msg['ballots'])}")
        self._schedule(lambda: self.vrf_status.configure(text="Результаты получены", foreground="blue"))

    def _on_error(self, msg):
        self._log(self.reg_log, f"ОШИБКА от сервера: {msg['message']}")

    def _verify(self):
        w = self.vrf_log
        if self.stored_results is None:
            self._log(w, "ОШИБКА: Сначала получите результаты!")
            return
        res = self.stored_results
        r = res["r"]
        P = res["P"]
        R = res["R"]
        e_c = res["center_e"]
        n_c = res["center_n"]
        ballots = res["ballots"]
        self._schedule(lambda: w.delete("1.0", tk.END))
        self._log(w, "=== Верификация результатов ===")
        self._log(w, "")
        self._log(w, "Опубликованные параметры:")
        self._log(w, f"  Открытый ключ центра: e={e_c}, n={n_c}")
        self._log(w, f"  r = {r}, P = {P}, R = {R}")
        self._log(w, "")
        self._log(w, "Шаг 1: Восстановление Q")
        Q = (2 ** r) * (3 ** P) * R
        self._log(w, f"  Q = 2^{r} * 3^{P} * {R} = {Q}")
        self._log(w, "")
        self._log(w, "Шаг 2: Вычисление F из опубликованных бюллетеней")
        F = 1
        for vid, fi in ballots:
            self._log(w, f"  fi({vid}) = {fi}")
            F = (F * fi) % n_c
        self._log(w, f"  F = {F}")
        self._log(w, "")
        self._log(w, "Шаг 3: Проверка Q^e mod n == F")
        Qe = pow(Q, e_c, n_c)
        self._log(w, f"  Q^e mod n = {Qe}")
        self._log(w, f"  F        = {F}")
        eq = (Qe == F)
        if eq:
            self._log(w, "  Равенство: ДА (верно)")
        else:
            self._log(w, "  Равенство: НЕТ (ошибка!)")
        self._log(w, "")
        self._log(w, "Шаг 4: Проверка R (не делится на 2 и на 3)")
        d2 = (R % 2 == 0)
        d3 = (R % 3 == 0)
        self._log(w, f"  R = {R}")
        if d2:
            self._log(w, "  R делится на 2: ДА (ошибка!)")
        else:
            self._log(w, "  R делится на 2: НЕТ (верно)")
        if d3:
            self._log(w, "  R делится на 3: ДА (ошибка!)")
        else:
            self._log(w, "  R делится на 3: НЕТ (верно)")
        r_ok = not d2 and not d3
        self._log(w, "")
        self._log(w, "=" * 55)
        if eq and r_ok:
            self._log(w, "  ИТОГ: ПОДСЧЁТ ПРАВИЛЬНЫЙ")
            self._log(w, "  Все проверки пройдены. Результаты достоверны.")
            self._schedule(lambda: self.vrf_status.configure(text="Подсчёт подтверждён", foreground="green"))
        else:
            self._log(w, "  ИТОГ: ПОДСЧЁТ НЕПРАВИЛЬНЫЙ")
            if not eq:
                self._log(w, "  Причина: Q^e mod n != F")
            if not r_ok:
                self._log(w, "  Причина: R делится на 2 или 3")
            self._schedule(lambda: self.vrf_status.configure(text="Ошибка!", foreground="red"))
        self._log(w, "=" * 55)

    def _gen_attacker_keys(self):
        self._log(self.atk_log, "Генерация RSA-ключей злоумышленника...")
        self.root.update()
        self.attacker_keys = generate_rsa_keys(512)
        self._log(self.atk_log, f"Ключи готовы: e={self.attacker_keys['e']}")
        self._log(self.atk_log, f"  n={self.attacker_keys['n']}")
        self._log(self.atk_log, f"  d={self.attacker_keys['d']}")
        self._schedule(lambda: self.atk_key_status.configure(text="Ключи злоумышленника готовы", foreground="orange"))

    def _attacker_register(self):
        if not self.connected:
            self._log(self.atk_log, "ОШИБКА: Нет подключения!")
            return
        if self.attacker_keys is None:
            self._log(self.atk_log, "ОШИБКА: Сначала сгенерируйте ключи!")
            return
        target = self.atk_target.get()
        self.pending_action = "atk_register"
        self._log(self.atk_log, f"--- Попытка регистрации под ID {target} ---")
        self._log(self.atk_log, f"Отправка СВОЕГО открытого ключа вместо ключа избирателя {target}...")
        try:
            send_msg(self.sock, {
                "type": "register",
                "voter_id": target,
                "pub_e": self.attacker_keys["e"],
                "pub_n": self.attacker_keys["n"]
            })
        except (ConnectionError, OSError) as e:
            self._log(self.atk_log, f"ОШИБКА: {e}")

    def _attacker_vote(self):
        if not self.connected:
            self._log(self.atk_log, "ОШИБКА: Нет подключения!")
            return
        if self.attacker_keys is None:
            self._log(self.atk_log, "ОШИБКА: Сначала сгенерируйте ключи!")
            return
        if self.center_pub_e is None:
            self._log(self.atk_log, "ОШИБКА: Нет открытого ключа центра!")
            return
        target = self.atk_target.get()
        self.pending_action = "atk_vote"
        self._log(self.atk_log, f"--- Попытка голосования под ID {target} ---")
        self._log(self.atk_log, "Запрос голосования...")
        try:
            send_msg(self.sock, {"type": "vote_request", "voter_id": target})
        except (ConnectionError, OSError) as e:
            self._log(self.atk_log, f"ОШИБКА: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = VotingClient(root)
    root.mainloop()
