"""
Клиентская часть протокола электронного голосования — Избиратель.

Протокол реализует систему электронного голосования с обеспечением:
  - Аутентификации на основе схемы «вызов-ответ» (Challenge-Response) с использованием
    цифровой подписи RSA: центр отправляет случайное число (challenge), избиратель
    подписывает его своим секретным ключом: signature = challenge^d_voter mod n_voter.
    Центр проверяет: signature^e_voter mod n_voter == challenge.
  - Конфиденциальности голоса посредством «затенения» (blinding) бюллетеня:
    избиратель формирует ti = b * qi, где b — голос (1=воздержался, 2=за, 3=против),
    qi — случайное простое число (qi >= 5), затем шифрует: fi = ti^e_center mod n_center.
    Центр при расшифровке получает ti, но не может отделить b от qi — голос скрыт.
  - Верификации подсчёта: после голосования центр публикует F (произведение всех fi),
    параметры r (голоса «за»), P (голоса «против»), R (контрольное число).
    Избиратель проверяет: Q = 2^r * 3^P * R, затем Q^e_center mod n_center == F,
    а также R не делится на 2 и на 3.

Злоумышленник (вкладка «Злоумышленник») имитирует попытку регистрации/голосования
под чужим ID. Злоумышленник подписывает challenge СВОИМ секретным ключом d_attacker,
но центр проверяет подпись по открытому ключу настоящего избирателя (e_voter, n_voter),
поэтому signature^e_voter mod n_voter != challenge — атака отражена.

Сообщения протокола (типы):
  От клиента: register, signature, vote_request, vote_response, get_voter_list, get_table, get_results
  От сервера: center_key, challenge, auth_result, vote_challenge, vote_result,
              voting_started, ballots_published, voter_list, table, results, error

Потокобезопасность: сетевой поток использует _schedule() для постановки операций
с GUI в очередь, а _poll() (вызываемый через root.after в главном потоке Tkinter)
извлекает и выполняет их безопасно.
"""

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
    """Клиент электронного голосования — интерфейс избирателя.

    Реализует полный цикл: подключение → генерация ключей RSA → регистрация
    (аутентификация Challenge-Response) → подготовка и отправка затенённого
    бюллетеня → проверка подсчёта. Также включает вкладку для имитации атаки.
    """

    def __init__(self, root):
        """Инициализация клиента: создание переменных состояния и построение GUI.

        Переменные состояния:
          - center_pub_e, center_pub_n — открытый ключ центра (получается при подключении)
          - voter_keys — RSA-ключи избирателя (e, d, n) — генерируются локально
          - prepared_fi, prepared_qi, prepared_vote — подготовленный бюллетень и его компоненты
          - pending_action — текущий шаг протокола ('register', 'vote', 'atk_register', 'atk_vote')
          - attacker_keys — RSA-ключи злоумышленника для имитации атаки
          - stored_results — сохранённые результаты голосования для верификации
          - voting_active — флаг активного голосования
          - ballots_received — флаг публикации бюллетеней
        """
        self.root = root
        self.root.title("Избиратель — Клиент электронного голосования")
        self.root.geometry("1100x880")
        self.root.minsize(900, 700)

        # Сокет и приёмник сообщений
        self.sock = None
        self.recv = None
        self.connected = False
        # Очередь для потокобезопасного обновления GUI из сетевого потока
        self.q = queue.Queue()

        # Открытый ключ избирательного центра (e_center, n_center)
        # Используется для шифрования бюллетеня: fi = ti^e_center mod n_center
        self.center_pub_e = None
        self.center_pub_n = None

        # RSA-ключи избирателя: {'e': ..., 'd': ..., 'n': ...}
        # e, n — открытый ключ (передаётся центру при регистрации)
        # d — секретный ключ (используется для подписи challenge)
        self.voter_keys = None
        self.registered = False
        self.voted = False

        # Подготовленный бюллетень и его компоненты:
        # fi = (b * qi)^e_center mod n_center — зашифрованный затенённый бюллетень
        # qi — случайное простое число (qi >= 5), маскирующее голос b
        # prepared_vote = b — сам голос (1=воздержался, 2=за, 3=против)
        self.prepared_fi = None
        self.prepared_qi = None
        self.prepared_vote = None

        # Текущий шаг протокола; определяет, как обрабатывается входящий challenge:
        #   'register'      — регистрация избирателя (подпись своим d_voter)
        #   'vote'           — голосование (подпись + отправка fi)
        #   'atk_register'   — атака: регистрация под чужим ID (подпись d_attacker)
        #   'atk_vote'        — атака: голосование под чужим ID (подпись d_attacker + чужой fi)
        self.pending_action = None
        # RSA-ключи злоумышленника (свои e, d, n) — для имитации атаки
        self.attacker_keys = None
        # Сохранённые результаты голосования (r, P, R, F, ballots) для верификации
        self.stored_results = None
        self.voting_active = False
        self.ballots_received = False

        self._build_gui()
        # Запуск цикла опроса очереди GUI-обновлений (работает в главном потоке Tkinter)
        self._poll()

    def _poll(self):
        """Опрос очереди _schedule: извлекает и выполняет функции в главном потоке Tkinter.

        Вызывается каждые 50 мс через root.after(). Это обеспечивает потокобезопасность:
        сетевой поток не вызывает методы Tkinter напрямую, а ставит функции в очередь q.
        """
        while not self.q.empty():
            fn = self.q.get_nowait()
            try:
                fn()
            except tk.TclError:
                # Окно могло быть уже уничтожено — игнорируем
                pass
        self.root.after(50, self._poll)

    def _schedule(self, fn):
        """Постановка функции fn в очередь для выполнения в главном потоке Tkinter.

        Используется сетевым потоком для безопасного обновления виджетов GUI.
        """
        self.q.put(fn)

    def _txt(self, parent, height=8):
        """Создаёт текстовый виджет с полосой прокрутки для вывода логов."""
        f = ttk.Frame(parent)
        f.pack(fill=tk.BOTH, expand=True, padx=3, pady=2)
        t = tk.Text(f, height=height, wrap=tk.WORD, font=("Consolas", 9))
        sb = ttk.Scrollbar(f, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        return t

    def _log(self, w, msg):
        """Потокобезопасная запись сообщения msg в текстовый виджет w.

        Использует _schedule для постановки вставки текста в очередь GUI.
        """
        def _do():
            w.insert(tk.END, msg + "\n")
            w.see(tk.END)
        self._schedule(_do)

    # ==================== Построение GUI ====================

    def _build_gui(self):
        """Построение графического интерфейса: 4 вкладки Notebook.

        Вкладки:
          1. «Подключение и регистрация» — подключение к серверу, генерация ключей, регистрация
          2. «Голосование» — выбор голоса, подготовка бюллетеня, отправка, таблица бюллетеней
          3. «Проверка подсчёта» — получение и верификация результатов голосования
          4. «Злоумышленник» — имитация атаки (регистрация/голосование под чужим ID)
        """
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # --- Вкладка 1: Подключение и регистрация ---
        t1 = ttk.Frame(nb)
        nb.add(t1, text=" Подключение и регистрация ")

        # Блок подключения к серверу (Избиркому)
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

        # Блок генерации RSA-ключей избирателя
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

        # Блок регистрации (аутентификация Challenge-Response)
        rf = ttk.LabelFrame(t1, text="Регистрация (аутентификация)")
        rf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        rr = ttk.Frame(rf)
        rr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(rr, text="Зарегистрироваться", command=self._register).pack(side=tk.LEFT, padx=5)
        ttk.Button(rr, text="Получить список избирателей", command=self._get_voter_list).pack(side=tk.LEFT, padx=5)
        self.reg_status = ttk.Label(rr, text="Не зарегистрирован", foreground="red")
        self.reg_status.pack(side=tk.LEFT, padx=10)
        self.reg_log = self._txt(rf, height=8)

        # --- Вкладка 2: Голосование ---
        t2 = ttk.Frame(nb)
        nb.add(t2, text=" Голосование ")

        # Выбор голоса: b=1 (воздержался), b=2 (за), b=3 (против)
        vf = ttk.LabelFrame(t2, text="Выбор голоса")
        vf.pack(fill=tk.X, padx=5, pady=5)
        vr = ttk.Frame(vf)
        vr.pack(fill=tk.X, padx=5, pady=3)
        self.vote_var = tk.IntVar(value=2)
        ttk.Radiobutton(vr, text="За (b=2)", variable=self.vote_var, value=2).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(vr, text="Против (b=3)", variable=self.vote_var, value=3).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(vr, text="Воздержался (b=1)", variable=self.vote_var, value=1).pack(side=tk.LEFT, padx=5)

        # Формирование и отправка бюллетеня
        bf = ttk.LabelFrame(t2, text="Формирование и отправка бюллетеня")
        bf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        br = ttk.Frame(bf)
        br.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(br, text="Подготовить бюллетень", command=self._prepare_ballot).pack(side=tk.LEFT, padx=5)
        ttk.Button(br, text="Отправить голос", command=self._send_vote).pack(side=tk.LEFT, padx=5)
        self.vote_btn_status = ttk.Label(br, text="Голос не отправлен", foreground="red")
        self.vote_btn_status.pack(side=tk.LEFT, padx=10)
        self.vote_phase_label = ttk.Label(br, text="Ожидание начала голосования", foreground="red")
        self.vote_phase_label.pack(side=tk.LEFT, padx=10)
        self.vote_log = self._txt(bf, height=10)

        # Таблица опубликованных бюллетеней (fi) — публикуется после завершения голосования
        tf = ttk.LabelFrame(t2, text="Таблица бюллетеней (публикуется после завершения голосования)")
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

        # --- Вкладка 3: Проверка подсчёта ---
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

        # --- Вкладка 4: Злоумышленник ---
        t4 = ttk.Frame(nb)
        nb.add(t4, text=" Злоумышленник ")
        ttk.Label(t4, text="Имитация атаки: злоумышленник пытается зарегистрироваться / проголосовать под чужим ID",
                  font=("Arial", 10, "bold"), foreground="red").pack(anchor=tk.W, padx=8, pady=5)

        # Настройки злоумышленника: целевой ID и генерация его собственных RSA-ключей
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

        # Кнопки запуска атаки: регистрация и голосование под чужим ID
        abr = ttk.LabelFrame(t4, text="Атака")
        abr.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        abr_row = ttk.Frame(abr)
        abr_row.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(abr_row, text="Попытка регистрации", command=self._attacker_register).pack(side=tk.LEFT, padx=5)
        ttk.Button(abr_row, text="Попытка голосования", command=self._attacker_vote).pack(side=tk.LEFT, padx=5)
        self.atk_log = self._txt(abr, height=14)

    # ==================== Подключение / Отключение ====================

    def _connect(self):
        """Подключение к серверу (Избиркому) по TCP.

        После подключения запускается фоновый поток _recv_loop для приёма сообщений.
        Сервер автоматически отправляет свой открытый ключ (center_key) при подключении.
        """
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
            # MsgReceiver обеспечивает framing сообщений (длина + данные)
            self.recv = MsgReceiver(self.sock)
            self.connected = True
            self.conn_status.configure(text="Подключено", foreground="green")
            self._log(self.reg_log, f"Подключено к {self.srv_ip.get()}:{port}")
        except ConnectionError as e:
            self._log(self.reg_log, f"ОШИБКА подключения: {e}")
            return
        # Запуск фонового потока для приёма сообщений от сервера
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _disconnect(self):
        """Отключение от сервера: закрытие сокета и сброс состояния подключения."""
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.recv = None
        self.conn_status.configure(text="Не подключено", foreground="red")

    # ==================== Приём и обработка сообщений ====================

    def _recv_loop(self):
        """Цикл приёма сообщений от сервера (работает в отдельном потоке).

        Читает сообщения через MsgReceiver.recv() и передаёт их в _handle_msg.
        При разрыве соединения инициирует отключение через _schedule.
        """
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
        """Диспетчеризация входящих сообщений по типу.

        Типы сообщений от сервера:
          center_key     — открытый ключ центра (e, n) — приходит при подключении
          challenge      — случайное число для аутентификации при регистрации
          auth_result    — результат проверки подписи (успех/неудача)
          vote_challenge — случайное число для аутентификации при голосовании
          vote_result    — результат приёма голоса
          voting_started — уведомление о начале голосования (список избирателей)
          ballots_published — публикация бюллетеней после завершения голосования
          voter_list     — список зарегистрированных избирателей (id, pub_e, pub_n)
          table          — таблица бюллетеней (id, fi)
          results        — результаты голосования (r, P, R, F, ballots)
          error          — сообщение об ошибке
        """
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
        elif t == "voting_started":
            self._on_voting_started(msg)
        elif t == "ballots_published":
            self._on_ballots_published(msg)
        elif t == "voter_list":
            self._on_voter_list(msg)
        elif t == "table":
            self._on_table(msg)
        elif t == "results":
            self._on_results(msg)
        elif t == "error":
            self._on_error(msg)

    # ==================== Обработчики сообщений ====================

    def _on_center_key(self, msg):
        """Обработка сообщения center_key: сохранение открытого ключа избирательного центра.

        Ключ (e_center, n_center) нужен для:
          1. Шифрования бюллетеня: fi = ti^e_center mod n_center
          2. Верификации результатов: Q^e_center mod n_center == F
        """
        self.center_pub_e = msg["e"]
        self.center_pub_n = msg["n"]
        self._log(self.reg_log, f"Получен открытый ключ центра: e={msg['e']}, n={msg['n']}")

    def _gen_keys(self):
        """Генерация RSA-ключей избирателя (512 бит).

        Создаёт пару ключей: открытый (e, n) — для проверки подписи центром,
        и секретный (d, n) — для создания цифровой подписи (challenge^d mod n).
        """
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

    # ==================== Регистрация (аутентификация Challenge-Response) ====================

    def _register(self):
        """Начало регистрации избирателя: отправка открытого ключа на сервер.

        Шаг 1 протокола регистрации: избиратель отправляет свой ID и открытый ключ (e, n).
        Сервер сохраняет ключ и отправляет challenge (случайное число).
        Затем в _on_challenge избиратель подписывает challenge своим секретным ключом d.
        """
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
        # Устанавливаем pending_action, чтобы _on_challenge знал, что это регистрация
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
        """Обработка challenge от сервера — центральный шаг аутентификации Challenge-Response.

        Схема «вызов-ответ»:
          1. Центр отправляет случайное число challenge
          2. Избиратель создаёт цифровую подпись: signature = challenge^d mod n
             (шифрование challenge секретным ключом избирателя)
          3. Центр проверяет: signature^e mod n == challenge
             (расшифровка открытым ключом избирателя и сравнение с challenge)

        Поведение зависит от pending_action:
          'register'     — подпись секретным ключом избирателя, отправка signature
          'vote'         — подпись секретным ключом + отправка signature и зашифрованного бюллетеня fi
          'atk_register' — подпись СВОИМ ключом d_attacker (атака: центр проверит по ключу
                           настоящего избирателя → подпись не совпадёт → атака отражена)
          'atk_vote'     — подпись СВОИМ ключом + отправка своего fi (атака при голосовании)
        """
        challenge = msg["challenge"]
        vid = self.vid_var.get()

        if self.pending_action == "register":
            # --- Нормальная регистрация ---
            w = self.reg_log
            self._log(w, f"Получен challenge от центра: {challenge}")
            keys = self.voter_keys
            if keys is None:
                self._log(w, "ОШИБКА: Нет ключей!")
                return
            # Цифровая подпись RSA: signature = challenge^d_voter mod n_voter
            sig = rsa_encrypt(challenge, keys["d"], keys["n"])
            self._log(w, f"Подпись секретным ключом: signature = {sig}")
            try:
                send_msg(self.sock, {"type": "signature", "voter_id": vid, "signature": sig})
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

        elif self.pending_action == "vote":
            # --- Нормальное голосование ---
            w = self.vote_log
            self._log(w, f"Получен challenge: {challenge}")
            keys = self.voter_keys
            if keys is None:
                self._log(w, "ОШИБКА: Нет ключей!")
                return
            # Цифровая подпись RSA: signature = challenge^d_voter mod n_voter
            sig = rsa_encrypt(challenge, keys["d"], keys["n"])
            self._log(w, f"Подпись: signature = {sig}")
            try:
                # Отправляем подпись и подготовленный зашифрованный бюллетень fi
                send_msg(self.sock, {
                    "type": "vote_response",
                    "voter_id": vid,
                    "signature": sig,
                    "fi": self.prepared_fi
                })
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

        elif self.pending_action == "atk_register":
            # --- Атака: регистрация под чужим ID ---
            w = self.atk_log
            self._log(w, f"Получен challenge: {challenge}")
            if self.attacker_keys is None:
                self._log(w, "ОШИБКА: Нет ключей злоумышленника!")
                return
            # Злоумышленник подписывает СВОИМ секретным ключом d_attacker
            # Центр проверит: sig^e_real mod n_real == challenge → НЕ совпадёт!
            sig = rsa_encrypt(challenge, self.attacker_keys["d"], self.attacker_keys["n"])
            self._log(w, f"Злоумышленник подписывает СВОИМ ключом: {sig}")
            self._log(w, "Отправка подписи (сервер проверит ключом настоящего избирателя)...")
            target = self.atk_target.get()
            try:
                send_msg(self.sock, {"type": "signature", "voter_id": target, "signature": sig})
            except (ConnectionError, OSError) as e:
                self._log(w, f"ОШИБКА: {e}")

        elif self.pending_action == "atk_vote":
            # --- Атака: голосование под чужим ID ---
            w = self.atk_log
            self._log(w, f"Получен challenge: {challenge}")
            if self.attacker_keys is None:
                self._log(w, "ОШИБКА: Нет ключей!")
                return
            # Злоумышленник подписывает СВОИМ секретным ключом d_attacker
            sig = rsa_encrypt(challenge, self.attacker_keys["d"], self.attacker_keys["n"])
            self._log(w, f"Злоумышленник подписывает СВОИМ ключом: {sig}")
            # Злоумышленник формирует СВОЙ бюллетень с желаемым голосом
            atk_vote_val = self.vote_var.get()
            qi_atk = generate_random_prime_qi()
            ti_atk = atk_vote_val * qi_atk
            # Шифрование бюллетеня открытым ключом центра (как при нормальном голосовании)
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
        """Обработка vote_challenge: делегируется в _on_challenge (pending_action='vote')."""
        self._on_challenge(msg)

    # ==================== Голосование: уведомления о фазах ====================

    def _on_voting_started(self, msg):
        """Обработка уведомления о начале голосования.

        Сервер отправляет список зарегистрированных избирателей.
        Голосование становится активным — можно отправлять голос.
        """
        self.voting_active = True
        voters = msg.get("voters", [])
        self._log(self.vote_log, f"ГОЛОСОВАНИЕ НАЧАЛОСЬ! Список избирателей: {voters}")
        self._schedule(lambda: self.vote_phase_label.configure(text="Голосование АКТИВНО", foreground="green"))

    def _on_ballots_published(self, msg):
        """Обработка публикации бюллетеней после завершения голосования.

        Центр публикует все бюллетени (fi) и может повторно передать свой открытый ключ.
        Это необходимо для верификации: избиратель может проверить, что F = Q^e mod n.
        """
        self.ballots_received = True
        self.voting_active = False
        ballots = msg.get("ballots", [])
        # Центр может передать свой открытый ключ повторно (для верификации)
        if "center_e" in msg:
            self.center_pub_e = msg["center_e"]
        if "center_n" in msg:
            self.center_pub_n = msg["center_n"]
        self._log(self.vote_log, f"Голосование завершено. Опубликовано бюллетеней: {len(ballots)}")
        self._schedule(lambda: self.vote_phase_label.configure(text="Голосование завершено, бюллетени опубликованы", foreground="blue"))
        # Обновляем таблицу бюллетеней
        self._on_table(msg)

    def _on_voter_list(self, msg):
        """Обработка списка зарегистрированных избирателей (id, pub_e, pub_n)."""
        voters = msg.get("voters", [])
        w = self.reg_log
        self._log(w, "--- Список зарегистрированных избирателей ---")
        for v in voters:
            self._log(w, f"  ID={v['id']}  pub_e={v['pub_e']}  pub_n={v['pub_n']}")
        self._log(w, f"Всего: {len(voters)}")

    def _get_voter_list(self):
        """Запрос списка зарегистрированных избирателей у сервера."""
        if not self.connected:
            self._log(self.reg_log, "ОШИБКА: Нет подключения!")
            return
        try:
            send_msg(self.sock, {"type": "get_voter_list"})
        except (ConnectionError, OSError):
            pass

    # ==================== Результат аутентификации ====================

    def _on_auth_result(self, msg):
        """Обработка результата аутентификации (после проверки подписи центром).

        Центр проверил: signature^e_voter mod n_voter == challenge.
        Если подпись совпадает — аутентификация успешна, избиратель зарегистрирован.
        Для атаки: подпись злоумышленника (challenge^d_attacker mod n_attacker)
        при проверке ключом настоящего избирателя не совпадает → атака отражена.
        """
        success = msg["success"]
        message = msg["message"]
        # Определяем, в какой лог писать результат
        if self.pending_action == "register":
            w = self.reg_log
        elif self.pending_action == "atk_register":
            w = self.atk_log
        else:
            w = self.reg_log
        self._log(w, f"Результат аутентификации: {message}")
        if success and self.pending_action == "register":
            # Успешная регистрация — подпись совпала с ключом избирателя
            self.registered = True
            self._schedule(lambda: self.reg_status.configure(text="Зарегистрирован", foreground="green"))
        elif success and self.pending_action == "atk_register":
            # Аномалия: злоумышленник прошёл регистрацию (возможно, был первым с этим ID)
            self._log(w, "ВНИМАНИЕ: Злоумышленник прошёл регистрацию (был первым)!")
        elif not success and self.pending_action == "atk_register":
            # Ожидаемый результат атаки: signature^e_real mod n_real != challenge
            # т.к. злоумышленник подписывал ключом d_attacker, а не d_real
            self._log(w, "ОЖИДАЕМО: Подпись злоумышленника не совпадает с ключом настоящего избирателя.")
            self._log(w, "АТАКА ОТРАЖЕНА!")
        self.pending_action = None

    # ==================== Формирование и отправка бюллетеня ====================

    def _prepare_ballot(self):
        """Подготовка затенённого (blinded) и зашифрованного бюллетеня.

        Алгоритм:
          1. Выбирается голос b: 1=воздержался, 2=за, 3=против
          2. Генерируется случайное простое qi (qi >= 5) — множитель для затенения
          3. Формируется затенённый бюллетень: ti = b * qi
             (центр при расшифровке получит ti, но не сможет отделить b от qi)
          4. Шифрование RSA открытым ключом центра: fi = ti^e_center mod n_center
             (только центр с секретным ключом d_center может расшифровать fi → ti)
        """
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
        # Затенение: ti = b * qi — голос b маскируется случайным простым множителем qi
        ti = b * qi
        # Шифрование RSA открытым ключом центра: fi = ti^e_center mod n_center
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
        """Отправка запроса на голосование: инициирует шаг Challenge-Response для голосования.

        Шаг 1: отправляется vote_request с voter_id.
        Сервер отправит vote_challenge, на который избиратель ответит
        подписью и зашифрованным бюллетенем fi (в _on_challenge, pending_action='vote').
        """
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
        # Устанавливаем pending_action, чтобы _on_challenge знал, что это голосование
        self.pending_action = "vote"
        self._log(w, "--- Отправка голоса ---")
        self._log(w, f"Запрос голосования (ID={vid})...")
        try:
            send_msg(self.sock, {"type": "vote_request", "voter_id": vid})
        except (ConnectionError, OSError) as e:
            self._log(w, f"ОШИБКА: {e}")

    def _on_vote_result(self, msg):
        """Обработка результата голосования от сервера.

        Для нормального голосования: при успехе отмечаем, что голос принят.
        Для атаки: при неудаче подтверждаем, что подпись злоумышленника не прошла проверку.
        """
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
            # Голос принят сервером
            self.voted = True
            self._schedule(lambda: self.vote_btn_status.configure(text="Голос отправлен", foreground="green"))
        elif not success and self.pending_action == "atk_vote":
            # Атака отражена: злоумышленник не знает d_real настоящего избирателя,
            # поэтому его подпись (challenge^d_attacker mod n_attacker)
            # не проходит проверку: sig^e_real mod n_real != challenge
            self._log(w, "ОЖИДАЕМО: Злоумышленник не знает секретный ключ настоящего избирателя.")
            self._log(w, "АТАКА ОТРАЖЕНА!")
        self.pending_action = None

    # ==================== Таблица бюллетеней ====================

    def _get_table(self):
        """Запрос таблицы опубликованных бюллетеней (ID, fi) у сервера."""
        if not self.connected:
            return
        try:
            send_msg(self.sock, {"type": "get_table"})
        except (ConnectionError, OSError):
            pass

    def _on_table(self, msg):
        """Обработка таблицы бюллетеней: обновление Treeview.

        Каждый бюллетень представлен парой (voter_id, fi), где
        fi = (b * qi)^e_center mod n_center — зашифрованный затенённый бюллетень.
        Также сервер может передать повторно открытый ключ центра.
        """
        ballots = msg.get("ballots", [])
        msg_text = msg.get("message", "")
        if "center_e" in msg:
            self.center_pub_e = msg["center_e"]
        if "center_n" in msg:
            self.center_pub_n = msg["center_n"]
        if msg_text and not ballots:
            self._log(self.vote_log, msg_text)
        def _do():
            for item in self.table_tree.get_children():
                self.table_tree.delete(item)
            for vid, fi in ballots:
                self.table_tree.insert("", tk.END, values=(vid, fi))
        self._schedule(_do)

    # ==================== Верификация результатов ====================

    def _get_results(self):
        """Запрос результатов голосования у сервера для последующей верификации."""
        if not self.connected:
            self._log(self.vrf_log, "ОШИБКА: Нет подключения!")
            return
        try:
            send_msg(self.sock, {"type": "get_results"})
        except (ConnectionError, OSError) as e:
            self._log(self.vrf_log, f"ОШИБКА: {e}")

    def _on_results(self, msg):
        """Сохранение полученных результатов голосования для верификации.

        Результаты содержат:
          r  — количество голосов «за» (показатель степени двойки)
          P  — количество голосов «против» (показатель степени тройки)
          R  — контрольное число (произведение всех qi, не делится на 2 и 3)
          F  — произведение всех fi по модулю n_center
          ballots — список всех бюллетеней (id, fi)
          center_e, center_n — открытый ключ центра для проверки
        """
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
        """Обработка сообщения об ошибке от сервера."""
        self._log(self.reg_log, f"ОШИБКА от сервера: {msg['message']}")

    def _verify(self):
        """Верификация результатов голосования на стороне избирателя.

        Проверка корректности подсчёта основана на гомоморфных свойствах RSA:
          Произведение зашифрованных бюллетеней = шифрование произведения исходных:
            F = (fi_1 * fi_2 * ... * fi_k) mod n = (t1*t2*...*tk)^e mod n

          Центр расшифровывает F → T = t1*t2*...*tk = (b1*q1)*(b2*q2)*...*(bk*qk)
          и разлагает T на множители:
            T = 2^r * 3^P * R,  где R не делится на 2 и 3

        Шаги проверки:
          1. Восстановление Q = 2^r * 3^P * R  (из опубликованных r, P, R)
          2. Вычисление F из опубликованных бюллетеней: F = (fi_1 * fi_2 * ... * fi_k) mod n
          3. Проверка гомоморфного равенства: Q^e_center mod n_center == F
             Если равенство выполняется — подсчёт по голосам «за» и «против» верен
          4. Проверка контрольного числа R: R не должно делиться на 2 и на 3
             (если R делится на 2 или 3 — значит, центр «украл» голоса,
              включив лишние множители b=2 или b=3 в R)
        """
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

        # Шаг 1: Восстановление Q = 2^r * 3^P * R
        self._log(w, "Шаг 1: Восстановление Q")
        Q = (2 ** r) * (3 ** P) * R
        self._log(w, f"  Q = 2^{r} * 3^{P} * {R} = {Q}")
        self._log(w, "")

        # Шаг 2: Вычисление F = произведение всех fi по модулю n_center
        self._log(w, "Шаг 2: Вычисление F из опубликованных бюллетеней")
        F = 1
        for vid, fi in ballots:
            self._log(w, f"  fi({vid}) = {fi}")
            F = (F * fi) % n_c
        self._log(w, f"  F = {F}")
        self._log(w, "")

        # Шаг 3: Проверка гомоморфного равенства: Q^e mod n == F
        # Если T = 2^r * 3^P * R, то T^e mod n = F (по гомоморфности RSA)
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

        # Шаг 4: Проверка контрольного числа R
        # R = q1 * q2 * ... * qk — произведение случайных простых qi (каждое qi >= 5)
        # Если R делится на 2 или 3, значит центр подделал результат,
        # включив лишние множители голосов (b=2 или b=3) в R
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

        # Итоговый вывод
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

    # ==================== Злоумышленник (имитация атаки) ====================

    def _gen_attacker_keys(self):
        """Генерация RSA-ключей злоумышленника (512 бит).

        Злоумышленник имеет СВОИ ключи (e_attacker, d_attacker, n_attacker).
        При атаке он подписывает challenge своим d_attacker, но центр
        проверяет подпись по открытому ключу настоящего избирателя (e_real, n_real),
        поэтому: sig^e_real mod n_real != challenge — атака обнаружена.
        """
        self._log(self.atk_log, "Генерация RSA-ключей злоумышленника...")
        self.root.update()
        self.attacker_keys = generate_rsa_keys(512)
        self._log(self.atk_log, f"Ключи готовы: e={self.attacker_keys['e']}")
        self._log(self.atk_log, f"  n={self.attacker_keys['n']}")
        self._log(self.atk_log, f"  d={self.attacker_keys['d']}")
        self._schedule(lambda: self.atk_key_status.configure(text="Ключи злоумышленника готовы", foreground="orange"))

    def _attacker_register(self):
        """Попытка регистрации злоумышленника под чужим ID.

        Злоумышленник отправляет СВОЙ открытый ключ вместо ключа настоящего избирателя.
        Если ID ещё не зарегистрирован — сервер может принять ключ злоумышленника
        (и тогда настоящий избиратель не сможет зарегистрироваться).
        Если ID уже зарегистрирован — сервер использует сохранённый ключ настоящего
        избирателя для проверки подписи, и подпись злоумышленника не совпадёт.
        """
        if not self.connected:
            self._log(self.atk_log, "ОШИБКА: Нет подключения!")
            return
        if self.attacker_keys is None:
            self._log(self.atk_log, "ОШИБКА: Сначала сгенерируйте ключи!")
            return
        target = self.atk_target.get()
        # Устанавливаем pending_action='atk_register', чтобы _on_challenge
        # знал, что нужно подписывать ключом злоумышленника
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
        """Попытка голосования злоумышленника под чужим ID.

        Злоумышленник отправляет vote_request с чужим voter_id.
        При получении vote_challenge он подпишет его СВОИМ ключом d_attacker
        (в _on_challenge, pending_action='atk_vote'), а центр проверит
        по ключу настоящего избирателя → подпись не совпадёт → атака отражена.
        """
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
        # Устанавливаем pending_action='atk_vote', чтобы _on_challenge
        # знал, что нужно подписывать ключом злоумышленника и отправить свой fi
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
