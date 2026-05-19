"""
Сервер Избиркома — Центр электронного голосования на основе гомоморфного RSA-протокола.

Протокол электронного голосования с обеспечением:
  - Аутентификации избирателей по схеме «Вызов-Ответ» (Challenge-Response)
    на основе цифровой подписи RSA;
  - Конфиденциальности бюллетеня шифрованием RSA с открытым ключом центра;
  - Подсчёта голосов без расшифровки отдельных бюллетеней благодаря
    гомоморфному свойству RSA.

Использование RSA в протоколе:
  1) Шифрование бюллетеней: избиратель шифрует голос b открытым ключом
     центра (e_center, n_center), получая fi = b^e mod n. Благодаря
     гомоморфности: произведение зашифрованных бюллетеней
     F = fi1 * fi2 * ... * fik mod n  равно шифрованию произведения
     открытых текстов  F = (b1*b2*...*bk)^e mod n.
  2) Цифровая подпись: избиратель подписывает случайный вызов (challenge)
     своим секретным ключом d_voter: signature = challenge^d mod n.
     Центр проверяет подпись открытым ключом избирателя:
     signature^e_voter mod n_voter == challenge.

Схема аутентификации «Вызов-Ответ» (Challenge-Response):
  - Регистрация: избиратель отправляет свой открытый ключ (e, n).
  - Центр генерирует случайный challenge и отправляет его избирателю.
  - Избиратель подписывает challenge своим секретным ключом d:
    signature = challenge^d mod n, и отправляет signature обратно.
  - Центр проверяет: signature^e mod n == challenge.
  Если проверка пройдена — аутентификация успешна.

Слепое подписание бюллетеня (на стороне клиента):
  - Избиратель формирует бюллетень: ti = b * qi, где b — голос (2 или 3),
    qi — случайное простое число >= 5 (фактор слепоты).
  - Шифрование: fi = ti^e_center mod n_center.
  - Благодаря гомоморфности RSA при перемножении зашифрованных бюллетеней
    qi сокращаются (попарные qi обратимы mod n), и результат зависит
    только от произведения голосов.

Правила публикации:
  - Список избирателей (с открытыми ключами) публикуется ДО начала
    голосования, чтобы каждый мог проверить право участия.
  - Таблица зашифрованных бюллетеней публикуется ТОЛЬКО ПОСЛЕ завершения
    голосования (не после каждого голоса!), чтобы предотвратить
    отслеживание порядка голосования.

Подсчёт голосов:
  - F = произведение всех fi mod n  (гомоморфное произведение).
  - Q = F^d mod n  (расшифровка секретным ключом центра).
  - Q = 2^r * 3^P * R  (факторизация Q).
    где r — число голосов «За» (код 2), P — число голосов «Против» (код 3),
    R — контрольное число (должно быть свободно от 2 и 3).
  - Число воздержавшихся = N - r - P.

Потокобезопасность GUI:
  - Сетевые потоки НЕ вызывают методы tkinter напрямую.
  - Вместо этого используется очередь: _schedule(fn) помещает функцию
    в очередь, а _poll() (вызываемый через root.after) выполняет её
    в главном потоке tkinter. Это предотвращает гонки данных и
    исключает TclError при обновлении виджетов из сетевых потоков.

Обработка сообщений:
  - Каждый метод _on_* обрабатывает определённый тип сообщения
    от клиента (тип определяется полем 'type' в сообщении).
  - _dispatch() маршрутизирует входящие сообщения по соответствующим
    обработчикам.
"""

import tkinter as tk
from tkinter import ttk
import socket
import threading
import queue
from datetime import datetime
from shared import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    LCG, send_msg, MsgReceiver
)

_server_lcg = LCG()


class VotingServer:
    """Центр электронного голосования (Избирком).

    Атрибуты:
        center_keys:       RSA-ключи центра (e, d, n). Открытый (e, n)
                           используется избирателями для шифрования бюллетеней,
                           секретный d — для расшифровки при подсчёте.
        registered_voters: Словарь зарегистрированных избирателей:
                           {voter_id: {pub_e, pub_n, challenge, authenticated, ...}}.
                           Публикуется ДО начала голосования.
        received_ballots:  Словарь принятых зашифрованных бюллетеней:
                           {voter_id: fi}. Публикуется ПОСЛЕ завершения голосования.
        client_sockets:    Активные соединения с клиентами.
        client_threads:    Потоки обработки клиентов.
        voting_active:     Флаг: голосование активно (принимаются бюллетени).
        voting_ended:      Флаг: голосование завершено (бюллетени больше не принимаются).
        ballots_published: Флаг: таблица бюллетеней опубликована.
        q:                 Очередь функций для потокобезопасного обновления GUI.
    """

    def __init__(self, root):
        """Инициализация сервера: создание переменных состояния и GUI."""
        self.root = root
        self.root.title("Избирком — Центр электронного голосования")
        self.root.geometry("1150x900")
        self.root.minsize(950, 700)

        # RSA-ключи центра: e (открытый), d (секретный), n (модуль)
        self.center_keys = None
        # Реестр избирателей: ключи, challenge, статус аутентификации
        self.registered_voters = {}
        # Принятые зашифрованные бюллетени: voter_id -> fi
        self.received_ballots = {}
        # Активные клиентские соединения и потоки
        self.client_sockets = {}
        self.client_threads = {}

        # Результаты подсчёта голосов
        self.counting_done = False   # Подсчёт выполнен?
        self.count_r = None          # Число голосов «За» (степень двойки)
        self.count_P = None          # Число голосов «Против» (степень тройки)
        self.count_R = None          # Контрольное число (свободно от 2 и 3)
        self.count_F = None          # Гомоморфное произведение зашифрованных бюллетеней

        # Фазы голосования
        self.voting_active = False   # Голосование активно — бюллетени принимаются
        self.voting_ended = False    # Голосование завершено — бюллетени НЕ принимаются
        self.ballots_published = False  # Таблица бюллетеней опубликована

        # Сетевые ресурсы
        self.server_socket = None    # Серверный сокет (слушающий)
        self.running = False         # Флаг работы сервера
        self.q = queue.Queue()       # Очередь для потокобезопасных обновлений GUI

        self._build_gui()
        self._poll()  # Запуск цикла опроса очереди GUI

    def _poll(self):
        """Опрос очереди функций для потокобезопасного обновления GUI.

        Вызывается каждые 50 мс через root.after(). Извлекает все
        функции из очереди и выполняет их в главном потоке tkinter,
        предотвращая TclError при обновлении виджетов из сетевых потоков.
        """
        while not self.q.empty():
            fn = self.q.get_nowait()
            try:
                fn()
            except tk.TclError:
                pass
        self.root.after(50, self._poll)

    def _schedule(self, fn):
        """Поместить функцию в очередь для отложенного выполнения в GUI-потоке.

        Используется сетевыми потоками вместо прямого вызова методов tkinter,
        что обеспечивает потокобезопасность. Функция fn будет вызвана
        в _poll() на следующей итерации (в течение ~50 мс).
        """
        self.q.put(fn)

    def _txt(self, parent, height=8):
        """Создать виджет Text с полосой прокрутки. Возвращает объект Text."""
        f = ttk.Frame(parent)
        f.pack(fill=tk.BOTH, expand=True, padx=3, pady=2)
        t = tk.Text(f, height=height, wrap=tk.WORD, font=('Consolas', 9))
        sb = ttk.Scrollbar(f, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        return t

    def _log(self, w, msg):
        """Потокобезопасная запись сообщения в виджет Text w.

        Использует _schedule() для безопасного обновления GUI
        из любого потока (включая сетевые).
        """
        def _do():
            w.insert(tk.END, msg + "\n")
            w.see(tk.END)
        self._schedule(_do)

    # ==================== Построение GUI ====================

    def _build_gui(self):
        """Построение интерфейса: три вкладки — Настройка, Голосование, Подсчёт."""
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # --- Вкладка 1: Настройка и регистрация ---
        t1 = ttk.Frame(nb)
        nb.add(t1, text=" Настройка и регистрация ")

        # Настройки сервера: IP, порт, кнопки запуска/остановки
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

        # Ключи избиркома: генерация RSA-ключей (1024 бит)
        kf = ttk.LabelFrame(t1, text="Ключи избиркома")
        kf.pack(fill=tk.X, padx=5, pady=5)
        kr = ttk.Frame(kf)
        kr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(kr, text="Сгенерировать ключи RSA (1024 бит)", command=self._gen_keys).pack(side=tk.LEFT, padx=3)
        self.key_status = ttk.Label(kr, text="Ключи не сгенерированы", foreground='red')
        self.key_status.pack(side=tk.LEFT, padx=10)
        self.key_log = self._txt(kf, height=6)

        # Список избирателей — публикуется ДО голосования
        rf = ttk.LabelFrame(t1, text="Список зарегистрированных избирателей (публикация до голосования)")
        rf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Таблица: ID, открытый ключ e, модуль n, статус аутентификации
        cols = ("ID", "Открытый ключ e", "Открытый ключ n", "Статус")
        self.voter_tree = ttk.Treeview(rf, columns=cols, show='headings', height=6)
        for c in cols:
            self.voter_tree.heading(c, text=c)
            self.voter_tree.column(c, width=180 if c != "ID" else 50)
        self.voter_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self.reg_log = self._txt(rf, height=6)

        # --- Вкладка 2: Голосование ---
        t2 = ttk.Frame(nb)
        nb.add(t2, text=" Голосование ")

        # Управление фазой голосования: начало/конец
        vf = ttk.LabelFrame(t2, text="Управление голосованием")
        vf.pack(fill=tk.X, padx=5, pady=5)

        vr1 = ttk.Frame(vf)
        vr1.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(vr1, text="Начало:").pack(side=tk.LEFT)
        self.start_time_var = tk.StringVar(value=datetime.now().strftime("%d.%m.%Y %H:%M"))
        ttk.Entry(vr1, textvariable=self.start_time_var, width=16).pack(side=tk.LEFT, padx=3)
        ttk.Label(vr1, text="Конец:").pack(side=tk.LEFT)
        self.end_time_var = tk.StringVar(value="")
        ttk.Entry(vr1, textvariable=self.end_time_var, width=16).pack(side=tk.LEFT, padx=3)
        ttk.Label(vr1, text="формат: DD.MM.YYYY HH:MM").pack(side=tk.LEFT, padx=3)

        vr2 = ttk.Frame(vf)
        vr2.pack(fill=tk.X, padx=5, pady=3)
        self.btn_start_vote = ttk.Button(vr2, text="Начать голосование", command=self._start_voting)
        self.btn_start_vote.pack(side=tk.LEFT, padx=5)
        self.btn_end_vote = ttk.Button(vr2, text="Завершить и опубликовать бюллетени", command=self._end_voting, state=tk.DISABLED)
        self.btn_end_vote.pack(side=tk.LEFT, padx=5)
        self.vote_phase_label = ttk.Label(vr2, text="Голосование не начато", foreground='red')
        self.vote_phase_label.pack(side=tk.LEFT, padx=10)

        # Таблица зашифрованных бюллетеней — публикуется ПОСЛЕ голосования
        bf = ttk.LabelFrame(t2, text="Таблица зашифрованных бюллетеней (публикация после голосования)")
        bf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Таблица: ID избирателя, fi (зашифрованный бюллетень)
        bcols = ("ID избирателя", "fi (зашифрованный бюллетень)")
        self.ballot_tree = ttk.Treeview(bf, columns=bcols, show='headings', height=6)
        for c in bcols:
            self.ballot_tree.heading(c, text=c)
            self.ballot_tree.column(c, width=400)
        self.ballot_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self.vote_log = self._txt(t2, height=8)

        # --- Вкладка 3: Подсчёт и проверка ---
        t3 = ttk.Frame(nb)
        nb.add(t3, text=" Подсчёт и проверка ")

        cr = ttk.Frame(t3)
        cr.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(cr, text="Подсчитать голоса", command=self._count_votes).pack(side=tk.LEFT, padx=5)
        self.cnt_status = ttk.Label(cr, text="Ожидание", foreground='red')
        self.cnt_status.pack(side=tk.LEFT, padx=10)

        self.cnt_log = self._txt(t3, height=22)

    # ==================== Управление сервером ====================

    def _start_server(self):
        """Запуск TCP-сервера: привязка к адресу, начало приёма соединений.

        Проверяет: (1) сервер ещё не запущен, (2) ключи RSA сгенерированы,
        (3) порт корректен. Запускает поток приёма соединений _accept_loop.
        """
        if self.running:
            self._log(self.vote_log, "Сервер уже запущен!")
            return
        if self.center_keys is None:
            self._log(self.vote_log, "ОШИБКА: Сначала сгенерируйте ключи!")
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            self._log(self.vote_log, "ОШИБКА: Неверный порт!")
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

        # Запуск потока приёма клиентских подключений
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _stop_server(self):
        """Остановка сервера: закрытие всех клиентских соединений и серверного сокета."""
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
        """Цикл приёма клиентских подключений (работает в отдельном потоке).

        Для каждого нового клиента:
        1. Принимает соединение и сохраняет сокет.
        2. Отправляет открытый ключ центра (e_center, n_center) —
           нужен клиенту для шифрования бюллетеня.
        3. Запускает поток _handle_client для обработки сообщений клиента.
        """
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
                # Немедленно отправляем открытый ключ центра новому клиенту
                # (e, n) — избиратель будет шифровать им бюллетень
                send_msg(conn, {
                    'type': 'center_key',
                    'e': self.center_keys['e'],
                    'n': self.center_keys['n']
                })
            except (ConnectionError, OSError):
                continue
            # Запуск потока обработки сообщений данного клиента
            t = threading.Thread(target=self._handle_client, args=(conn, cid), daemon=True)
            self.client_threads[cid] = t
            t.start()

    def _handle_client(self, conn, cid):
        """Цикл обработки сообщений от одного клиента (в отдельном потоке).

        Читает сообщения через MsgReceiver и маршрутизирует их
        через _dispatch(). При отключении клиента — закрывает сокет
        и удаляет из словаря.
        """
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
        """Маршрутизация входящего сообщения по типу к соответствующему обработчику.

        Типы сообщений:
          'register'      -> _on_register   : запрос регистрации избирателя
          'signature'     -> _on_signature  : ответ на challenge (цифровая подпись)
          'vote_request'  -> _on_vote_request: запрос на голосование
          'vote_response' -> _on_vote_response: ответ на vote_challenge (подпись + бюллетень)
          'get_voter_list' -> _on_get_voter_list: запрос списка избирателей
          'get_table'     -> _on_get_table  : запрос таблицы бюллетеней
          'get_results'   -> _on_get_results: запрос результатов подсчёта
        """
        t = msg.get('type')
        if t == 'register':
            self._on_register(msg, conn)
        elif t == 'signature':
            self._on_signature(msg, conn)
        elif t == 'vote_request':
            self._on_vote_request(msg, conn)
        elif t == 'vote_response':
            self._on_vote_response(msg, conn)
        elif t == 'get_voter_list':
            self._on_get_voter_list(conn)
        elif t == 'get_table':
            self._on_get_table(conn)
        elif t == 'get_results':
            self._on_get_results(conn)

    # ==================== Регистрация (Challenge-Response) ====================

    def _on_register(self, msg, conn):
        """Обработка запроса на регистрацию избирателя.

        Шаг 1 схемы «Вызов-Ответ»:
        - Избиратель присылает свой ID и открытый ключ RSA (e, n).
        - Если регистрация допустима (голосование ещё не началось, ID уникален),
          центр генерирует случайный challenge (128 бит) и отправляет его.
        - Challenge сохраняется в registered_voters для последующей проверки
          подписи в _on_signature().

        Отказ в регистрации возможен по причинам:
        - Голосование уже началось (voting_active) или завершено (voting_ended).
        - Избиратель с таким ID уже зарегистрирован.
        """
        vid = msg['voter_id']
        pub_e = msg['pub_e']   # Открытая экспонента избирателя
        pub_n = msg['pub_n']   # Модуль RSA избирателя

        self._log(self.reg_log, f"--- Запрос регистрации от избирателя {vid} ---")

        # Отказ: голосование уже началось — регистрация запрещена
        if self.voting_active or self.voting_ended:
            self._log(self.reg_log, f"  ОТКАЗ: Регистрация завершена! Голосование уже началось.")
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': 'Регистрация завершена! Голосование уже началось.'})
            except (ConnectionError, OSError):
                pass
            return

        # Отказ: избиратель уже зарегистрирован (повторная регистрация)
        if vid in self.registered_voters:
            self._log(self.reg_log, f"  ОТКАЗ: Избиратель {vid} уже зарегистрирован!")
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': f'Избиратель {vid} уже зарегистрирован!'})
            except (ConnectionError, OSError):
                pass
            return

        # Генерация случайного challenge (128 бит) для аутентификации
        # Избиратель должен будет подписать его своим секретным ключом d_voter
        challenge = _server_lcg.getrandbits(128)
        self.registered_voters[vid] = {
            'pub_e': pub_e, 'pub_n': pub_n,
            'challenge': challenge, 'authenticated': False
        }

        self._log(self.reg_log, f"  Получен открытый ключ: e={pub_e}, n={pub_n}")
        self._log(self.reg_log, f"  Отправлен вызов (challenge): {challenge}")

        # Отправка challenge избирателю — шаг 2 схемы «Вызов-Ответ»
        try:
            send_msg(conn, {'type': 'challenge', 'challenge': challenge})
        except (ConnectionError, OSError):
            pass

    def _on_signature(self, msg, conn):
        """Обработка цифровой подписи избирателя (шаг 3 Challenge-Response).

        Избиратель подписал challenge своим секретным ключом d_voter:
          signature = challenge^d_voter mod n_voter

        Центр проверяет подпись с помощью открытого ключа избирателя:
          signature^e_voter mod n_voter == challenge

        Если проверка успешна — избиратель аутентифицирован.
        Если нет — запись удаляется из реестра.

        Примечание: rsa_encrypt(signature, pub_e, pub_n) вычисляет
        signature^e mod n, что для проверки подписи RSA эквивалентно
        «шифрованию подписи открытым ключом» для восстановления
        исходного сообщения (challenge).
        """
        vid = msg['voter_id']
        signature = msg['signature']  # signature = challenge^d_voter mod n_voter

        if vid not in self.registered_voters:
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': 'Избиратель не найден!'})
            except (ConnectionError, OSError):
                pass
            return

        info = self.registered_voters[vid]
        challenge = info['challenge']    # Оригинальный challenge, отправленный избирателю
        pub_e = info['pub_e']            # Открытая экспонента избирателя e_voter
        pub_n = info['pub_n']            # Модуль RSA избирателя n_voter

        self._log(self.reg_log, f"--- Проверка подписи избирателя {vid} ---")
        self._log(self.reg_log, f"  signature = {signature}")

        # Проверка: signature^e_voter mod n_voter == challenge
        # rsa_encrypt(x, e, n) = x^e mod n — восстановление challenge из подписи
        verified = rsa_encrypt(signature, pub_e, pub_n) == challenge
        self._log(self.reg_log, f"  signature^e mod n = {rsa_encrypt(signature, pub_e, pub_n)}")
        self._log(self.reg_log, f"  challenge        = {challenge}")
        self._log(self.reg_log, f"  Результат: {'УСПЕШНО' if verified else 'НЕУДАЧА'}")

        if verified:
            # Аутентификация пройдена — избиратель допущен к голосованию
            info['authenticated'] = True
            self._update_voter_tree(vid, pub_e, pub_n, "Зарегистрирован ✓")
        else:
            # Аутентификация не пройдена — удаляем из реестра
            del self.registered_voters[vid]
            self._update_voter_tree(vid, pub_e, pub_n, "Ошибка аутентификации ✗")

        try:
            send_msg(conn, {'type': 'auth_result', 'success': verified,
                            'message': 'Аутентификация успешна!' if verified else
                            'Аутентификация не пройдена! Подпись неверна.'})
        except (ConnectionError, OSError):
            pass

    # ==================== Управление фазой голосования ====================

    def _start_voting(self):
        """Начало фазы голосования: voting_active = True.

        Проверки:
        - Сервер запущен.
        - Голосование ещё не началось.
        - Есть хотя бы один аутентифицированный избиратель.

        После начала: регистрация новых избирателей запрещена,
        бюллетени принимаются (voting_active=True).
        Всем подключённым клиентам отправляется уведомление
        'voting_started' со списком допущенных избирателей.
        """
        if not self.running:
            self._log(self.vote_log, "ОШИБКА: Сначала запустите сервер!")
            return
        if self.voting_active:
            self._log(self.vote_log, "Голосование уже начато!")
            return

        # Формируем список аутентифицированных избирателей
        authenticated = [vid for vid, info in self.registered_voters.items() if info.get('authenticated')]
        if not authenticated:
            self._log(self.vote_log, "ОШИБКА: Нет зарегистрированных избирателей!")
            return

        # Активация фазы голосования — теперь бюллетени принимаются
        self.voting_active = True
        self._log(self.vote_log, f"\n{'='*50}")
        self._log(self.vote_log, "ГОЛОСОВАНИЕ НАЧАЛОСЬ!")
        self._log(self.vote_log, f"Список избирателей: {sorted(authenticated)}")
        self._log(self.vote_log, f"{'='*50}\n")

        self._schedule(lambda: self.vote_phase_label.configure(text="Голосование АКТИВНО", foreground='green'))
        self._schedule(lambda: self.btn_start_vote.configure(state=tk.DISABLED))
        self._schedule(lambda: self.btn_end_vote.configure(state=tk.NORMAL))

        # Уведомление всех клиентов о начале голосования
        # и отправка списка допущенных избирателей (для проверки)
        for cid, conn in list(self.client_sockets.items()):
            try:
                send_msg(conn, {
                    'type': 'voting_started',
                    'voters': sorted(authenticated)
                })
            except (ConnectionError, OSError):
                pass

    def _end_voting(self):
        """Завершение голосования и публикация таблицы бюллетеней.

        Устанавливает voting_active=False, voting_ended=True.
        После завершения бюллетени больше НЕ принимаются.
        Таблица зашифрованных бюллетеней публикуется ОДНОМОМЕНТНО
        (не после каждого голоса!) — это предотвращает отслеживание
        порядка голосования. Каждому клиенту отправляются:
        - Список бюллетеней (voter_id, fi)
        - Открытый ключ центра (e, n) — для проверки гомоморфности.
        """
        if not self.voting_active:
            return

        # Деактивация приёма бюллетеней
        self.voting_active = False
        self.voting_ended = True

        self._log(self.vote_log, f"\n{'='*50}")
        self._log(self.vote_log, "ГОЛОСОВАНИЕ ЗАВЕРШЕНО!")
        self._log(self.vote_log, f"Получено бюллетеней: {len(self.received_ballots)}")
        self._log(self.vote_log, f"{'='*50}\n")

        # Публикация таблицы бюллетеней (только после завершения!)
        self._update_ballot_tree()
        self.ballots_published = True

        self._schedule(lambda: self.vote_phase_label.configure(text="Голосование завершено, бюллетени опубликованы", foreground='blue'))
        self._schedule(lambda: self.btn_end_vote.configure(state=tk.DISABLED))

        # Формирование и отправка таблицы бюллетеней всем клиентам
        # ballots: [[voter_id, fi], ...] — зашифрованные бюллетени
        # center_e, center_n — открытый ключ для проверки
        ballots = [[vid, fi] for vid, fi in sorted(self.received_ballots.items())]
        for cid, conn in list(self.client_sockets.items()):
            try:
                send_msg(conn, {
                    'type': 'ballots_published',
                    'ballots': ballots,
                    'center_e': self.center_keys['e'],
                    'center_n': self.center_keys['n']
                })
            except (ConnectionError, OSError):
                pass

    # ==================== Приём бюллетеней ====================

    def _on_vote_request(self, msg, conn):
        """Обработка запроса на голосование от избирателя.

        Шаг 1 протокола голосования: избиратель запрашивает право проголосовать.
        Проверки:
        - Голосование активно (voting_active=True) — бюллетени принимаются
          ТОЛЬКО в активной фазе.
        - Избиратель зарегистрирован и аутентифицирован.
        - Избиратель ещё не голосовал (защита от двойного голосования).

        При успехе — генерируется vote_challenge (128 бит) и отправляется
        избирателю. Это вторая аутентификация «Вызов-Ответ» при голосовании:
        избиратель должен подписать challenge своим секретным ключом d_voter
        и отправить подпись вместе с зашифрованным бюллетенем fi.
        """
        vid = msg['voter_id']

        self._log(self.vote_log, f"--- Запрос голосования от избирателя {vid} ---")

        # Проверка: голосование активно (временное ограничение)
        # Бюллетени принимаются ТОЛЬКО когда voting_active=True
        if not self.voting_active:
            reason = "Голосование ещё не началось!" if not self.voting_ended else "Голосование уже завершено! Бюллетень принята вне срока!"
            self._log(self.vote_log, f"  ОТКАЗ: {reason}")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False, 'message': reason})
            except (ConnectionError, OSError):
                pass
            return

        # Проверка: избиратель зарегистрирован
        if vid not in self.registered_voters:
            self._log(self.vote_log, f"  ОТКАЗ: Избиратель {vid} не зарегистрирован!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': f'Избиратель {vid} не зарегистрирован!'})
            except (ConnectionError, OSError):
                pass
            return

        # Проверка: избиратель прошёл аутентификацию при регистрации
        if not self.registered_voters[vid]['authenticated']:
            self._log(self.vote_log, f"  ОТКАЗ: Аутентификация не пройдена!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Аутентификация не пройдена!'})
            except (ConnectionError, OSError):
                pass
            return

        # Проверка: защита от двойного голосования
        if vid in self.received_ballots:
            self._log(self.vote_log, f"  ОТКАЗ: Двойное голосование!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': f'Избиратель {vid} уже голосовал!'})
            except (ConnectionError, OSError):
                pass
            return

        # Генерация vote_challenge для повторной аутентификации
        # при отправке бюллетеня (схема «Вызов-Ответ»)
        challenge = _server_lcg.getrandbits(128)
        self.registered_voters[vid]['vote_challenge'] = challenge

        self._log(self.vote_log, f"  Аутентификация: отправлен вызов {challenge}")

        # Отправка challenge избирателю
        try:
            send_msg(conn, {'type': 'vote_challenge', 'challenge': challenge})
        except (ConnectionError, OSError):
            pass

    def _on_vote_response(self, msg, conn):
        """Обработка ответа на vote_challenge: подпись + зашифрованный бюллетень.

        Шаг 2 протокола голосования: избиратель отправляет:
        - signature: подпись vote_challenge секретным ключом d_voter
          (signature = vote_challenge^d_voter mod n_voter)
        - fi: зашифрованный бюллетень.
          fi = ti^e_center mod n_center, где ti = b * qi,
          b — голос (2=«За», 3=«Против»), qi — случайное простое >= 5
          (фактор слепоты, маскирует голос b).

        Центр проверяет:
        1. Подпись: signature^e_voter mod n_voter == vote_challenge
        2. Двойное голосование: избиратель ещё не подавал бюллетень.

        При успешной проверке бюллетень fi сохраняется в received_ballots.
        Таблица бюллетеней НЕ публикуется после каждого голоса —
        только по завершении голосования (_end_voting).
        """
        vid = msg['voter_id']
        signature = msg['signature']  # signature = challenge^d_voter mod n_voter
        fi = msg['fi']                # fi = ti^e_center mod n_center (зашифрованный бюллетень)

        # Проверка: избиратель зарегистрирован
        if vid not in self.registered_voters:
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Избиратель не найден!'})
            except (ConnectionError, OSError):
                pass
            return

        info = self.registered_voters[vid]
        # Получаем vote_challenge, отправленный в _on_vote_request()
        challenge = info.get('vote_challenge')
        if challenge is None:
            # Нет активного запроса на голосование — подозрительная ситуация
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Нет активного запроса!'})
            except (ConnectionError, OSError):
                pass
            return

        pub_e = info['pub_e']  # e_voter — для проверки подписи
        pub_n = info['pub_n']  # n_voter — модуль RSA избирателя

        self._log(self.vote_log, f"--- Проверка подписи при голосовании (избиратель {vid}) ---")
        self._log(self.vote_log, f"  signature = {signature}")

        # Проверка цифровой подписи: signature^e_voter mod n_voter == challenge
        verified = rsa_encrypt(signature, pub_e, pub_n) == challenge
        self._log(self.vote_log, f"  signature^e mod n = {rsa_encrypt(signature, pub_e, pub_n)}")
        self._log(self.vote_log, f"  challenge        = {challenge}")
        self._log(self.vote_log, f"  Результат: {'УСПЕШНО' if verified else 'НЕУДАЧА'}")

        if verified:
            # Повторная проверка на двойное голосование (на случай гонки)
            if vid in self.received_ballots:
                self._log(self.vote_log, f"  ОТКАЗ: Двойное голосование!")
                try:
                    send_msg(conn, {'type': 'vote_result', 'success': False,
                                    'message': 'Двойное голосование!'})
                except (ConnectionError, OSError):
                    pass
                return

            # Бюллетень принят: fi сохраняется, но НЕ публикуется немедленно
            # Таблица будет опубликована только по завершении голосования
            self.received_ballots[vid] = fi
            self._log(self.vote_log, f"  Бюллетень принят: fi = {fi}")

            try:
                send_msg(conn, {'type': 'vote_result', 'success': True,
                                'message': 'Голос принят!'})
            except (ConnectionError, OSError):
                pass
        else:
            # Подпись неверна — бюллетень отклонён
            self._log(self.vote_log, f"  ОТКАЗ: Аутентификация не пройдена! Голос отклонён.")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': 'Аутентификация не пройдена! Подпись неверна.'})
            except (ConnectionError, OSError):
                pass

        # Удаление vote_challenge — предотвращает повторное использование
        info.pop('vote_challenge', None)

    # ==================== Запросы данных: список избирателей, таблица, результаты ====================

    def _on_get_voter_list(self, conn):
        """Отправка списка зарегистрированных аутентифицированных избирателей.

        Список публикуется ДО начала голосования, чтобы каждый мог
        проверить право участия. Содержит ID и открытые ключи (e, n)
        для проверки подписей других избирателей.
        """
        voters = []
        for vid, info in sorted(self.registered_voters.items()):
            if info.get('authenticated'):
                voters.append({'id': vid, 'pub_e': info['pub_e'], 'pub_n': info['pub_n']})
        try:
            send_msg(conn, {'type': 'voter_list', 'voters': voters})
        except (ConnectionError, OSError):
            pass

    def _on_get_table(self, conn):
        """Отправка таблицы зашифрованных бюллетеней.

        Таблица доступна ТОЛЬКО после завершения голосования
        (ballots_published=True). До этого — пустой список.
        Правило: публикация после завершения, не после каждого голоса!
        Вместе с бюллетенями отправляется открытый ключ центра (e, n)
        для проверки гомоморфного свойства клиентом.
        """
        if not self.ballots_published:
            try:
                send_msg(conn, {'type': 'table', 'ballots': [],
                                'center_e': self.center_keys['e'],
                                'center_n': self.center_keys['n'],
                                'message': 'Бюллетени ещё не опубликованы! Голосование ещё не завершено.'})
            except (ConnectionError, OSError):
                pass
            return
        # Таблица: [[voter_id, fi], ...] + открытый ключ центра
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
        """Отправка результатов подсчёта голосов клиенту.

        Доступно только после выполнения _count_votes() (counting_done=True).
        Отправляются: r (За), P (Против), R (контрольное), F (гомоморфное
        произведение), таблица бюллетеней, открытый ключ центра.
        """
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

    # ==================== Подсчёт голосов ====================

    def _count_votes(self):
        """Подсчёт голосов с использованием гомоморфного свойства RSA.

        Алгоритм подсчёта (без расшифровки отдельных бюллетеней):

        Шаг 1: F = произведение всех fi mod n
          Гомоморфное свойство RSA:
          fi = ti^e mod n,  поэтому  F = (t1*t2*...*tk)^e mod n
          Произведение зашифрованных = шифрование произведения.

        Шаг 2: Q = F^d mod n  (расшифровка секретным ключом центра)
          Q = t1*t2*...*tk = (b1*q1)*(b2*q2)*...*(bk*qk)
          где bi — голос (2 или 3), qi — фактор слепоты (простое >= 5).
          Поскольку qi — простые, отличные от 2 и 3, они не влияют
          на степени 2 и 3 в разложении Q. Поэтому:
          Q = 2^r * 3^P * R, где r — число «За», P — число «Против».

        Шаг 3: Факторизация Q
          Извлекаем r (степень двойки) и P (степень тройки).
          R — контрольное число, должно быть свободно от 2 и 3.
          Число воздержавшихся = N - r - P.

        Контрольная проверка: 2^r * 3^P * R == Q
        """
        w = self.cnt_log
        if self.center_keys is None:
            self._log(w, "ОШИБКА: Ключи не сгенерированы!")
            return
        if not self.received_ballots:
            self._log(w, "ОШИБКА: Нет бюллетеней!")
            return

        self._schedule(lambda: w.delete('1.0', tk.END))

        n_c = self.center_keys['n']  # Модуль RSA центра
        d_c = self.center_keys['d']  # Секретный ключ центра (для расшифровки)

        self._log(w, "=== Подсчёт голосов ===\n")

        # Шаг 1: Гомоморфное произведение зашифрованных бюллетеней
        # F = fi1 * fi2 * ... * fik mod n
        # Благодаря гомоморфности: F = (t1*t2*...*tk)^e mod n
        self._log(w, "Шаг 1: F = произведение всех fi mod n")
        F = 1
        for vid, fi in sorted(self.received_ballots.items()):
            self._log(w, f"  fi({vid}) = {fi}")
            F = (F * fi) % n_c  # Гомоморфное умножение mod n
        self.count_F = F
        self._log(w, f"\n  F = {F}\n")

        # Шаг 2: Расшифровка гомоморфного произведения
        # Q = F^d mod n — применяем секретный ключ центра
        # Q = t1*t2*...*tk = произведение открытых текстов бюллетеней
        self._log(w, "Шаг 2: Q = F^d mod n  (расшифровка секретным ключом)")
        Q = rsa_decrypt(F, d_c, n_c)
        self._log(w, f"  Q = {Q}\n")

        # Шаг 3: Факторизация Q = 2^r * 3^P * R
        # Голос «За» кодируется как b=2, «Против» — b=3.
        # Факторы слепоты qi — простые >= 5, не влияют на степени 2 и 3.
        # Поэтому r = число голосов «За», P = число голосов «Против».
        self._log(w, "Шаг 3: Факторизация Q = 2^r * 3^P * R")
        temp = Q
        r = 0
        # Подсчёт степени двойки (число голосов «За»)
        while temp > 0 and temp % 2 == 0:
            r += 1
            temp //= 2
        P = 0
        # Подсчёт степени тройки (число голосов «Против»)
        while temp > 0 and temp % 3 == 0:
            P += 1
            temp //= 3
        # Оставшееся число R — контрольное (произведение qi и возможных
        # «воздержавшихся» бюллетеней с b=1). Должно быть свободно от 2 и 3.
        R = temp

        self.count_r = r
        self.count_P = P
        self.count_R = R
        self.counting_done = True

        # Число воздержавшихся = всего бюллетеней - «За» - «Против»
        N = len(self.received_ballots)
        abstained = N - r - P

        self._log(w, f"  r (За)           = {r}")
        self._log(w, f"  P (Против)       = {P}")
        self._log(w, f"  Воздержались     = {abstained}")
        self._log(w, f"  R (контрольное)  = {R}")
        # Контрольная проверка: R не должно делиться на 2 или 3
        self._log(w, f"  R % 2 == 0? {R % 2 == 0}")
        self._log(w, f"  R % 3 == 0? {R % 3 == 0}")

        # Верификация: 2^r * 3^P * R должно равняться Q
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

    # ==================== Генерация ключей ====================

    def _gen_keys(self):
        """Генерация RSA-ключей избиркома (1024 бит).

        Ключи используются для:
        - Шифрования бюллетеней: избиратель шифрует ti открытым ключом (e, n).
        - Расшифровки при подсчёте: центр расшифровывает F секретным ключом d.
        Открытый ключ (e, n) отправляется каждому клиенту при подключении.
        """
        self._log(self.key_log, "Генерация RSA-ключей избиркома (1024 бит)...")
        self.root.update()
        self.center_keys = generate_rsa_keys(1024)
        self._log(self.key_log, f"Открытый ключ: e={self.center_keys['e']}")
        self._log(self.key_log, f"  n={self.center_keys['n']}")
        self._log(self.key_log, f"Секретный ключ: d={self.center_keys['d']}")
        self._log(self.key_log, f"  n={self.center_keys['n']}")
        self._schedule(lambda: self.key_status.configure(
            text="Ключи сгенерированы ✓", foreground='green'))

    # ==================== Обновление таблиц GUI ====================

    def _update_voter_tree(self, vid, pub_e, pub_n, status):
        """Потокобезопасное добавление записи в таблицу избирателей.

        Использует _schedule() для безопасного обновления Treeview
        из сетевого потока.
        """
        def _do():
            self.voter_tree.insert('', tk.END, values=(vid, pub_e, pub_n, status))
        self._schedule(_do)

    def _update_ballot_tree(self):
        """Потокобезопасное обновление таблицы бюллетеней после завершения голосования.

        Очищает таблицу и заполняет её всеми принятыми зашифрованными
        бюллетенями (fi). Вызывается один раз при _end_voting().
        Использует _schedule() для безопасного обновления Treeview.
        """
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
    # Режим --auto: автоматическая генерация ключей и запуск сервера
    if "--auto" in sys.argv:
        app._gen_keys()
        root.update()
        app._start_server()
    root.mainloop()
