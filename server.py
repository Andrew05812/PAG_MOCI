import tkinter as tk
from tkinter import ttk
import socket
import threading
import queue
import random
from datetime import datetime
from shared import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    send_msg, MsgReceiver
)


class VotingServer:
    def __init__(self, root):
        self.root = root
        self.root.title("\u0418\u0437\u0431\u0438\u0440\u043a\u043e\u043c \u2014 \u0426\u0435\u043d\u0442\u0440 \u044d\u043b\u0435\u043a\u0442\u0440\u043e\u043d\u043d\u043e\u0433\u043e \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u044f")
        self.root.geometry("1150x900")
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

        self.voting_active = False
        self.voting_ended = False
        self.ballots_published = False

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

        # --- Tab 1: Setup & Registration ---
        t1 = ttk.Frame(nb)
        nb.add(t1, text=" \u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430 \u0438 \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f ")

        sf = ttk.LabelFrame(t1, text="\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u0441\u0435\u0440\u0432\u0435\u0440\u0430")
        sf.pack(fill=tk.X, padx=5, pady=5)

        row1 = ttk.Frame(sf)
        row1.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(row1, text="IP:").pack(side=tk.LEFT)
        self.ip_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(row1, textvariable=self.ip_var, width=14).pack(side=tk.LEFT, padx=3)
        ttk.Label(row1, text="\u041f\u043e\u0440\u0442:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="9999")
        ttk.Entry(row1, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=3)
        ttk.Button(row1, text="\u0417\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c \u0441\u0435\u0440\u0432\u0435\u0440", command=self._start_server).pack(side=tk.LEFT, padx=8)
        ttk.Button(row1, text="\u041e\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c", command=self._stop_server).pack(side=tk.LEFT, padx=3)
        self.srv_status = ttk.Label(row1, text="\u0421\u0435\u0440\u0432\u0435\u0440 \u043d\u0435 \u0437\u0430\u043f\u0443\u0449\u0435\u043d", foreground='red')
        self.srv_status.pack(side=tk.LEFT, padx=10)

        kf = ttk.LabelFrame(t1, text="\u041a\u043b\u044e\u0447\u0438 \u0438\u0437\u0431\u0438\u0440\u043a\u043e\u043c\u0430")
        kf.pack(fill=tk.X, padx=5, pady=5)
        kr = ttk.Frame(kf)
        kr.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(kr, text="\u0421\u0433\u0435\u043d\u0435\u0440\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u043a\u043b\u044e\u0447\u0438 RSA (1024 \u0431\u0438\u0442)", command=self._gen_keys).pack(side=tk.LEFT, padx=3)
        self.key_status = ttk.Label(kr, text="\u041a\u043b\u044e\u0447\u0438 \u043d\u0435 \u0441\u0433\u0435\u043d\u0435\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u044b", foreground='red')
        self.key_status.pack(side=tk.LEFT, padx=10)
        self.key_log = self._txt(kf, height=6)

        rf = ttk.LabelFrame(t1, text="\u0421\u043f\u0438\u0441\u043e\u043a \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u0435\u0439 (\u043f\u0443\u0431\u043b\u0438\u043a\u0430\u0446\u0438\u044f \u0434\u043e \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u044f)")
        rf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        cols = ("ID", "\u041e\u0442\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447 e", "\u041e\u0442\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447 n", "\u0421\u0442\u0430\u0442\u0443\u0441")
        self.voter_tree = ttk.Treeview(rf, columns=cols, show='headings', height=6)
        for c in cols:
            self.voter_tree.heading(c, text=c)
            self.voter_tree.column(c, width=180 if c != "ID" else 50)
        self.voter_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self.reg_log = self._txt(rf, height=6)

        # --- Tab 2: Voting ---
        t2 = ttk.Frame(nb)
        nb.add(t2, text=" \u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 ")

        # Voting phase controls
        vf = ttk.LabelFrame(t2, text="\u0423\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u0435 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435\u043c")
        vf.pack(fill=tk.X, padx=5, pady=5)

        vr1 = ttk.Frame(vf)
        vr1.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(vr1, text="\u041d\u0430\u0447\u0430\u043b\u043e:").pack(side=tk.LEFT)
        self.start_time_var = tk.StringVar(value=datetime.now().strftime("%d.%m.%Y %H:%M"))
        ttk.Entry(vr1, textvariable=self.start_time_var, width=16).pack(side=tk.LEFT, padx=3)
        ttk.Label(vr1, text="\u041a\u043e\u043d\u0435\u0446:").pack(side=tk.LEFT)
        self.end_time_var = tk.StringVar(value="")
        ttk.Entry(vr1, textvariable=self.end_time_var, width=16).pack(side=tk.LEFT, padx=3)
        ttk.Label(vr1, text="\u0444\u043e\u0440\u043c\u0430\u0442: DD.MM.YYYY HH:MM").pack(side=tk.LEFT, padx=3)

        vr2 = ttk.Frame(vf)
        vr2.pack(fill=tk.X, padx=5, pady=3)
        self.btn_start_vote = ttk.Button(vr2, text="\u041d\u0430\u0447\u0430\u0442\u044c \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435", command=self._start_voting)
        self.btn_start_vote.pack(side=tk.LEFT, padx=5)
        self.btn_end_vote = ttk.Button(vr2, text="\u0417\u0430\u0432\u0435\u0440\u0448\u0438\u0442\u044c \u0438 \u043e\u043f\u0443\u0431\u043b\u0438\u043a\u043e\u0432\u0430\u0442\u044c \u0431\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u0438", command=self._end_voting, state=tk.DISABLED)
        self.btn_end_vote.pack(side=tk.LEFT, padx=5)
        self.vote_phase_label = ttk.Label(vr2, text="\u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u043d\u0435 \u043d\u0430\u0447\u0430\u0442\u043e", foreground='red')
        self.vote_phase_label.pack(side=tk.LEFT, padx=10)

        bf = ttk.LabelFrame(t2, text="\u0422\u0430\u0431\u043b\u0438\u0446\u0430 \u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u0431\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u0435\u0439 (\u043f\u0443\u0431\u043b\u0438\u043a\u0430\u0446\u0438\u044f \u043f\u043e\u0441\u043b\u0435 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u044f)")
        bf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        bcols = ("ID \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044f", "fi (\u0437\u0430\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0431\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u044c)")
        self.ballot_tree = ttk.Treeview(bf, columns=bcols, show='headings', height=6)
        for c in bcols:
            self.ballot_tree.heading(c, text=c)
            self.ballot_tree.column(c, width=400)
        self.ballot_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        self.vote_log = self._txt(t2, height=8)

        # --- Tab 3: Counting ---
        t3 = ttk.Frame(nb)
        nb.add(t3, text=" \u041f\u043e\u0434\u0441\u0447\u0451\u0442 \u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 ")

        cr = ttk.Frame(t3)
        cr.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(cr, text="\u041f\u043e\u0434\u0441\u0447\u0438\u0442\u0430\u0442\u044c \u0433\u043e\u043b\u043e\u0441\u0430", command=self._count_votes).pack(side=tk.LEFT, padx=5)
        self.cnt_status = ttk.Label(cr, text="\u041e\u0436\u0438\u0434\u0430\u043d\u0438\u0435", foreground='red')
        self.cnt_status.pack(side=tk.LEFT, padx=10)

        self.cnt_log = self._txt(t3, height=22)

    # ==================== Server controls ====================

    def _start_server(self):
        if self.running:
            self._log(self.vote_log, "\u0421\u0435\u0440\u0432\u0435\u0440 \u0443\u0436\u0435 \u0437\u0430\u043f\u0443\u0449\u0435\u043d!")
            return
        if self.center_keys is None:
            self._log(self.vote_log, "\u041e\u0428\u0418\u0411\u041a\u0410: \u0421\u043d\u0430\u0447\u0430\u043b\u0430 \u0441\u0433\u0435\u043d\u0435\u0440\u0438\u0440\u0443\u0439\u0442\u0435 \u043a\u043b\u044e\u0447\u0438!")
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            self._log(self.vote_log, "\u041e\u0428\u0418\u0411\u041a\u0410: \u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043f\u043e\u0440\u0442!")
            return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.ip_var.get(), port))
        except OSError as e:
            self._log(self.vote_log, f"\u041e\u0428\u0418\u0411\u041a\u0410 \u043f\u0440\u0438\u0432\u044f\u0437\u043a\u0438: {e}")
            return
        self.server_socket.listen(10)
        self.running = True
        self.srv_status.configure(text=f"\u0421\u0435\u0440\u0432\u0435\u0440 \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 :{port}", foreground='green')
        self._log(self.vote_log, f"\u0421\u0435\u0440\u0432\u0435\u0440 \u0437\u0430\u043f\u0443\u0449\u0435\u043d \u043d\u0430 {self.ip_var.get()}:{port}")

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
        self.srv_status.configure(text="\u0421\u0435\u0440\u0432\u0435\u0440 \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d", foreground='red')

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
            self._log(self.vote_log, f"\u041f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435: {cid}")
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
                self._log(self.vote_log, f"\u041e\u0442\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435: {cid}")
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
        elif t == 'get_voter_list':
            self._on_get_voter_list(conn)
        elif t == 'get_table':
            self._on_get_table(conn)
        elif t == 'get_results':
            self._on_get_results(conn)

    # ==================== Registration ====================

    def _on_register(self, msg, conn):
        vid = msg['voter_id']
        pub_e = msg['pub_e']
        pub_n = msg['pub_n']

        self._log(self.reg_log, f"--- \u0417\u0430\u043f\u0440\u043e\u0441 \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u0438 \u043e\u0442 \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044f {vid} ---")

        if self.voting_active or self.voting_ended:
            self._log(self.reg_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0430! \u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0443\u0436\u0435 \u043d\u0430\u0447\u0430\u043b\u043e\u0441\u044c.")
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': '\u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0430! \u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0443\u0436\u0435 \u043d\u0430\u0447\u0430\u043b\u043e\u0441\u044c.'})
            except (ConnectionError, OSError):
                pass
            return

        if vid in self.registered_voters:
            self._log(self.reg_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c {vid} \u0443\u0436\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d!")
            try:
                send_msg(conn, {'type': 'auth_result', 'success': False,
                                'message': f'\u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c {vid} \u0443\u0436\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d!'})
            except (ConnectionError, OSError):
                pass
            return

        challenge = random.getrandbits(128)
        self.registered_voters[vid] = {
            'pub_e': pub_e, 'pub_n': pub_n,
            'challenge': challenge, 'authenticated': False
        }

        self._log(self.reg_log, f"  \u041f\u043e\u043b\u0443\u0447\u0435\u043d \u043e\u0442\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447: e={pub_e}, n={pub_n}")
        self._log(self.reg_log, f"  \u041e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d \u0432\u044b\u0437\u043e\u0432 (challenge): {challenge}")

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
                                'message': '\u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d!'})
            except (ConnectionError, OSError):
                pass
            return

        info = self.registered_voters[vid]
        challenge = info['challenge']
        pub_e = info['pub_e']
        pub_n = info['pub_n']

        self._log(self.reg_log, f"--- \u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043f\u043e\u0434\u043f\u0438\u0441\u0438 \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044f {vid} ---")
        self._log(self.reg_log, f"  signature = {signature}")

        verified = rsa_encrypt(signature, pub_e, pub_n) == challenge
        self._log(self.reg_log, f"  signature^e mod n = {rsa_encrypt(signature, pub_e, pub_n)}")
        self._log(self.reg_log, f"  challenge        = {challenge}")
        self._log(self.reg_log, f"  \u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442: {'\u0423\u0421\u041f\u0415\u0428\u041d\u041e' if verified else '\u041d\u0415\u0423\u0414\u0410\u0427\u0410'}")

        if verified:
            info['authenticated'] = True
            self._update_voter_tree(vid, pub_e, pub_n, "\u0417\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d \u2713")
        else:
            del self.registered_voters[vid]
            self._update_voter_tree(vid, pub_e, pub_n, "\u041e\u0448\u0438\u0431\u043a\u0430 \u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u0438 \u2717")

        try:
            send_msg(conn, {'type': 'auth_result', 'success': verified,
                            'message': '\u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u0443\u0441\u043f\u0435\u0448\u043d\u0430!' if verified else
                            '\u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u043d\u0435 \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u0430! \u041f\u043e\u0434\u043f\u0438\u0441\u044c \u043d\u0435\u0432\u0435\u0440\u043d\u0430.'})
        except (ConnectionError, OSError):
            pass

    # ==================== Voting Phase Control ====================

    def _start_voting(self):
        if not self.running:
            self._log(self.vote_log, "\u041e\u0428\u0418\u0411\u041a\u0410: \u0421\u043d\u0430\u0447\u0430\u043b\u0430 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0441\u0435\u0440\u0432\u0435\u0440!")
            return
        if self.voting_active:
            self._log(self.vote_log, "\u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0443\u0436\u0435 \u043d\u0430\u0447\u0430\u0442\u043e!")
            return

        authenticated = [vid for vid, info in self.registered_voters.items() if info.get('authenticated')]
        if not authenticated:
            self._log(self.vote_log, "\u041e\u0428\u0418\u0411\u041a\u0410: \u041d\u0435\u0442 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u0435\u0439!")
            return

        self.voting_active = True
        self._log(self.vote_log, f"\n{'='*50}")
        self._log(self.vote_log, "\u0413\u041e\u041b\u041e\u0421\u041e\u0412\u0410\u041d\u0418\u0415 \u041d\u0410\u0427\u0410\u041b\u041e\u0421\u042c!")
        self._log(self.vote_log, f"\u0421\u043f\u0438\u0441\u043e\u043a \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u0435\u0439: {sorted(authenticated)}")
        self._log(self.vote_log, f"{'='*50}\n")

        self._schedule(lambda: self.vote_phase_label.configure(text="\u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0410\u041a\u0422\u0418\u0412\u041d\u041e", foreground='green'))
        self._schedule(lambda: self.btn_start_vote.configure(state=tk.DISABLED))
        self._schedule(lambda: self.btn_end_vote.configure(state=tk.NORMAL))

        for cid, conn in list(self.client_sockets.items()):
            try:
                send_msg(conn, {
                    'type': 'voting_started',
                    'voters': sorted(authenticated)
                })
            except (ConnectionError, OSError):
                pass

    def _end_voting(self):
        if not self.voting_active:
            return

        self.voting_active = False
        self.voting_ended = True

        self._log(self.vote_log, f"\n{'='*50}")
        self._log(self.vote_log, "\u0413\u041e\u041b\u041e\u0421\u041e\u0412\u0410\u041d\u0418\u0415 \u0417\u0410\u0412\u0415\u0420\u0428\u0415\u041d\u041e!")
        self._log(self.vote_log, f"\u041f\u043e\u043b\u0443\u0447\u0435\u043d\u043e \u0431\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u0435\u0439: {len(self.received_ballots)}")
        self._log(self.vote_log, f"{'='*50}\n")

        self._update_ballot_tree()
        self.ballots_published = True

        self._schedule(lambda: self.vote_phase_label.configure(text="\u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e, \u0431\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u0438 \u043e\u043f\u0443\u0431\u043b\u0438\u043a\u043e\u0432\u0430\u043d\u044b", foreground='blue'))
        self._schedule(lambda: self.btn_end_vote.configure(state=tk.DISABLED))

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

    # ==================== Voting ====================

    def _on_vote_request(self, msg, conn):
        vid = msg['voter_id']

        self._log(self.vote_log, f"--- \u0417\u0430\u043f\u0440\u043e\u0441 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u044f \u043e\u0442 \u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044f {vid} ---")

        if not self.voting_active:
            reason = "\u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0435\u0449\u0451 \u043d\u0435 \u043d\u0430\u0447\u0430\u043b\u043e\u0441\u044c!" if not self.voting_ended else "\u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0443\u0436\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e! \u0411\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u044c \u043f\u0440\u0438\u043d\u044f\u0442\u0430 \u0432\u043d\u0435 \u0441\u0440\u043e\u043a\u0430!"
            self._log(self.vote_log, f"  \u041e\u0422\u041a\u0410\u0417: {reason}")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False, 'message': reason})
            except (ConnectionError, OSError):
                pass
            return

        if vid not in self.registered_voters:
            self._log(self.vote_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c {vid} \u043d\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': f'\u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c {vid} \u043d\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043e\u0432\u0430\u043d!'})
            except (ConnectionError, OSError):
                pass
            return

        if not self.registered_voters[vid]['authenticated']:
            self._log(self.vote_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u043d\u0435 \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u0430!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': '\u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u043d\u0435 \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u0430!'})
            except (ConnectionError, OSError):
                pass
            return

        if vid in self.received_ballots:
            self._log(self.vote_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0414\u0432\u043e\u0439\u043d\u043e\u0435 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435!")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': f'\u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c {vid} \u0443\u0436\u0435 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043b!'})
            except (ConnectionError, OSError):
                pass
            return

        challenge = random.getrandbits(128)
        self.registered_voters[vid]['vote_challenge'] = challenge

        self._log(self.vote_log, f"  \u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f: \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d \u0432\u044b\u0437\u043e\u0432 {challenge}")

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
                                'message': '\u0418\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d!'})
            except (ConnectionError, OSError):
                pass
            return

        info = self.registered_voters[vid]
        challenge = info.get('vote_challenge')
        if challenge is None:
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': '\u041d\u0435\u0442 \u0430\u043a\u0442\u0438\u0432\u043d\u043e\u0433\u043e \u0437\u0430\u043f\u0440\u043e\u0441\u0430!'})
            except (ConnectionError, OSError):
                pass
            return

        pub_e = info['pub_e']
        pub_n = info['pub_n']

        self._log(self.vote_log, f"--- \u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043f\u043e\u0434\u043f\u0438\u0441\u0438 \u043f\u0440\u0438 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0438 (\u0438\u0437\u0431\u0438\u0440\u0430\u0442\u0435\u043b\u044c {vid}) ---")
        self._log(self.vote_log, f"  signature = {signature}")

        verified = rsa_encrypt(signature, pub_e, pub_n) == challenge
        self._log(self.vote_log, f"  signature^e mod n = {rsa_encrypt(signature, pub_e, pub_n)}")
        self._log(self.vote_log, f"  challenge        = {challenge}")
        self._log(self.vote_log, f"  \u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442: {'\u0423\u0421\u041f\u0415\u0428\u041d\u041e' if verified else '\u041d\u0415\u0423\u0414\u0410\u0427\u0410'}")

        if verified:
            if vid in self.received_ballots:
                self._log(self.vote_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0414\u0432\u043e\u0439\u043d\u043e\u0435 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435!")
                try:
                    send_msg(conn, {'type': 'vote_result', 'success': False,
                                    'message': '\u0414\u0432\u043e\u0439\u043d\u043e\u0435 \u0433\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435!'})
                except (ConnectionError, OSError):
                    pass
                return

            self.received_ballots[vid] = fi
            self._log(self.vote_log, f"  \u0411\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u044c \u043f\u0440\u0438\u043d\u044f\u0442: fi = {fi}")

            try:
                send_msg(conn, {'type': 'vote_result', 'success': True,
                                'message': '\u0413\u043e\u043b\u043e\u0441 \u043f\u0440\u0438\u043d\u044f\u0442!'})
            except (ConnectionError, OSError):
                pass
        else:
            self._log(self.vote_log, f"  \u041e\u0422\u041a\u0410\u0417: \u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u043d\u0435 \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u0430! \u0413\u043e\u043b\u043e\u0441 \u043e\u0442\u043a\u043b\u043e\u043d\u0451\u043d.")
            try:
                send_msg(conn, {'type': 'vote_result', 'success': False,
                                'message': '\u0410\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u043d\u0435 \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u0430! \u041f\u043e\u0434\u043f\u0438\u0441\u044c \u043d\u0435\u0432\u0435\u0440\u043d\u0430.'})
            except (ConnectionError, OSError):
                pass

        info.pop('vote_challenge', None)

    # ==================== Voter list & Table ====================

    def _on_get_voter_list(self, conn):
        voters = []
        for vid, info in sorted(self.registered_voters.items()):
            if info.get('authenticated'):
                voters.append({'id': vid, 'pub_e': info['pub_e'], 'pub_n': info['pub_n']})
        try:
            send_msg(conn, {'type': 'voter_list', 'voters': voters})
        except (ConnectionError, OSError):
            pass

    def _on_get_table(self, conn):
        if not self.ballots_published:
            try:
                send_msg(conn, {'type': 'table', 'ballots': [],
                                'center_e': self.center_keys['e'],
                                'center_n': self.center_keys['n'],
                                'message': '\u0411\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u0438 \u0435\u0449\u0451 \u043d\u0435 \u043e\u043f\u0443\u0431\u043b\u0438\u043a\u043e\u0432\u0430\u043d\u044b! \u0413\u043e\u043b\u043e\u0441\u043e\u0432\u0430\u043d\u0438\u0435 \u0435\u0449\u0451 \u043d\u0435 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u043e.'})
            except (ConnectionError, OSError):
                pass
            return
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
                send_msg(conn, {'type': 'error', 'message': '\u041f\u043e\u0434\u0441\u0447\u0451\u0442 \u0435\u0449\u0451 \u043d\u0435 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d!'})
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
            self._log(w, "\u041e\u0428\u0418\u0411\u041a\u0410: \u041a\u043b\u044e\u0447\u0438 \u043d\u0435 \u0441\u0433\u0435\u043d\u0435\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u044b!")
            return
        if not self.received_ballots:
            self._log(w, "\u041e\u0428\u0418\u0411\u041a\u0410: \u041d\u0435\u0442 \u0431\u044e\u043b\u043b\u0435\u0442\u0435\u043d\u0435\u0439!")
            return

        self._schedule(lambda: w.delete('1.0', tk.END))

        n_c = self.center_keys['n']
        d_c = self.center_keys['d']

        self._log(w, "=== \u041f\u043e\u0434\u0441\u0447\u0451\u0442 \u0433\u043e\u043b\u043e\u0441\u043e\u0432 ===\n")

        self._log(w, "\u0428\u0430\u0433 1: F = \u043f\u0440\u043e\u0438\u0437\u0432\u0435\u0434\u0435\u043d\u0438\u0435 \u0432\u0441\u0435\u0445 fi mod n")
        F = 1
        for vid, fi in sorted(self.received_ballots.items()):
            self._log(w, f"  fi({vid}) = {fi}")
            F = (F * fi) % n_c
        self.count_F = F
        self._log(w, f"\n  F = {F}\n")

        self._log(w, "\u0428\u0430\u0433 2: Q = F^d mod n  (\u0440\u0430\u0441\u0448\u0438\u0444\u0440\u043e\u0432\u043a\u0430 \u0441\u0435\u043a\u0440\u0435\u0442\u043d\u044b\u043c \u043a\u043b\u044e\u0447\u043e\u043c)")
        Q = rsa_decrypt(F, d_c, n_c)
        self._log(w, f"  Q = {Q}\n")

        self._log(w, "\u0428\u0430\u0433 3: \u0424\u0430\u043a\u0442\u043e\u0440\u0438\u0437\u0430\u0446\u0438\u044f Q = 2^r * 3^P * R")
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

        self._log(w, f"  r (\u0417\u0430)           = {r}")
        self._log(w, f"  P (\u041f\u0440\u043e\u0442\u0438\u0432)       = {P}")
        self._log(w, f"  \u0412\u043e\u0437\u0434\u0435\u0440\u0436\u0430\u043b\u0438\u0441\u044c     = {abstained}")
        self._log(w, f"  R (\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u043e\u0435)  = {R}")
        self._log(w, f"  R % 2 == 0? {R % 2 == 0}")
        self._log(w, f"  R % 3 == 0? {R % 3 == 0}")

        self._log(w, f"\n\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: 2^{r} * 3^{P} * {R} = {(2 ** r) * (3 ** P) * R}")
        self._log(w, f"Q = {Q}")
        self._log(w, f"\u0421\u043e\u0432\u043f\u0430\u0434\u0435\u043d\u0438\u0435: {((2 ** r) * (3 ** P) * R) == Q}\n")

        self._log(w, "=" * 50)
        self._log(w, "         \u0420\u0415\u0417\u0423\u041b\u042c\u0422\u0410\u0422\u042b \u0413\u041e\u041b\u041e\u0421\u041e\u0412\u0410\u041d\u0418\u042f")
        self._log(w, "=" * 50)
        self._log(w, f"  \u0417\u0430:            {r}")
        self._log(w, f"  \u041f\u0440\u043e\u0442\u0438\u0432:        {P}")
        self._log(w, f"  \u0412\u043e\u0437\u0434\u0435\u0440\u0436\u0430\u043b\u0438\u0441\u044c:  {abstained}")
        self._log(w, f"  \u041a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u043e\u0435 R: {R}")
        self._log(w, "=" * 50)

        self._schedule(lambda: self.cnt_status.configure(
            text="\u041f\u043e\u0434\u0441\u0447\u0451\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d \u2713", foreground='green'))

    # ==================== Key generation ====================

    def _gen_keys(self):
        self._log(self.key_log, "\u0413\u0435\u043d\u0435\u0440\u0430\u0446\u0438\u044f RSA-\u043a\u043b\u044e\u0447\u0435\u0439 \u0438\u0437\u0431\u0438\u0440\u043a\u043e\u043c\u0430 (1024 \u0431\u0438\u0442)...")
        self.root.update()
        self.center_keys = generate_rsa_keys(1024)
        self._log(self.key_log, f"\u041e\u0442\u043a\u0440\u044b\u0442\u044b\u0439 \u043a\u043b\u044e\u0447: e={self.center_keys['e']}")
        self._log(self.key_log, f"  n={self.center_keys['n']}")
        self._log(self.key_log, f"\u0421\u0435\u043a\u0440\u0435\u0442\u043d\u044b\u0439 \u043a\u043b\u044e\u0447: d={self.center_keys['d']}")
        self._log(self.key_log, f"  n={self.center_keys['n']}")
        self._schedule(lambda: self.key_status.configure(
            text="\u041a\u043b\u044e\u0447\u0438 \u0441\u0433\u0435\u043d\u0435\u0440\u0438\u0440\u043e\u0432\u0430\u043d\u044b \u2713", foreground='green'))

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
