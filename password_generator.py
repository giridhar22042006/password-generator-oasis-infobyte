"""
Project 3: Random Password Generator (Beginner + Advanced)
Oasis Infobyte - Python Programming Internship
---------------------------------------------------
Features:
  - Configurable length (8–64)
  - Toggle: uppercase, lowercase, digits, symbols
  - Exclude specific characters
  - Password strength meter
  - One-click clipboard copy
  - Generate multiple passwords at once
  - Password history (session)
  - GUI via Tkinter  |  CLI fallback

Requirements:
    Python 3.7+  (tkinter included in stdlib)
    pip install pyperclip   (optional — for clipboard on Linux)
"""

import secrets
import string
import tkinter as tk
from tkinter import messagebox, font as tkfont

# ── Password Logic ────────────────────────────────────────────────────────────

CHAR_SETS = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "digits":    string.digits,
    "symbols":   "!@#$%^&*()-_=+[]{}|;:,.<>?",
}


def build_charset(include: dict[str, bool], exclude: str = "") -> str:
    chars = "".join(v for k, v in CHAR_SETS.items() if include.get(k, True))
    if exclude:
        chars = "".join(c for c in chars if c not in exclude)
    return chars


def generate_password(
    length: int,
    include: dict[str, bool],
    exclude: str = "",
) -> str:
    charset = build_charset(include, exclude)
    if not charset:
        raise ValueError("No characters available. Enable at least one character type.")

    # Guarantee at least one char from each enabled group
    required = []
    for key, chars in CHAR_SETS.items():
        if include.get(key, True):
            pool = "".join(c for c in chars if c not in exclude)
            if pool:
                required.append(secrets.choice(pool))

    if len(required) > length:
        required = required[:length]

    rest = [secrets.choice(charset) for _ in range(length - len(required))]
    combined = required + rest
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)


def strength(password: str) -> tuple[int, str, str]:
    """
    Returns (score 0-4, label, hex color).
    Score based on length, variety, and entropy.
    """
    score = 0
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_sym   = any(c in CHAR_SETS["symbols"] for c in password)

    score += sum([has_upper, has_lower, has_digit, has_sym])
    if len(password) >= 12:
        score += 1
    if len(password) >= 20:
        score += 1

    if score <= 2:
        return 1, "Weak",   "#E24B4A"
    elif score == 3:
        return 2, "Fair",   "#EF9F27"
    elif score == 4:
        return 3, "Strong", "#1D9E75"
    else:
        return 4, "Very strong", "#0B6E4F"


# ── GUI ───────────────────────────────────────────────────────────────────────

class PasswordApp(tk.Tk):
    C = {
        "bg":      "#0d1117",
        "panel":   "#161b22",
        "border":  "#30363d",
        "accent":  "#58a6ff",
        "green":   "#3fb950",
        "text":    "#c9d1d9",
        "muted":   "#8b949e",
        "entry":   "#21262d",
        "danger":  "#f85149",
    }
    HEIGHTS = {"btn": 36, "entry": 38}

    def __init__(self):
        super().__init__()
        self.title("Password Generator — Oasis Infobyte")
        self.resizable(False, False)
        self.configure(bg=self.C["bg"])
        self._history: list[str] = []
        self._build()
        self._center(500, 680)
        self._generate()

    def _center(self, w, h):
        self.geometry(f"{w}x{h}")
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _label(self, parent, text, size=11, muted=False, **kw):
        return tk.Label(
            parent, text=text,
            font=("Helvetica", size),
            fg=self.C["muted"] if muted else self.C["text"],
            bg=parent.cget("bg"), **kw
        )

    def _row(self, parent, **kw):
        f = tk.Frame(parent, bg=parent.cget("bg"), **kw)
        f.pack(fill="x")
        return f

    def _toggle(self, parent, text: str, var: tk.BooleanVar):
        cb = tk.Checkbutton(
            parent, text=text, variable=var,
            font=("Helvetica", 11),
            fg=self.C["text"], bg=parent.cget("bg"),
            activeforeground=self.C["accent"],
            activebackground=parent.cget("bg"),
            selectcolor=self.C["entry"],
            cursor="hand2",
            command=self._generate
        )
        cb.pack(side="left", padx=(0, 16))
        return cb

    def _btn(self, parent, text, cmd, color=None, **kw):
        b = tk.Button(
            parent, text=text, command=cmd,
            font=("Helvetica", 11, "bold"),
            bg=color or self.C["accent"],
            fg=self.C["bg"],
            activebackground=self.C["panel"],
            activeforeground=self.C["text"],
            relief="flat", bd=0, cursor="hand2",
            pady=8, **kw
        )
        b.pack(**kw)
        return b

    # ── Build UI ─────────────────────────────────────────────────────────────

    def _build(self):
        C = self.C

        # Header
        header = tk.Frame(self, bg=C["bg"], pady=20)
        header.pack(fill="x")
        tk.Label(header, text="🔐 Password Generator",
                 font=("Helvetica", 20, "bold"),
                 fg=C["accent"], bg=C["bg"]).pack()
        tk.Label(header, text="Secure  •  Customizable  •  Instant",
                 font=("Helvetica", 10), fg=C["muted"], bg=C["bg"]).pack()

        # Main panel
        pnl = tk.Frame(self, bg=C["panel"],
                       highlightbackground=C["border"], highlightthickness=1,
                       padx=24, pady=20)
        pnl.pack(fill="x", padx=20)

        # Length
        len_row = self._row(pnl)
        self._label(len_row, "Length").pack(side="left")
        self.len_var = tk.IntVar(value=16)
        self.len_display = self._label(len_row, "16", muted=True)
        self.len_display.pack(side="right")
        self.len_scale = tk.Scale(
            pnl, from_=4, to=64, orient="horizontal",
            variable=self.len_var,
            bg=C["panel"], fg=C["text"], troughcolor=C["entry"],
            highlightthickness=0, sliderlength=18, bd=0,
            activebackground=C["accent"],
            command=lambda v: (self.len_display.config(text=v), self._generate())
        )
        self.len_scale.pack(fill="x", pady=(4, 12))

        # Character options
        self._label(pnl, "Include").pack(anchor="w")
        opt_row = tk.Frame(pnl, bg=C["panel"])
        opt_row.pack(fill="x", pady=(4, 12))
        self.opt_upper  = tk.BooleanVar(value=True)
        self.opt_lower  = tk.BooleanVar(value=True)
        self.opt_digits = tk.BooleanVar(value=True)
        self.opt_sym    = tk.BooleanVar(value=True)
        self._toggle(opt_row, "A–Z",  self.opt_upper)
        self._toggle(opt_row, "a–z",  self.opt_lower)
        self._toggle(opt_row, "0–9",  self.opt_digits)
        self._toggle(opt_row, "!@#…", self.opt_sym)

        # Exclude
        excl_row = self._row(pnl)
        self._label(excl_row, "Exclude chars").pack(side="left")
        self.excl_var = tk.StringVar()
        self.excl_var.trace_add("write", lambda *_: self._generate())
        tk.Entry(
            pnl, textvariable=self.excl_var,
            font=("Courier", 12), bg=C["entry"], fg=C["text"],
            insertbackground=C["text"], relief="flat", bd=6
        ).pack(fill="x", pady=(4, 0))

        # Count
        count_row = self._row(pnl)
        self._label(count_row, "How many?").pack(side="left")
        self.count_var = tk.IntVar(value=1)
        for n in (1, 3, 5, 10):
            rb = tk.Radiobutton(
                count_row, text=str(n), value=n, variable=self.count_var,
                bg=C["panel"], fg=C["text"], selectcolor=C["entry"],
                activebackground=C["panel"], activeforeground=C["accent"],
                font=("Helvetica", 11), cursor="hand2",
                command=self._generate
            )
            rb.pack(side="left", padx=(12, 0))

        # Output area
        out_frame = tk.Frame(self, bg=C["bg"])
        out_frame.pack(fill="both", expand=True, padx=20, pady=(16, 0))

        self.result_box = tk.Text(
            out_frame, font=("Courier", 13), bg=C["entry"], fg=C["green"],
            insertbackground=C["text"], relief="flat", bd=0,
            padx=14, pady=12, wrap="word", height=6,
            state="disabled", cursor="arrow"
        )
        self.result_box.pack(fill="both", expand=True)

        # Strength bar
        strength_frame = tk.Frame(self, bg=C["bg"], pady=6)
        strength_frame.pack(fill="x", padx=20)
        self._label(strength_frame, "Strength", muted=True).pack(side="left")
        self.strength_bar = tk.Canvas(strength_frame, height=10, bg=C["entry"],
                                      highlightthickness=0)
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=(8, 8))
        self.strength_label = self._label(strength_frame, "", muted=True)
        self.strength_label.pack(side="right")

        # Action buttons
        btn_frame = tk.Frame(self, bg=C["bg"])
        btn_frame.pack(fill="x", padx=20, pady=12)
        tk.Button(
            btn_frame, text="↻  Regenerate",
            command=self._generate,
            font=("Helvetica", 11, "bold"),
            bg=C["accent"], fg=C["bg"],
            activebackground="#79b8ff", relief="flat", bd=0,
            cursor="hand2", pady=9
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(
            btn_frame, text="⎘  Copy",
            command=self._copy,
            font=("Helvetica", 11, "bold"),
            bg=C["green"], fg=C["bg"],
            activebackground="#56d364", relief="flat", bd=0,
            cursor="hand2", pady=9
        ).pack(side="left", fill="x", expand=True, padx=(6, 0))

        # History
        tk.Button(
            self, text="🕓  View Session History",
            command=self._show_history,
            font=("Helvetica", 10),
            bg=C["panel"], fg=C["muted"],
            activebackground=C["border"], activeforeground=C["text"],
            relief="flat", bd=0, cursor="hand2", pady=7
        ).pack(fill="x", padx=20, pady=(0, 16))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _generate(self, *_):
        include = {
            "uppercase": self.opt_upper.get(),
            "lowercase": self.opt_lower.get(),
            "digits":    self.opt_digits.get(),
            "symbols":   self.opt_sym.get(),
        }
        if not any(include.values()):
            self._show_result("Enable at least one character type!", color=self.C["danger"])
            return

        count  = self.count_var.get()
        length = self.len_var.get()
        excl   = self.excl_var.get()

        passwords = []
        for _ in range(count):
            try:
                passwords.append(generate_password(length, include, excl))
            except ValueError as e:
                self._show_result(str(e), color=self.C["danger"])
                return

        self._history.extend(passwords)
        result = "\n".join(passwords)
        self._show_result(result)

        # Update strength for first password
        sc, label, color = strength(passwords[0])
        self._update_strength(sc, label, color)

    def _show_result(self, text: str, color: str = None):
        self.result_box.config(state="normal")
        self.result_box.delete("1.0", "end")
        self.result_box.insert("1.0", text)
        if color:
            self.result_box.config(fg=color)
        else:
            self.result_box.config(fg=self.C["green"])
        self.result_box.config(state="disabled")

    def _update_strength(self, score: int, label: str, color: str):
        self.strength_bar.update_idletasks()
        w = self.strength_bar.winfo_width() or 200
        fill_w = int((score / 4) * w)
        self.strength_bar.delete("all")
        self.strength_bar.create_rectangle(0, 0, fill_w, 10, fill=color, outline="")
        self.strength_label.config(text=label, fg=color)

    def _copy(self):
        content = self.result_box.get("1.0", "end").strip()
        if not content:
            return
        first_pw = content.split("\n")[0]
        try:
            import pyperclip
            pyperclip.copy(first_pw)
        except ImportError:
            self.clipboard_clear()
            self.clipboard_append(first_pw)
        messagebox.showinfo("Copied!", "Password copied to clipboard.")

    def _show_history(self):
        if not self._history:
            messagebox.showinfo("History", "No passwords generated this session.")
            return
        win = tk.Toplevel(self)
        win.title("Session History")
        win.configure(bg=self.C["bg"])
        win.geometry("420x360")
        tk.Label(win, text="Session Passwords", font=("Helvetica", 14, "bold"),
                 fg=self.C["accent"], bg=self.C["bg"]).pack(pady=10)
        box = tk.Text(win, font=("Courier", 11), bg=self.C["entry"],
                      fg=self.C["green"], relief="flat", padx=12, pady=8)
        box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        for i, pw in enumerate(reversed(self._history[-20:]), 1):
            box.insert("end", f"{i:>2}. {pw}\n")
        box.config(state="disabled")


# ── CLI fallback ──────────────────────────────────────────────────────────────

def cli_mode():
    print("\n" + "=" * 55)
    print("  PASSWORD GENERATOR — Oasis Infobyte (CLI Mode)")
    print("=" * 55)
    try:
        length = int(input("Password length [16]: ").strip() or "16")
    except ValueError:
        length = 16
    n_str = input("How many passwords? [1]: ").strip() or "1"
    count = int(n_str) if n_str.isdigit() else 1
    excl = input("Exclude characters (leave blank for none): ").strip()

    include = {"uppercase": True, "lowercase": True, "digits": True, "symbols": True}
    print()
    for _ in range(count):
        pw = generate_password(length, include, excl)
        sc, label, _ = strength(pw)
        print(f"  {pw}  [{label}]")


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        app = PasswordApp()
        app.mainloop()
    except tk.TclError:
        print("[No display — CLI mode]")
        cli_mode()
