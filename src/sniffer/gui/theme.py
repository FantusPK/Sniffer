"""Dark-theme colour palette, fonts, and ttk style configuration."""

from __future__ import annotations

from tkinter import ttk

# ── colours ───────────────────────────────────────────────────────────

BG = "#1a1a1a"
PANEL = "#242424"
BORDER = "#333333"
ACCENT = "#e8a020"
TEXT = "#e0e0e0"
MUTED = "#888888"
DANGER = "#cc3333"
SUCCESS = "#2a9d4e"
INPUT_BG = "#2a2a2a"
LOG_BG = "#0d0d0d"
FOOTER_BG = "#111111"

# ── fonts ─────────────────────────────────────────────────────────────

FONT_MONO = ("Courier New", 10)
FONT_MONO_SM = ("Courier New", 9)
FONT_MONO_XS = ("Courier New", 8)
FONT_TITLE = ("Courier New", 18, "bold")
FONT_BTN = ("Courier New", 11, "bold")
FONT_BTN_SM = ("Courier New", 10)
FONT_STAT = ("Courier New", 14, "bold")
FONT_REFRESH = ("Courier New", 12)


# ── ttk style setup ──────────────────────────────────────────────────

def apply(root) -> None:  # noqa: ANN001 – tk.Tk but avoids import
    """Apply the dark theme to all ttk widgets under *root*."""
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure("TFrame", background=BG)
    style.configure(
        "TLabel", background=BG, foreground=TEXT, font=FONT_MONO,
    )
    style.configure(
        "TEntry",
        fieldbackground=INPUT_BG,
        foreground=TEXT,
        insertcolor=TEXT,
        font=FONT_MONO,
    )
    style.configure(
        "TCombobox",
        fieldbackground=INPUT_BG,
        foreground=TEXT,
        font=FONT_MONO,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", INPUT_BG)],
        foreground=[("readonly", TEXT)],
    )
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=PANEL,
        foreground=MUTED,
        font=FONT_MONO,
        padding=[12, 6],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", BG)],
        foreground=[("selected", ACCENT)],
    )
