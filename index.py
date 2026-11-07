"""
Scanner Rápido - verificação rápida de arquivos suspeitos (Windows/Linux/Mac).
Como usar: python scanner_rapido.py

O que ele faz:
 1. Varre pastas de risco (Downloads, Desktop, Temp, Inicialização).
 2. Aponta arquivos suspeitos (extensão dupla, executável em pasta temporária,
    executável oculto) e confere o hash SHA-256 contra uma lista de ameaças
    conhecidas (arquivo opcional "hashes.txt" na mesma pasta, um hash por linha).
 3. Lista programas que iniciam junto com o Windows.
 4. Botão para chamar o Microsoft Defender (verificação rápida de verdade).

Importante: é uma ferramenta de apoio. Não substitui um antivírus.
"""
import os
import sys
import hashlib
import threading
import queue
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor

IS_WIN = sys.platform.startswith("win")

EXT_RISCO = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
             ".ps1", ".com", ".pif", ".hta", ".jar", ".msi", ".dll"}
EXT_ISCA = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
            ".txt", ".mp3", ".mp4", ".zip", ".rar"}
TAM_MAX_HASH = 150 * 1024 * 1024  # só calcula hash de arquivos até 150 MB


def pastas_padrao():
    home = os.path.expanduser("~")
    pastas = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop")]
    if IS_WIN:
        appdata = os.environ.get("APPDATA", "")
        local = os.environ.get("LOCALAPPDATA", "")
        pastas += [
            os.path.join(local, "Temp"),
            os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        ]
    else:
        pastas.append("/tmp")
    return [p for p in pastas if p and os.path.isdir(p)]


def carregar_hashes():
    caminho = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hashes.txt")
    if not os.path.isfile(caminho):
        return set()
    with open(caminho, encoding="utf-8", errors="ignore") as f:
        return {l.strip().lower() for l in f if len(l.strip()) == 64}


def sha256(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloco)
    return h.hexdigest()


def analisar(caminho, hashes_ruins):
    """Retorna lista de (gravidade, motivo)."""
    achados = []
    nome = os.path.basename(caminho).lower()
    partes = nome.split(".")
    ext = "." + partes[-1] if len(partes) > 1 else ""
    if ext not in EXT_RISCO:
        return achados

    # Extensão dupla enganosa: relatorio.pdf.exe
    if len(partes) >= 3 and ("." + partes[-2]) in EXT_ISCA:
        achados.append(("ALTA", "Extensão dupla enganosa (finge ser documento/imagem)"))

    # Executável em pasta temporária
    pasta = os.path.dirname(caminho).lower()
    if "temp" in pasta or pasta.startswith("/tmp"):
        achados.append(("MÉDIA", "Executável/script em pasta temporária"))

    # Oculto (Windows)
    if IS_WIN:
        try:
            if os.stat(caminho).st_file_attributes & 2:
                achados.append(("MÉDIA", "Executável oculto"))
        except OSError:
            pass

    # Hash conhecido
    if hashes_ruins:
        try:
            if os.path.getsize(caminho) <= TAM_MAX_HASH and sha256(caminho) in hashes_ruins:
                achados.append(("CRÍTICA", "Hash coincide com ameaça conhecida"))
        except OSError:
            pass
    return achados


def itens_inicializacao():
    achados = []
    if not IS_WIN:
        return achados
    try:
        import winreg
        chaves = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for raiz, sub in chaves:
            try:
                with winreg.OpenKey(raiz, sub) as k:
                    i = 0
                    while True:
                        nome, valor, _ = winreg.EnumValue(k, i)
                        i += 1
                        gravidade = "MÉDIA" if "temp" in str(valor).lower() else "INFO"
                        achados.append((gravidade, f"[Inicialização] {nome}", str(valor)))
            except OSError:
                pass
    except ImportError:
        pass
    return achados


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scanner Rápido")
        self.geometry("900x520")
        self.fila = queue.Queue()
        self.parar = threading.Event()
        self.hashes = carregar_hashes()

        topo = ttk.Frame(self, padding=8)
        topo.pack(fill="x")
        self.b_rapida = ttk.Button(topo, text="Verificação rápida", command=self.rapida)
        self.b_rapida.pack(side="left")
        self.b_pasta = ttk.Button(topo, text="Escolher pasta...", command=self.escolher)
        self.b_pasta.pack(side="left", padx=6)
        if IS_WIN:
            ttk.Button(topo, text="Defender (rápida)", command=self.defender).pack(side="left")
        ttk.Button(topo, text="Parar", command=self.parar.set).pack(side="right")

        cols = ("grav", "arquivo", "motivo")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for c, t, w in (("grav", "Gravidade", 90), ("arquivo", "Arquivo / Item", 460), ("motivo", "Motivo", 330)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure("CRÍTICA", background="#f8b4b4")
        self.tree.tag_configure("ALTA", background="#fcd5b0")
        self.tree.tag_configure("MÉDIA", background="#fff3b0")
        self.tree.pack(fill="both", expand=True, padx=8)

        self.barra = ttk.Progressbar(self, mode="indeterminate")
        self.barra.pack(fill="x", padx=8, pady=(6, 0))
        self.status = tk.StringVar(value=f"Pronto. Hashes conhecidos carregados: {len(self.hashes)}")
        ttk.Label(self, textvariable=self.status, padding=8).pack(fill="x")
        self.after(100, self.atualizar)

    # ---------- varredura ----------
    def rapida(self):
        self.iniciar(pastas_padrao(), com_inicializacao=True)

    def escolher(self):
        p = filedialog.askdirectory()
        if p:
            self.iniciar([p])

    def iniciar(self, pastas, com_inicializacao=False):
        self.tree.delete(*self.tree.get_children())
        self.parar.clear()
        self.b_rapida.state(["disabled"])
        self.b_pasta.state(["disabled"])
        self.barra.start(12)
        threading.Thread(target=self.varrer, args=(pastas, com_inicializacao), daemon=True).start()

    def varrer(self, pastas, com_inicializacao):
        total = 0
        suspeitos = 0
        if com_inicializacao:
            for grav, nome, valor in itens_inicializacao():
                self.fila.put(("achado", grav, nome, valor))
        with ThreadPoolExecutor(max_workers=min(16, (os.cpu_count() or 4) * 2)) as pool:
            futuros = []
            for pasta in pastas:
                for raiz, _, arquivos in os.walk(pasta):
                    if self.parar.is_set():
                        break
                    for a in arquivos:
                        caminho = os.path.join(raiz, a)
                        futuros.append((caminho, pool.submit(analisar, caminho, self.hashes)))
                    self.fila.put(("status", f"Verificando: {raiz}"))
            for caminho, fut in futuros:
                if self.parar.is_set():
                    break
                total += 1
                for grav, motivo in fut.result():
                    suspeitos += 1
                    self.fila.put(("achado", grav, caminho, motivo))
        self.fila.put(("fim", total, suspeitos))

    def atualizar(self):
        try:
            while True:
                msg = self.fila.get_nowait()
                if msg[0] == "achado":
                    _, g, a, m = msg
                    self.tree.insert("", "end", values=(g, a, m), tags=(g,))
                elif msg[0] == "status":
                    self.status.set(msg[1][:120])
                elif msg[0] == "fim":
                    self.barra.stop()
                    self.b_rapida.state(["!disabled"])
                    self.b_pasta.state(["!disabled"])
                    self.status.set(f"Concluído: {msg[1]} arquivos analisados, {msg[2]} alertas.")
        except queue.Empty:
            pass
        self.after(100, self.atualizar)

    # ---------- Defender ----------
    def defender(self):
        if not messagebox.askyesno("Defender", "Iniciar verificação rápida do Microsoft Defender?"):
            return
        self.status.set("Defender executando a verificação rápida...")
        self.barra.start(12)

        def rodar():
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "Start-MpScan -ScanType QuickScan"],
                    capture_output=True, text=True)
                ok = r.returncode == 0
                msg = "Verificação do Defender concluída." if ok else f"Falha: {r.stderr.strip()[:200]}"
            except Exception as e:
                msg = f"Erro ao chamar o Defender: {e}"
            self.fila.put(("status", msg))
            self.after(0, self.barra.stop)

        threading.Thread(target=rodar, daemon=True).start()


if __name__ == "__main__":
    App().mainloop()
