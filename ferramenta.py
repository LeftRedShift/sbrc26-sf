# app.py
# Streamlit UI com:
# - Abas por categoria
# - Sidebar com tabela de servidores (inclui "Esta máquina") + logs
# - Tela "Capturas Realizadas" (listar/download) + extração de features + ver features
# - Formulário dinâmico por ataque (0/1/2 campos) baseado em schema (ParamSpec)
# - Execução via "docker run --rm -d --name ..." (runner no AttackSpec)
# - Captura opcional via tcpdump na docker0 durante execução do ataque (até container encerrar)
#
# Requisitos:
# - requirements.txt: streamlit>=1.31
# - attacks/registry.py (ParamSpec/AttackSpec/CATEGORIES)
# - attacks/runners.py (docker_* helpers)

import csv
import ipaddress
import json
import shutil
import signal
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st

from attacks.registry import CATEGORIES, AttackSpec, ParamSpec
from attacks.runners import (
    docker_available,
    docker_container_status,
    docker_logs,
    docker_rm_force,
)

# -----------------------------
# Diretórios / Paths
# -----------------------------
CAPTURES_DIR = Path("captures")
FEATURES_DIR = Path("features")
TMP_DIR = Path(".tmp")


def _ensure_dirs() -> None:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)
    TMP_DIR.mkdir(parents=True, exist_ok=True)


def stem_no_ext(p: Path) -> str:
    # recon_arp_scan-20260124_161958 (sem .pcap)
    return p.name[:-5] if p.name.lower().endswith(".pcap") else p.stem


def build_feature_paths(pcap_path: Path) -> Dict[str, Path]:
    base = stem_no_ext(pcap_path)
    return {
        "ntlflowlyzer": FEATURES_DIR / f"ntlflowlyzer-{base}.csv",
        "tshark": FEATURES_DIR / f"tshark-{base}.csv",
        "scapy": FEATURES_DIR / f"scapy-{base}.csv",
    }


def build_capture_path(attack_id: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return CAPTURES_DIR / f"{attack_id}-{ts}.pcap"


def tool_exists(exe: str) -> bool:
    return shutil.which(exe) is not None


# -----------------------------
# Execução de comandos (binário-safe)
# -----------------------------
def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """
    Executa comando e retorna (rc, stdout, stderr) SEM UnicodeDecodeError.
    Decodifica bytes com UTF-8 errors='replace'.
    """
    p = subprocess.run(cmd, capture_output=True)  # bytes
    stdout = (p.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()
    return p.returncode, stdout, stderr


# -----------------------------
# Extração de Features
# -----------------------------
def extract_with_ntlflowlyzer(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    if not tool_exists("ntlflowlyzer"):
        return {"ok": False, "stderr": "ntlflowlyzer não encontrado no PATH (instale o NTLFlowLyzer).", "cmd": []}

    _ensure_dirs()

    cfg = {
        "pcap_file_address": str(pcap_path.resolve()),
        "output_file_address": str(out_csv.resolve()),
        "label": "Unknown",
        "number_of_threads": 4,
    }

    cfg_path = TMP_DIR / f"ntlflowlyzer-{stem_no_ext(pcap_path)}.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    cmd = ["ntlflowlyzer", "-c", str(cfg_path)]
    rc, out, err = _run(cmd)

    ok = (rc == 0) and out_csv.exists()  # pode estar vazio, mas se gerou arquivo, consideramos ok

    return {
        "ok": ok,
        "returncode": rc,
        "stdout": out,
        "stderr": err,
        "cmd": cmd,
        "output": str(out_csv),
        "config": str(cfg_path),
    }


def extract_with_tshark(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    if not tool_exists("tshark"):
        return {"ok": False, "stderr": "tshark não encontrado no PATH.", "cmd": []}

    _ensure_dirs()

    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "_ws.col.Protocol",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "udp.srcport",
        "udp.dstport",
    ]

    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]

    try:
        p = subprocess.run(cmd, capture_output=True)
        stdout = (p.stdout or b"").decode("utf-8", errors="replace")
        stderr = (p.stderr or b"").decode("utf-8", errors="replace").strip()

        out_csv.write_text(stdout, encoding="utf-8")
        ok = (p.returncode == 0) and out_csv.exists()
        return {"ok": ok, "returncode": p.returncode, "stderr": stderr, "cmd": cmd, "output": str(out_csv)}
    except Exception as e:
        return {"ok": False, "stderr": str(e), "cmd": cmd}


def extract_with_scapy(pcap_path: Path, out_csv: Path) -> Dict[str, Any]:
    _ensure_dirs()
    try:
        from scapy.all import PcapReader  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
    except Exception as e:
        return {"ok": False, "stderr": f"Scapy não disponível/import falhou: {e}", "cmd": ["python/scapy"]}

    header = [
        "pkt_index",
        "time_epoch",
        "frame_len",
        "eth_src",
        "eth_dst",
        "ip_src",
        "ip_dst",
        "ip_proto",
        "l4",
        "src_port",
        "dst_port",
        "tcp_flags",
    ]

    try:
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)

            idx = 0
            with PcapReader(str(pcap_path)) as pr:
                for pkt in pr:
                    idx += 1
                    t = getattr(pkt, "time", None)

                    eth_src = eth_dst = ""
                    ip_src = ip_dst = ""
                    ip_proto = ""
                    l4 = ""
                    src_port = dst_port = ""
                    tcp_flags = ""

                    frame_len = len(bytes(pkt))

                    if pkt.haslayer(Ether):
                        eth = pkt[Ether]
                        eth_src = getattr(eth, "src", "") or ""
                        eth_dst = getattr(eth, "dst", "") or ""

                    if pkt.haslayer(IP):
                        ip = pkt[IP]
                        ip_src = getattr(ip, "src", "") or ""
                        ip_dst = getattr(ip, "dst", "") or ""
                        ip_proto = str(getattr(ip, "proto", "") or "")

                        if pkt.haslayer(TCP):
                            tcp = pkt[TCP]
                            l4 = "TCP"
                            src_port = str(getattr(tcp, "sport", "") or "")
                            dst_port = str(getattr(tcp, "dport", "") or "")
                            tcp_flags = str(getattr(tcp, "flags", "") or "")
                        elif pkt.haslayer(UDP):
                            udp = pkt[UDP]
                            l4 = "UDP"
                            src_port = str(getattr(udp, "sport", "") or "")
                            dst_port = str(getattr(udp, "dport", "") or "")

                    w.writerow(
                        [
                            idx,
                            f"{float(t):.6f}" if t is not None else "",
                            frame_len,
                            eth_src,
                            eth_dst,
                            ip_src,
                            ip_dst,
                            ip_proto,
                            l4,
                            src_port,
                            dst_port,
                            tcp_flags,
                        ]
                    )

        return {"ok": True, "cmd": ["python/scapy"], "output": str(out_csv)}
    except Exception as e:
        return {"ok": False, "stderr": str(e), "cmd": ["python/scapy"], "output": str(out_csv)}


# -----------------------------
# Sidebar: Servidores + Logs
# -----------------------------
SERVER_SPECS = [
    ("Servidor Web", "sbrc26-servidor-http-server"),
    ("Servidor SSH", "sbrc26-servidor-ssh-server"),
    ("SMB Server", "sbrc26-servidor-smb-server"),
    ("MQTT Broker", "sbrc26-servidor-mqtt-broker"),
    ("CoAP Server", "sbrc26-servidor-coap-server"),
    ("Telnet Server", "sbrc26-servidor-telnet-server"),
    ("SSL Heartbleed", "sbrc26-servidor-ssl-heartbleed"),
]

SERVER_LOG_SPECS: Dict[str, Dict[str, Any]] = {
    "sbrc26-servidor-coap-server": {"mode": "docker_logs"},
    "sbrc26-servidor-http-server": {"mode": "docker_logs"},
    "sbrc26-servidor-mqtt-broker": {"mode": "docker_logs"},
    "sbrc26-servidor-smb-server": {"mode": "exec_sh", "sh": "/var/log/samba/*"},
    "sbrc26-servidor-ssh-server": {"mode": "exec_sh", "sh": "/var/log/auth.log"},
    "sbrc26-servidor-ssl-heartbleed": {"mode": "exec_sh", "sh": "/var/log/access.log"},
    "sbrc26-servidor-telnet-server": {
        "mode": "exec_sh",
        "sh": "/var/log/wtmp",
        "binary": True,
        "binary_hint": "O arquivo /var/log/wtmp é binário; o modo Tail raw pode ser ilegível.",
        "alt_label": "Usar last",
        "alt_sh": 'command -v last >/dev/null 2>&1 && last -f /var/log/wtmp || echo "Comando last não está disponível no container."',
    },
}

# -----------------------------
# Configuração da página
# -----------------------------
st.set_page_config(page_title="Testbed de Ataques (Streamlit)", layout="wide")
st.title("Testbed de Ataques")
st.caption(
    "Selecione uma categoria e um ataque. Preencha os parâmetros (quando aplicável) "
    "e clique em Iniciar ataque para acionar a execução via Docker."
)

st.markdown(
    '''
    <style>
    section[data-testid="stSidebar"] button[kind="secondary"],
    section[data-testid="stSidebar"] button[kind="primary"] {
        padding-top: 0.15rem !important;
        padding-bottom: 0.15rem !important;
        min-height: 1.6rem !important;
        line-height: 1.2rem !important;
        font-size: 0.85rem !important;
    }
    section[data-testid="stSidebar"] .stButton {
        margin-bottom: 0.2rem !important;
    }
    </style>
    ''',
    unsafe_allow_html=True,
)

# Estado persistente
if "last_attack_result" not in st.session_state:
    st.session_state["last_attack_result"] = {}
if "view" not in st.session_state:
    st.session_state["view"] = "main"

# -----------------------------
# Docker helpers (inspect/list)
# -----------------------------
def _container_ids_by_ancestor(image: str) -> List[str]:
    rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"ancestor={image}"])
    ids = [x for x in out.splitlines() if x.strip()] if rc == 0 else []

    if not ids and ":" not in image:
        rc, out, _ = _run(["docker", "ps", "-a", "-q", "--filter", f"ancestor={image}:latest"])
        ids = [x for x in out.splitlines() if x.strip()] if rc == 0 else []

    return ids


def _inspect(cont_id: str) -> Optional[dict]:
    rc, out, _ = _run(["docker", "inspect", cont_id])
    if rc != 0 or not out:
        return None
    try:
        data = json.loads(out)
        return data[0] if data else None
    except Exception:
        return None


def _extract_ips(inspected: dict) -> Dict[str, str]:
    ips: Dict[str, str] = {}
    nets = (inspected.get("NetworkSettings") or {}).get("Networks") or {}
    for net_name, net_data in nets.items():
        ip = (net_data or {}).get("IPAddress") or ""
        if ip:
            ips[net_name] = ip
    return ips


def _pick_preferred_container(container_ids: List[str]) -> Optional[str]:
    if not container_ids:
        return None
    for cid in container_ids:
        inspected = _inspect(cid)
        if not inspected:
            continue
        status = ((inspected.get("State") or {}).get("Status") or "").lower()
        if status == "running":
            return cid
    return container_ids[0]


def _get_preferred_container_id_by_ancestor(image_base: str) -> Optional[str]:
    ids = _container_ids_by_ancestor(image_base)
    return _pick_preferred_container(ids)

# -----------------------------
# Logs dos servidores (view)
# -----------------------------
def fetch_server_logs(image_base: str, tail_lines: int = 200, prefer_alt: bool = False) -> Dict[str, Any]:
    if not docker_available():
        return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": "Docker indisponível.", "returncode": 1}

    cid = _get_preferred_container_id_by_ancestor(image_base)
    if not cid:
        return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": f"Container não encontrado para ancestor={image_base}.", "returncode": 1}

    spec = SERVER_LOG_SPECS.get(image_base, {"mode": "docker_logs"})
    mode = spec.get("mode", "docker_logs")
    tail_lines = max(1, min(int(tail_lines), 5000))

    if mode == "docker_logs":
        cmd = ["docker", "logs", "--tail", str(tail_lines), cid]
        rc, out, err = _run(cmd)
        return {"ok": rc == 0, "mode": mode, "cmd_display": " ".join(cmd), "stdout": out, "stderr": err, "returncode": rc}

    if mode == "exec_sh":
        if prefer_alt and spec.get("alt_sh"):
            sh_cmd = f"{spec['alt_sh']} | head -n {tail_lines}"
            cmd = ["docker", "exec", cid, "sh", "-lc", sh_cmd]
            rc, out, err = _run(cmd)
            return {"ok": True, "mode": mode, "cmd_display": " ".join(cmd), "stdout": out, "stderr": err, "returncode": rc}

        files_expr = spec.get("sh", "")
        sh_cmd = f"tail -n {tail_lines} {files_expr} 2>/dev/null || true"
        cmd = ["docker", "exec", cid, "sh", "-lc", sh_cmd]
        rc, out, err = _run(cmd)
        return {"ok": True, "mode": mode, "cmd_display": " ".join(cmd), "stdout": out, "stderr": err, "returncode": rc}

    return {"ok": False, "mode": "error", "cmd_display": "", "stdout": "", "stderr": f"Modo de log desconhecido: {mode}", "returncode": 1}


def _clip_text(s: str, max_chars: int = 120_000) -> str:
    if not s:
        return s
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + "\n\n[saída truncada: excedeu o limite de caracteres]"


def render_server_logs_view() -> None:
    label = st.session_state.get("server_logs_label", "")
    image_base = st.session_state.get("server_logs_image_base", "")
    st.subheader(f"Logs do servidor: {label}")

    if "server_logs_tail" not in st.session_state:
        st.session_state["server_logs_tail"] = 200

    spec = SERVER_LOG_SPECS.get(image_base, {})
    has_alt = bool(spec.get("alt_sh"))
    is_binary = bool(spec.get("binary"))

    top = st.columns([1, 1, 2])
    if top[0].button("Voltar"):
        st.session_state["view"] = "main"
        st.rerun()

    tail_lines = top[2].number_input("Tail (linhas)", min_value=1, max_value=5000, value=int(st.session_state["server_logs_tail"]), step=50)
    st.session_state["server_logs_tail"] = int(tail_lines)

    if top[1].button("Atualizar logs"):
        st.rerun()

    prefer_alt = False
    if is_binary:
        st.warning(spec.get("binary_hint", "Este log pode ser binário e a saída pode ficar ilegível."))
        if has_alt:
            mode_choice = st.radio("Modo de leitura", options=["Tail raw", spec.get("alt_label", "Alternativo")], horizontal=True, index=0, key="server_logs_mode_choice")
            prefer_alt = (mode_choice != "Tail raw")
            if not prefer_alt:
                st.error("Não é possível exibir este log no modo Tail raw (arquivo binário). Use o modo alternativo.")
                return

    result = fetch_server_logs(image_base, tail_lines=int(tail_lines), prefer_alt=prefer_alt)

    st.caption("Comando executado:")
    st.code(result.get("cmd_display", ""), language="bash")

    out = _clip_text(result.get("stdout", ""))
    err = _clip_text(result.get("stderr", ""))

    if out:
        st.code(out, language="text")
    else:
        st.write("Sem saída de logs.")

    if err:
        with st.expander("stderr", expanded=False):
            st.code(err, language="text")

# -----------------------------
# Capturas + Features (views)
# -----------------------------
def list_capture_files() -> List[Path]:
    _ensure_dirs()
    return sorted(CAPTURES_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)


def format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def render_captures_view() -> None:
    st.subheader("Capturas Realizadas")
    top = st.columns([1, 1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "main"
        st.rerun()
    if top[1].button("Atualizar lista"):
        st.rerun()

    files = list_capture_files()
    if not files:
        st.info('Nenhuma captura encontrada em "captures/".')
        return

    query = st.text_input("Filtrar por nome (opcional)", value="").strip().lower()
    if query:
        files = [p for p in files if query in p.name.lower()]

    st.caption(f'Total: {len(files)} arquivo(s) em "{CAPTURES_DIR}/"')

    h1, h2, h3, h4, h5, h6 = st.columns([4, 1.5, 2, 1.4, 1.6, 1.6])
    h1.write("Arquivo")
    h2.write("Tamanho")
    h3.write("Modificado em")
    h4.write("Download")
    h5.write("Extrair")
    h6.write("Ver features")

    for p in files:
        stat = p.stat()
        size = format_bytes(stat.st_size)
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        outs = build_feature_paths(p)
        has_features = any(path.exists() for path in outs.values())

        c1, c2, c3, c4, c5, c6 = st.columns([4, 1.5, 2, 1.4, 1.6, 1.6], gap="small")
        c1.write(p.name)
        c2.write(size)
        c3.write(mtime)

        with open(p, "rb") as f:
            c4.download_button("Download", data=f, file_name=p.name, mime="application/vnd.tcpdump.pcap", key=f"dl_{p.name}", use_container_width=True)

        if c5.button("Extrair", key=f"fx_{p.name}", type="secondary", use_container_width=True):
            st.session_state["selected_pcap"] = str(p)
            st.session_state["view"] = "features"
            st.rerun()

        if c6.button("Ver", key=f"vf_{p.name}", type="secondary", use_container_width=True, disabled=not has_features):
            st.session_state["selected_pcap"] = str(p)
            st.session_state["view"] = "view_features"
            st.rerun()


def render_features_view() -> None:
    st.subheader("Extração de Features")
    top = st.columns([1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "captures"
        st.rerun()

    pcap_str = st.session_state.get("selected_pcap", "")
    if not pcap_str:
        st.info("Nenhuma captura selecionada.")
        return

    pcap_path = Path(pcap_str)
    if not pcap_path.exists():
        st.error(f"Arquivo não encontrado: {pcap_path}")
        return

    _ensure_dirs()
    outs = build_feature_paths(pcap_path)

    st.write("Captura selecionada:", str(pcap_path))
    st.markdown("### Saídas previstas")
    st.code("\n".join([str(outs["ntlflowlyzer"]), str(outs["tshark"]), str(outs["scapy"])]), language="text")

    c1, c2, c3 = st.columns(3)
    run_ntl = c1.checkbox("NTLFlowLyzer", value=True)
    run_tsh = c2.checkbox("TShark", value=True)
    run_scp = c3.checkbox("Scapy", value=True)

    overwrite = st.checkbox("Sobrescrever CSVs existentes (se houver)", value=False)

    if st.button("Extrair features", type="primary"):
        results: Dict[str, Any] = {}
        with st.spinner("Executando extração... Esta ação pode levar vários minutos."):
            if run_ntl:
                results["ntlflowlyzer"] = extract_with_ntlflowlyzer(pcap_path, outs["ntlflowlyzer"]) if (overwrite or not outs["ntlflowlyzer"].exists()) else {"ok": True, "output": str(outs["ntlflowlyzer"]), "cmd": ["(skip) já existe"]}
            if run_tsh:
                results["tshark"] = extract_with_tshark(pcap_path, outs["tshark"]) if (overwrite or not outs["tshark"].exists()) else {"ok": True, "output": str(outs["tshark"]), "cmd": ["(skip) já existe"]}
            if run_scp:
                results["scapy"] = extract_with_scapy(pcap_path, outs["scapy"]) if (overwrite or not outs["scapy"].exists()) else {"ok": True, "output": str(outs["scapy"]), "cmd": ["(skip) já existe"]}

        st.markdown("### Resultados")
        for tool, res in results.items():
            if res.get("ok"):
                st.success(f"{tool}: OK → {res.get('output')}")
            else:
                st.error(f"{tool}: falhou")
                if res.get("stderr"):
                    st.code(res["stderr"], language="text")
            if res.get("cmd"):
                st.caption("Comando:")
                st.code(" ".join(res["cmd"]), language="bash")

        if st.button("Ir para Ver features", type="secondary"):
            st.session_state["view"] = "view_features"
            st.rerun()


def _preview_csv(path: Path, n_rows: int) -> Any:
    try:
        import pandas as pd  # type: ignore
        df = pd.read_csv(path)
        return df.head(n_rows)
    except Exception:
        rows: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= n_rows:
                    break
                rows.append(row)
        return rows


def render_view_features_view() -> None:
    st.subheader("Features extraídas")
    top = st.columns([1, 3])
    if top[0].button("Voltar"):
        st.session_state["view"] = "captures"
        st.rerun()

    pcap_str = st.session_state.get("selected_pcap", "")
    if not pcap_str:
        st.info("Nenhuma captura selecionada.")
        return

    pcap_path = Path(pcap_str)
    outs = build_feature_paths(pcap_path)
    existing = {tool: path for tool, path in outs.items() if path.exists()}

    st.write("Captura:", str(pcap_path))

    if not existing:
        st.warning("Nenhum arquivo de features encontrado para esta captura.")
        if st.button("Extrair features agora", type="primary"):
            st.session_state["view"] = "features"
            st.rerun()
        return

    st.markdown("### Arquivos encontrados")
    for tool, path in existing.items():
        cols = st.columns([3, 2, 2], gap="small")
        cols[0].write(path.name)
        cols[1].write(tool)
        with open(path, "rb") as f:
            cols[2].download_button("Download CSV", data=f, file_name=path.name, mime="text/csv", key=f"dl_csv_{tool}_{pcap_path.name}", use_container_width=True)

    st.markdown("### Pré-visualização")
    tool_list = list(existing.keys())
    tabs = st.tabs(tool_list)
    for tab, tool in zip(tabs, tool_list):
        with tab:
            csv_path = existing[tool]
            n = st.number_input("Linhas para prévia", min_value=5, max_value=500, value=50, step=5, key=f"preview_n_{tool}_{pcap_path.name}")
            preview = _preview_csv(csv_path, int(n))
            st.dataframe(preview, use_container_width=True)

# -----------------------------
# Host IP e status de servidores
# -----------------------------
def get_host_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "-"

@st.cache_data(ttl=5, show_spinner=False)
def get_servers_status() -> List[dict]:
    rows: List[dict] = [{"Servidor": "Esta máquina", "IP": get_host_ip()}]

    if not docker_available():
        rows.append({"Servidor": "Docker", "IP": "Docker indisponível (CLI não acessível)."})
        return rows

    for label, image in SERVER_SPECS:
        ids = _container_ids_by_ancestor(image)
        cid = _pick_preferred_container(ids)
        if not cid:
            rows.append({"Servidor": label, "IP": "-"})
            continue
        inspected = _inspect(cid)
        if not inspected:
            rows.append({"Servidor": label, "IP": "-"})
            continue
        ips = _extract_ips(inspected)
        ip = ips.get("bridge") or (next(iter(ips.values())) if ips else "-")
        rows.append({"Servidor": label, "IP": ip})

    return rows

# -----------------------------
# Captura tcpdump
# -----------------------------
def start_tcpdump_capture(pcap_path: Path, iface: str = "docker0") -> Dict[str, Any]:
    _ensure_dirs()
    cmd = ["tcpdump", "-i", iface, "-w", str(pcap_path)]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.25)
        if p.poll() is not None:
            out = (p.stdout.read() if p.stdout else b"")
            err = (p.stderr.read() if p.stderr else b"")
            return {"ok": False, "cmd": cmd, "popen": None, "stderr": (err or b"").decode("utf-8", errors="replace").strip(), "stdout": (out or b"").decode("utf-8", errors="replace").strip()}
        return {"ok": True, "cmd": cmd, "popen": p, "stdout": "", "stderr": ""}
    except FileNotFoundError:
        return {"ok": False, "cmd": cmd, "popen": None, "stdout": "", "stderr": "tcpdump não encontrado no PATH."}
    except Exception as e:
        return {"ok": False, "cmd": cmd, "popen": None, "stdout": "", "stderr": str(e)}

def stop_tcpdump_capture(p: subprocess.Popen, timeout: float = 3.0) -> Dict[str, Any]:
    try:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.terminate()
                try:
                    p.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    p.kill()

        out = (p.stdout.read() if p.stdout else b"")
        err = (p.stderr.read() if p.stderr else b"")
        return {"ok": True, "stdout": (out or b"").decode("utf-8", errors="replace").strip(), "stderr": (err or b"").decode("utf-8", errors="replace").strip()}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}

# -----------------------------
# Sidebar UI (render)
# -----------------------------
rows = get_servers_status()
ip_map = {r["Servidor"]: r["IP"] for r in rows}

st.sidebar.header("Dados Armazenados")
if st.sidebar.button("Ver Capturas Realizadas", type="secondary"):
    st.session_state["view"] = "captures"
    st.rerun()

st.sidebar.divider()

h1, h2, h3 = st.sidebar.columns([2, 2, 2])
h1.write("**Servidor**")
h2.write("**IP**")
h3.write("**Ver logs**")

c1, c2, c3 = st.sidebar.columns([2, 2, 2])
c1.write("Esta máquina")
c2.write(ip_map.get("Esta máquina", "-"))
c3.write("-")

for label, image_base in SERVER_SPECS:
    c1, c2, c3 = st.sidebar.columns([2, 2, 2], gap="small")
    c1.write(label)
    c2.write(ip_map.get(label, "-"))
    if c3.button("Logs", key=f"logs_btn_{image_base}", type="secondary", use_container_width=True):
        st.session_state["view"] = "server_logs"
        st.session_state["server_logs_label"] = label
        st.session_state["server_logs_image_base"] = image_base
        st.rerun()

if st.sidebar.button("Atualizar"):
    get_servers_status.clear()

st.sidebar.divider()
st.sidebar.header("Informação importante:")
st.sidebar.caption(
    "Esta ferramenta tem propósito experimental e educacional e não deve ser utilizada para atacar endereços externos. "
    "Para demonstração, utilize o próprio IP desta máquina como alvo dos ataques (nos ataques diretos a um endereço IP). "
    "Nos ataques em nível de rede, utilize a rede docker (172.17.0.0/16) ou sua rede local."
)

# -----------------------------
# Execução / Stop / Status do ataque
# -----------------------------
def run_attack_from_spec(spec: AttackSpec, resolved_params: Dict[str, Any], capture_enabled: bool = True) -> Dict[str, Any]:
    if not docker_available():
        return {"ok": False, "stderr": "Docker indisponível no host do Streamlit.", "cmd": [], "returncode": 1}

    if not capture_enabled:
        with st.spinner("Executando ataque..."):
            result = spec.runner(resolved_params)
        result["capture"] = {"enabled": False}
        return result

    pcap_path = build_capture_path(spec.id)
    cap = start_tcpdump_capture(pcap_path, iface="docker0")
    if not cap.get("ok"):
        return {"ok": False, "stderr": f"Falha ao iniciar captura: {cap.get('stderr') or ''}".strip(), "cmd": cap.get("cmd", []), "returncode": 1, "capture": {"enabled": True, "ok": False, "pcap_path": str(pcap_path), **cap}}

    tcpdump_p = cap["popen"]
    with st.spinner("Executando ataque e capturando tráfego..."):
        attack_result = spec.runner(resolved_params)

    if not attack_result.get("ok"):
        stop_info = stop_tcpdump_capture(tcpdump_p)
        attack_result["capture"] = {"enabled": True, "ok": True, "pcap_path": str(pcap_path), "tcpdump_cmd": cap.get("cmd"), "stop": stop_info}
        return attack_result

    container_id = attack_result.get("container_id")
    wait_err = ""
    if container_id:
        rc, out, err = _run(["docker", "wait", container_id])
        if rc != 0:
            wait_err = err or out or "Falha ao aguardar término do container."
    else:
        wait_err = "container_id não retornado; não foi possível aguardar término."

    stop_info = stop_tcpdump_capture(tcpdump_p)
    attack_result["capture"] = {"enabled": True, "ok": True, "pcap_path": str(pcap_path), "tcpdump_cmd": cap.get("cmd"), "wait_error": wait_err, "stop": stop_info}
    return attack_result

def show_last_attack_result(spec: AttackSpec) -> None:
    res = st.session_state["last_attack_result"].get(spec.id)
    if not res:
        return

    st.markdown("### Última execução")

    cap = res.get("capture") or {}
    if cap.get("enabled") is False:
        st.write("Captura:", "desativada")

    pcap = cap.get("pcap_path")
    if pcap:
        st.write("Captura:", pcap)
        if cap.get("tcpdump_cmd"):
            st.caption("Comando tcpdump:")
            st.code(" ".join(cap["tcpdump_cmd"]), language="bash")
        if cap.get("wait_error"):
            st.warning(f"Observação: {cap['wait_error']}")

    if res.get("ok"):
        st.success("Ataque iniciado com sucesso.")
        st.write("Container ID:", res.get("container_id") or "-")
    else:
        st.error("Falha ao iniciar o ataque.")
        st.write("Return code:", res.get("returncode"))
        if res.get("stderr"):
            st.code(res["stderr"], language="text")

    st.caption("Comando executado:")
    st.code(" ".join(res.get("cmd", [])), language="bash")

    if st.button("Limpar última saída", key=f"clear_last_{spec.id}"):
        st.session_state["last_attack_result"].pop(spec.id, None)
        st.rerun()

def stop_attack(spec: AttackSpec) -> None:
    if not spec.container_name:
        st.warning("Este ataque não possui container_name definido; não é possível parar automaticamente.")
        return
    if not docker_available():
        st.error("Docker indisponível no host do Streamlit.")
        return
    result = docker_rm_force(spec.container_name)
    if result.get("ok"):
        st.success("Container do ataque removido.")
    else:
        st.error("Falha ao remover o container do ataque.")
        if result.get("stderr"):
            st.code(result["stderr"], language="text")

def show_attack_runtime(spec: AttackSpec) -> None:
    if not spec.container_name:
        st.info("Este ataque não possui container_name definido; status/stop não disponíveis.")
        return
    status = docker_container_status(spec.container_name)
    if not status.get("exists"):
        st.write("Status do ataque:", "**parado**.")
        return
    st.write("Status do ataque:", status.get("status", "unknown"))
    st.write("Container:", status.get("id") or "-")
    with st.expander("Ver logs (tail 200)", expanded=False):
        logs = docker_logs(spec.container_name, tail=200)
        if logs.get("ok") and logs.get("stdout"):
            st.code(logs["stdout"], language="text")
        elif logs.get("stderr"):
            st.code(logs["stderr"], language="text")
        else:
            st.write("Sem logs disponíveis.")

# -----------------------------
# Formulário dinâmico por schema
# -----------------------------


def validate_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False


def validate_port(value: int) -> bool:
    return 1 <= int(value) <= 65535


def validate_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except Exception:
        return False


def resolve_placeholder(p: ParamSpec, host_ip: str) -> str:
    ph = getattr(p, "placeholder", None)
    if not ph:
        return ""
    return host_ip if ph == "__HOST_IP__" else str(ph)


def render_params_form(spec: AttackSpec, host_ip: str) -> Tuple[bool, Dict[str, Any], bool]:
    resolved: Dict[str, Any] = {}
    if not spec.params:
        if spec.no_params_note:
            st.info(spec.no_params_note)
        c1, c2 = st.columns([3, 2])
        capture_enabled = c2.toggle("Iniciar captura de pacotes junto do ataque", value=True, key=f"cap_toggle_{spec.id}")
        submitted = c1.button("Iniciar ataque", key=f"start_noparams_{spec.id}")
        return submitted, resolved, capture_enabled

    with st.form(f"form_{spec.id}", clear_on_submit=False):
        for p in spec.params:
            ph = resolve_placeholder(p, host_ip)
            if p.kind == "port":
                default_port = int(p.default) if p.default is not None else (int(ph) if ph.isdigit() else 1)
                value = st.number_input(p.label, min_value=1, max_value=65535, value=default_port, step=1, key=f"{spec.id}_{p.key}")
                resolved[p.key] = int(value)
            else:
                value = st.text_input(p.label, placeholder=ph if ph else None, value="" if p.default is None else str(p.default), key=f"{spec.id}_{p.key}").strip()
                if not value and ph:
                    value = ph
                    st.caption(f'Campo "{p.label}" vazio; usando valor sugerido: {ph}')
                resolved[p.key] = value

        c1, c2 = st.columns([3, 2])
        submitted = c1.form_submit_button("Iniciar ataque")
        capture_enabled = c2.toggle("Iniciar captura de pacotes junto do ataque", value=True, key=f"cap_toggle_{spec.id}")

    return submitted, resolved, capture_enabled

def validate_params(spec: AttackSpec, params: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for p in spec.params:
        v = params.get(p.key, "")
        if p.kind == "ip":
            if not v or not validate_ip(str(v)):
                errors.append(f'Campo "{p.label}" inválido.')
        elif p.kind == "cidr":
            if not v or not validate_cidr(str(v)):
                errors.append(f'Campo "{p.label}" inválido (ex.: 192.168.0.0/24).')
        elif p.kind == "port":
            try:
                pv = int(v)
                if not validate_port(pv):
                    errors.append(f'Campo "{p.label}" inválido (1–65535).')
            except Exception:
                errors.append(f'Campo "{p.label}" inválido (1–65535).')
        else:
            if v is None:
                errors.append(f'Campo "{p.label}" inválido.')
    return errors

# -----------------------------
# UI em abas por categoria
# -----------------------------
def category_tab_ui(category_name: str, attacks: List[AttackSpec]) -> None:
    st.subheader(category_name)

    attack_name_to_spec = {a.name: a for a in attacks}
    attack_name = st.selectbox("Ataque", list(attack_name_to_spec.keys()), key=f"attack_select_{category_name}")
    spec = attack_name_to_spec[attack_name]

    left, right = st.columns([2, 3], gap="large")
    host_ip = get_host_ip()

    with left:
        st.markdown("### Detalhes do ataque")
        st.markdown(f"ID: `{spec.id}`")
        st.markdown(f"Nome: {spec.name}")
        st.markdown(f"Descrição: {spec.description}")
        st.markdown(f"Imagem: `{spec.image}`")
        st.markdown(f"Container (nome): `{spec.container_name}`")
        if getattr(spec, "details_warning", None):
            st.warning(spec.details_warning)
        st.markdown("### Execução")
        show_attack_runtime(spec)

        col1, col2 = st.columns([1, 1])
        if col1.button("Atualizar status", key=f"refresh_status_{spec.id}"):
            st.rerun()
        if col2.button("Parar ataque", key=f"stop_{spec.id}"):
            stop_attack(spec)
            st.rerun()

    with right:
        st.markdown("### Parâmetros")
        submitted, resolved, capture_enabled = render_params_form(spec, host_ip)
        show_last_attack_result(spec)

        if submitted:
            errors = validate_params(spec, resolved)
            if errors:
                for e in errors:
                    st.error(e)
            else:
                result = run_attack_from_spec(spec, resolved, capture_enabled=capture_enabled)
                st.session_state["last_attack_result"][spec.id] = result
                st.rerun()

# -----------------------------
# Router de telas
# -----------------------------
if st.session_state["view"] == "server_logs":
    render_server_logs_view()
    st.stop()
if st.session_state["view"] == "captures":
    render_captures_view()
    st.stop()
if st.session_state["view"] == "features":
    render_features_view()
    st.stop()
if st.session_state["view"] == "view_features":
    render_view_features_view()
    st.stop()

# -----------------------------
# Tela principal: abas
# -----------------------------
category_names = list(CATEGORIES.keys())
tabs = st.tabs(category_names)
for tab, category_name in zip(tabs, category_names):
    with tab:
        category_tab_ui(category_name, CATEGORIES[category_name])

st.divider()
st.caption("Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC) 2026 - Salão de Ferramentas.")
