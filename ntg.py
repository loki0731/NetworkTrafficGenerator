#!/usr/bin/env python3
"""
Network Traffic Generator — PyQt6 GUI
Запуск iperf3 через SSH с реалтайм-графиком скорости
"""

import sys
import re
import time
import threading
import subprocess
from datetime import datetime
from collections import deque

import paramiko
import pyqtgraph as pg
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QGroupBox, QLabel, QLineEdit, QSpinBox, QComboBox,
    QPushButton, QTextEdit, QTabWidget, QCheckBox, QDoubleSpinBox,
    QFrame, QSizePolicy, QMessageBox, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor


DARK_BG      = "#0d1117"
PANEL_BG     = "#161b22"
BORDER       = "#30363d"
ACCENT_BLUE  = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED   = "#f85149"
ACCENT_AMBER = "#d29922"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {DARK_BG};
    color: {TEXT_PRIMARY};
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    font-size: 13px;
}}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    margin-top: 10px;
    padding: 10px 8px 8px 8px;
    font-weight: bold;
    color: {TEXT_MUTED};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: {ACCENT_BLUE};
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background-color: {PANEL_BG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 6px 8px;
    color: {TEXT_PRIMARY};
    selection-background-color: {ACCENT_BLUE};
    min-height: 24px;
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border-color: {ACCENT_BLUE};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background-color: {PANEL_BG};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT_BLUE};
    color: {TEXT_PRIMARY};
    padding: 2px;
}}
QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {BORDER};
    border: none;
    width: 16px;
    border-radius: 2px;
}}
QPushButton {{
    background-color: {PANEL_BG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 8px 16px;
    color: {TEXT_PRIMARY};
    font-weight: bold;
    min-height: 28px;
}}
QPushButton:hover {{ border-color: {ACCENT_BLUE}; color: {ACCENT_BLUE}; }}
QPushButton#btnStart {{
    background-color: #1a4a2e;
    border-color: {ACCENT_GREEN};
    color: {ACCENT_GREEN};
    font-size: 14px;
    min-height: 38px;
}}
QPushButton#btnStart:hover {{ background-color: #204d31; }}
QPushButton#btnStop {{
    background-color: #3d1a1a;
    border-color: {ACCENT_RED};
    color: {ACCENT_RED};
    font-size: 14px;
    min-height: 38px;
}}
QPushButton#btnStop:hover {{ background-color: #4d2020; }}
QPushButton:disabled {{ opacity: 0.4; color: {TEXT_MUTED}; border-color: {BORDER}; }}
QTextEdit {{
    background-color: {PANEL_BG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    color: #7ee787;
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 12px;
}}
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    background-color: {PANEL_BG};
}}
QTabBar::tab {{
    background-color: {DARK_BG};
    border: 1px solid {BORDER};
    padding: 6px 16px;
    color: {TEXT_MUTED};
    border-bottom: none;
    border-radius: 4px 4px 0 0;
}}
QTabBar::tab:selected {{ background-color: {PANEL_BG}; color: {ACCENT_BLUE}; border-color: {BORDER}; }}
QCheckBox {{ color: {TEXT_MUTED}; spacing: 6px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {BORDER};
    border-radius: 3px;
    background-color: {PANEL_BG};
}}
QCheckBox::indicator:checked {{ background-color: {ACCENT_BLUE}; border-color: {ACCENT_BLUE}; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{
    background: {DARK_BG}; width: 6px; border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER}; border-radius: 3px; min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QTabBar {{
    background-color: {DARK_BG};
    border: none;
}}
QTabBar::tab:!selected {{
    margin-top: 2px;
}}
QSplitter {{
    background-color: {DARK_BG};
}}
"""


class IperfWorker(QThread):
    data_point = pyqtSignal(float, float)
    log_line   = pyqtSignal(str)
    finished   = pyqtSignal(dict)
    error      = pyqtSignal(str)

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        cfg = self.config
        try:
            ssh_client = None
            if cfg.get("use_ssh"):
                self.log_line.emit(f"[SSH] Подключение к {cfg['ssh_user']}@{cfg['server_ip']}...")
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(
                    hostname=cfg["server_ip"],
                    port=cfg.get("ssh_port", 22),
                    username=cfg["ssh_user"],
                    password=cfg.get("ssh_pass", "") or None,
                    key_filename=cfg.get("ssh_key") or None,
                    timeout=10
                )
                self.log_line.emit("[SSH] Соединение установлено")
                ssh_client.exec_command(
                    f"pkill iperf3 2>/dev/null; sleep 0.3; iperf3 -s -p {cfg['port']} -D"
                )
                time.sleep(1.5)
                self.log_line.emit(f"[SSH] iperf3 -s запущен на порту {cfg['port']}")

            cmd = self._build_cmd(cfg)
            self.log_line.emit(f"[CMD] {' '.join(cmd)}")

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1
            )

            stats = {"max_gbps": 0.0, "min_gbps": float("inf"),
                     "samples": [], "start_time": time.time(),
                     "loss_pct": None, "jitter_ms": None, "retransmits": 0}
            parallel = cfg.get("parallel", 1)

            for line in proc.stdout:
                if self._stop_event.is_set():
                    proc.terminate()
                    break
                line = line.rstrip()
                self.log_line.emit(line)
                gbps = self._parse_gbps(line, parallel)
                if gbps is not None and gbps > 0:
                    ts = time.time() - stats["start_time"]
                    stats["samples"].append(gbps)
                    stats["max_gbps"] = max(stats["max_gbps"], gbps)
                    stats["min_gbps"] = min(stats["min_gbps"], gbps)
                    self.data_point.emit(ts, gbps)
                # Jitter
                mj = re.search(r"([\d.]+)\s*ms\s+[\d]+/[\d]+", line)
                if mj: stats["jitter_ms"] = float(mj.group(1))
                # Loss
                ml = re.search(r"\(([\d.]+)%\)", line)
                if ml: stats["loss_pct"] = float(ml.group(1))
                # Retransmits
                mr = re.search(r"\s(\d+)\s+sender", line)
                if mr:
                    try: stats["retransmits"] += int(mr.group(1))
                    except: pass

            proc.wait()
            stats["avg_gbps"] = (sum(stats["samples"]) / len(stats["samples"])
                                 if stats["samples"] else 0.0)

            if ssh_client:
                ssh_client.exec_command("pkill iperf3 2>/dev/null")
                ssh_client.close()

            self.finished.emit(stats)

        except paramiko.AuthenticationException:
            self.error.emit("SSH: Ошибка аутентификации — проверьте логин/пароль")
        except paramiko.NoValidConnectionsError as e:
            self.error.emit(f"SSH: Не удалось подключиться — {e}")
        except Exception as e:
            self.error.emit(f"Ошибка: {e}")

    def _build_cmd(self, cfg):
        cmd = [
            "iperf3", "-c", cfg["server_ip"],
            "-p", str(cfg["port"]),
            "-t", str(cfg["duration"]),
            "-P", str(cfg["parallel"]),
            "-i", "1",
            "--forceflush",
        ]
        mode = cfg["mode"]
        if mode == "TCP — макс. throughput":
            cmd += ["-w", cfg.get("window", "256K")]
        elif mode == "UDP flood":
            cmd += ["-u", "-b", cfg.get("bandwidth", "10G"),
                    "-l", cfg.get("pkt_size", "1400")]
        elif mode == "Bidirectional TCP":
            cmd += ["-w", cfg.get("window", "256K"), "--bidir"]
        elif mode == "Reverse (сервер → клиент)":
            cmd += ["-w", cfg.get("window", "256K"), "-R"]
        elif mode == "Small packets UDP":
            cmd += ["-u", "-b", cfg.get("bandwidth", "10G"), "-l", "64"]

        elif mode == "TCP Congestion test":
            
            cmd += ["-w", cfg.get("window", "256K")]
            
        elif mode == "Jitter / latency UDP":
            cmd += ["-u", "-b", cfg.get("bandwidth", "1G"), "-l", "172"] 
        elif mode == "Multi-port stress":
            
            cmd += ["-w", cfg.get("window", "256K")]

        if cfg.get("omit"):
            cmd += ["-O", "2"]
        if cfg.get("zerocopy"):
            cmd += ["-Z"]
        if cfg.get("mtu"):
            cmd += ["-M", str(cfg["mtu"])]

        return cmd

    @staticmethod
    def _parse_cwnd(line: str) -> str | None:
        """Извлекает значение cwnd из строки iperf3 для TCP Congestion test."""
        m = re.search(r"(\d+\.?\d*)\s*(K|M)Bytes\s*$", line)
        if m:
            return f"{m.group(1)} {m.group(2)}B"
        return None

    @staticmethod
    def _parse_gbps(line: str, parallel: int = 1) -> float | None:
        """
        Парсит скорость из строки iperf3.

        Логика:
        - parallel > 1 → берём только строки [SUM], индивидуальные потоки пропускаем.
        - parallel == 1 → берём обычные строки (нет [SUM]).
        - Строки итоговой статистики (sender/receiver) всегда пропускаем —
          они дублируют последний интервал и ломают avg.
        - Строки с (omitted) пропускаем — это slow-start, не считается.
        """
        if "Bits/sec" not in line and "bits/sec" not in line:
            return None
        
        if "sender" in line or "receiver" in line:
            return None
        
        if "(omitted)" in line:
            return None

        is_sum = line.lstrip().startswith("[SUM]")

        if parallel > 1:
            
            if not is_sum:
                return None
        else:
            
            if is_sum:
                return None

        m = re.search(r"([\d.]+)\s+Gbits/sec", line)
        if m: return float(m.group(1))
        m = re.search(r"([\d.]+)\s+Mbits/sec", line)
        if m: return float(m.group(1)) / 1000.0
        m = re.search(r"([\d.]+)\s+Kbits/sec", line)
        if m: return float(m.group(1)) / 1_000_000.0
        return None


ICON_B64 = "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"

DOCS_HTML = f"""
<html><head><style>
  body      {{ background:{DARK_BG}; color:{TEXT_PRIMARY};
               font-family:'JetBrains Mono','Consolas',monospace; font-size:13px;
               line-height:1.7; margin:0; padding:0; }}
  h1        {{ color:{ACCENT_BLUE}; font-size:18px; border-bottom:1px solid {BORDER};
               padding-bottom:8px; margin-top:0; letter-spacing:1px; }}
  h2        {{ color:{ACCENT_GREEN}; font-size:14px; margin-top:28px; margin-bottom:6px;
               letter-spacing:0.5px; }}
  h3        {{ color:{ACCENT_AMBER}; font-size:12px; margin-top:18px; margin-bottom:4px; }}
  p         {{ color:{TEXT_PRIMARY}; margin:6px 0; }}
  code      {{ background:{PANEL_BG}; color:{ACCENT_GREEN}; padding:1px 6px;
               border-radius:3px; font-size:12px; }}
  pre       {{ background:{PANEL_BG}; color:{ACCENT_GREEN}; padding:12px 16px;
               border-radius:6px; border:1px solid {BORDER}; overflow-x:auto;
               font-size:12px; line-height:1.6; }}
  table     {{ border-collapse:collapse; width:100%; margin:10px 0; }}
  th        {{ background:{PANEL_BG}; color:{ACCENT_BLUE}; padding:7px 12px;
               text-align:left; border:1px solid {BORDER}; font-size:11px;
               letter-spacing:0.5px; }}
  td        {{ padding:6px 12px; border:1px solid {BORDER}; color:{TEXT_PRIMARY};
               font-size:12px; }}
  tr:nth-child(even) td {{ background:#0f1318; }}
  .muted    {{ color:{TEXT_MUTED}; font-size:11px; }}
  .warn     {{ color:{ACCENT_AMBER}; }}
  .ok       {{ color:{ACCENT_GREEN}; }}
  .section  {{ margin-bottom:32px; }}
  hr        {{ border:none; border-top:1px solid {BORDER}; margin:24px 0; }}
</style></head><body>

<h1>Network Traffic Generator — Руководство по параметрам</h1>

<div class="section">
<h2>Режимы работы</h2>

<h3>TCP — макс. throughput</h3>
<p>Классический режим измерения пропускной способности. Клиент открывает <code>N</code> параллельных
TCP-соединений и отправляет данные как можно быстрее.<br>
<span class="muted">Флаги: <code>-P &lt;потоки&gt; -w &lt;window&gt;</code> — для базового измерения bandwidth и аттестационных испытаний.</span></p>

<h3>UDP flood</h3>
<p>Клиент генерирует UDP-пакеты с заданной скоростью. Нет механизма управления потоком —
пакеты уходят с постоянной скоростью независимо от потерь.<br>
<span class="muted">Флаги: <code>-u -b &lt;bandwidth&gt; -l &lt;packet_size&gt;</code></span><br>
<span class="warn">Важно:</span> loss &gt; 1–2% означает, что сеть не справляется с заданной скоростью.</p>

<h3>Bidirectional TCP</h3>
<p>Одновременная передача данных в обоих направлениях. Симулирует full-duplex нагрузку.<br>
<span class="muted">Флаг: <code>--bidir</code> — требует iperf3 ≥ 3.7.</span></p>

<h3>Reverse (сервер → клиент)</h3>
<p>Трафик направлен в обратную сторону: сервер генерирует, клиент принимает. Тестирует входящий канал.<br>
<span class="muted">Флаг: <code>-R</code></span></p>

<h3>Small packets UDP</h3>
<p>UDP-пакеты размером 64 байта — минимальный Ethernet-кадр. Максимальная нагрузка на форвардинг.<br>
<span class="muted">При 10 Гбит/с генерируется ~14,8 млн пакетов/с. Iperf3 упирается в CPU —
для честного line-rate используйте pktgen/DPDK.</span></p>

<h3>TCP Congestion test</h3>
<p>TCP-тест с логированием значений <code>cwnd</code> (congestion window) каждую секунду. Позволяет наблюдать,
как алгоритм управления перегрузкой (BBR, CUBIC, Reno) наращивает и сбрасывает окно в ответ на потери.<br>
<span class="muted">Флаги: <code>-w &lt;window&gt; -i 1</code>. Cwnd видно в колонке вывода iperf3.<br>
Для активации BBR: <code>sysctl -w net.ipv4.tcp_congestion_control=bbr</code></span></p>
<p>Что смотреть: если cwnd стабилен и растёт — канал чистый. Если cwnd резко падает и восстанавливается — есть потери или буферизация.</p>

<h3>Jitter / latency UDP</h3>
<p>UDP-пакеты размером 172 байта (типичный payload G.711 VoIP). Измеряет <strong>jitter</strong> (вариацию задержки)
и процент потерь — ключевые метрики для голосового и видеотрафика.<br>
<span class="muted">Флаги: <code>-u -b 1G -l 172</code>. Bandwidth намеренно ограничен — для VoIP важен не throughput, а стабильность.</span></p>
<table>
<tr><th>Метрика</th><th>Отлично</th><th>Допустимо</th><th>Плохо</th></tr>
<tr><td>Jitter</td><td>&lt; 1 мс</td><td>1–10 мс</td><td>&gt; 10 мс</td></tr>
<tr><td>Потери</td><td>0%</td><td>&lt; 1%</td><td>&gt; 1%</td></tr>
</table>

<h3>Multi-port stress</h3>
<p>Параллельные TCP-потоки на одном порту с высоким числом соединений. Нагружает таблицы состояний
<strong>NAT, stateful firewall, conntrack</strong> — оборудование, которое отслеживает каждое соединение отдельно.<br>
<span class="muted">Увеличьте количество потоков (-P) до 32–64 для максимальной нагрузки на conntrack.</span></p>
<p>Что смотреть: если throughput резко падает при большом числе потоков — узкое место в обработке состояний соединений.</p>
</div>

<hr>

<div class="section">
<h2>TCP Window (-w)</h2>
<p>Сколько байт может быть «в пути» без подтверждения. Определяет максимально достижимый throughput:</p>
<pre>max_throughput = window_size / RTT</pre>

<table>
<tr><th>Window</th><th>Оптимально для</th></tr>
<tr><td><code>64K</code></td><td>WAN, высокие задержки (&gt;10 мс)</td></tr>
<tr><td><code>128K</code></td><td>LAN, задержка 1–5 мс</td></tr>
<tr><td><code>256K</code></td><td><span class="ok">LAN 10G, задержка &lt;1 мс ✓</span></td></tr>
<tr><td><code>512K</code></td><td>10G+ с тюнингом ядра</td></tr>
<tr><td><code>1M</code></td><td>10G+ при включённом автотюнинге sysctl</td></tr>
<tr><td><code>4M</code></td><td>40/100G, jumbo frames</td></tr>
<tr><td><code>авто</code></td><td>Ядро управляет само — рекомендуется при настроенных tcp_rmem/wmem</td></tr>
</table>

<p class="muted">Рекомендация для 10G LAN: начните с <code>512K</code> или <code>авто</code> (если настроены sysctl-буферы).
При window 512K и RTT &lt;0.1 мс достигается ~13–14 Гбит/с на виртуальной сети.</p>
</div>

<hr>

<div class="section">
<h2>Параллельные потоки (-P)</h2>
<p>Один поток часто не насыщает 10G линк из-за ограничений одного ядра CPU.</p>

<table>
<tr><th>Потоки</th><th>Рекомендация</th></tr>
<tr><td><code>1</code></td><td>Диагностика, максимум на одно соединение</td></tr>
<tr><td><code>4</code></td><td>1G линки</td></tr>
<tr><td><code>8</code></td><td><span class="ok">10G линки — оптимально ✓</span></td></tr>
<tr><td><code>16</code></td><td>10G при jumbo frames или slow-start проблемах</td></tr>
<tr><td><code>32+</code></td><td>40G/100G, много ядер CPU</td></tr>
</table>
</div>

<hr>

<div class="section">
<h2>MSS — Maximum Segment Size (-M)</h2>
<p>Максимальный размер данных в одном TCP-сегменте. Связан с MTU:</p>
<pre>MSS = MTU − 40 байт (IP + TCP заголовки)</pre>

<table>
<tr><th>MTU</th><th>MSS</th><th>Применение</th></tr>
<tr><td>1500</td><td>1460</td><td>Стандартный Ethernet</td></tr>
<tr><td>9000</td><td>8960</td><td>Jumbo Frames</td></tr>
<tr><td>0 (авто)</td><td>ядро</td><td>Не передавать параметр, согласуется автоматически</td></tr>
</table>

<p>Для Jumbo Frames убедитесь, что MTU 9000 выставлен на обоих хостах и на всех коммутаторах:</p>
<pre>ip link set dev eth0 mtu 9000</pre>
</div>

<hr>

<div class="section">
<h2>Zero-copy (-Z)</h2>
<p>Использует <code>sendfile()</code> вместо стандартного <code>send()</code>. Данные передаются
напрямую из буфера ядра в сетевой стек без копирования в user-space.<br>
Снижает нагрузку на CPU на 20–40% при больших потоках.<br>
<span class="muted">Только для TCP. В UDP-режиме не поддерживается.</span></p>
</div>

<hr>

<div class="section">
<h2>Пропустить slow-start (-O 2)</h2>
<p>TCP slow-start: в первые 1–3 секунды скорость нарастает постепенно, занижая среднюю статистику.
Флаг <code>-O 2</code> говорит не считать первые 2 секунды в итоговый результат.<br>
<span class="muted">Рекомендуется оставлять включённым при тестах от 10 секунд.</span></p>
</div>

<hr>

<div class="section">
<h2>Тюнинг ОС для 10G</h2>
<p>Применяется на обоих хостах:</p>
<pre>ip link set dev eth0 mtu 9000
ip link set dev eth0 txqueuelen 10000

sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq
sysctl -w net.core.netdev_max_backlog=250000</pre>
<p class="muted">Для постоянного применения добавьте в <code>/etc/sysctl.conf</code>.</p>
</div>

<hr>

<div class="section">
<h2>Диагностика типичных проблем</h2>

<table>
<tr><th>Симптом</th><th>Причина</th><th>Решение</th></tr>
<tr><td>TCP &lt; 5 Гбит/с</td><td>Маленький Window или мало потоков</td><td>Window → 512K, потоки → 16</td></tr>
<tr><td>UDP losses &gt; 5%</td><td>Сеть или сервер не успевают</td><td>Снизить bandwidth или 1 поток</td></tr>
<tr><td>CPU 100% клиент</td><td>Ядро не справляется с pps</td><td>Включить Zero-copy или DPDK</td></tr>
<tr><td>Нестабильная скорость</td><td>TCP slow-start, буферизация</td><td>Включить -O 2, увеличить буферы</td></tr>
<tr><td>&lt; 1 Гбит/с на 10G</td><td>MTU не совпадает на пути</td><td>Проверить MTU на всех узлах</td></tr>
<tr><td>Среднее занижено</td><td>Парсер считал отдельные потоки</td><td>Обновите версию программы</td></tr>
</table>
</div>

</body></html>
"""



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Generator")
        self.setMinimumSize(1200, 780)
        self.worker: IperfWorker | None = None
        self._plot_x = deque(maxlen=600)
        self._plot_y = deque(maxlen=600)
        self._test_running = False
        self._setup_ui()
        self._setup_graph()
        self._update_ui_state()

    
    def _setup_ui(self):
        from PyQt6.QtWidgets import QSplitter, QTabWidget, QTabBar
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        
        self.top_tabs = QTabWidget()
        self.top_tabs.setDocumentMode(True)
        root.addWidget(self.top_tabs)

        
        test_widget = QWidget()
        test_layout = QHBoxLayout(test_widget)
        test_layout.setSpacing(0)
        test_layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER};
                border-radius: 2px;
            }}
            QSplitter::handle:hover {{
                background-color: {ACCENT_BLUE};
            }}
        """)

        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumWidth(300)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        left_inner = QWidget()
        left = QVBoxLayout(left_inner)
        left.setSpacing(10)
        left.setContentsMargins(12, 12, 8, 12)
        left.addWidget(self._build_connection_group())
        left.addWidget(self._build_ssh_group())
        left.addWidget(self._build_load_group())
        left.addWidget(self._build_advanced_group())
        left.addWidget(self._build_control_buttons())
        left.addWidget(self._build_stats_panel())
        left.addStretch()
        scroll.setWidget(left_inner)

        
        right_widget = QWidget()
        right = QVBoxLayout(right_widget)
        right.setSpacing(10)
        right.setContentsMargins(8, 12, 12, 12)
        right.addWidget(self._build_graph_area(), stretch=3)
        right.addWidget(self._build_log_area(), stretch=2)

        splitter.addWidget(scroll)
        splitter.addWidget(right_widget)
        splitter.setSizes([360, 800])   
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        test_layout.addWidget(splitter)
        self.top_tabs.addTab(test_widget, "  Тест  ")

        
        self.top_tabs.addTab(self._build_docs_tab(), "  Документация  ")

    def _build_docs_tab(self):
        """Вкладка с документацией по параметрам."""
        widget = QWidget()
        lay = QVBoxLayout(widget)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        docs = QTextEdit()
        docs.setReadOnly(True)
        docs.setStyleSheet(f"""
            QTextEdit {{
                background-color: {DARK_BG};
                border: none;
                color: {TEXT_PRIMARY};
                font-family: 'JetBrains Mono', 'Consolas', monospace;
                font-size: 13px;
                padding: 20px 32px;
            }}
        """)

        docs.setHtml(DOCS_HTML)
        lay.addWidget(docs)
        return widget

    def _build_connection_group(self):
        grp = QGroupBox("Подключение")
        lay = QGridLayout(grp)
        lay.setSpacing(8)
        lay.setColumnStretch(1, 1)

        lay.addWidget(self._lbl("IP"), 0, 0)
        self.inp_server = QLineEdit("192.168.100.2")
        lay.addWidget(self.inp_server, 0, 1)

        lay.addWidget(self._lbl("Порт"), 1, 0)
        self.inp_port = QSpinBox()
        self.inp_port.setRange(1, 65535)
        self.inp_port.setValue(5201)
        lay.addWidget(self.inp_port, 1, 1)

        return grp

    def _build_ssh_group(self):
        grp = QGroupBox("SSH")
        lay = QGridLayout(grp)
        lay.setSpacing(8)
        lay.setColumnStretch(1, 1)

        self.chk_ssh = QCheckBox("Использовать SSH")
        self.chk_ssh.toggled.connect(self._on_ssh_toggle)
        lay.addWidget(self.chk_ssh, 0, 0, 1, 2)

        self._ssh_widgets = []

        def ssh_row(row, label, widget):
            l = self._lbl(label)
            lay.addWidget(l, row, 0)
            lay.addWidget(widget, row, 1)
            self._ssh_widgets += [l, widget]

        self.inp_ssh_user = QLineEdit("kali")
        ssh_row(1, "Пользователь", self.inp_ssh_user)

        self.inp_ssh_pass = QLineEdit()
        self.inp_ssh_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_ssh_pass.setPlaceholderText("пусто = ключ ~/.ssh/id_rsa")
        ssh_row(2, "Пароль", self.inp_ssh_pass)

        self.inp_ssh_port = QSpinBox()
        self.inp_ssh_port.setRange(1, 65535)
        self.inp_ssh_port.setValue(22)
        ssh_row(3, "SSH порт", self.inp_ssh_port)

        self._on_ssh_toggle(False)
        return grp

    def _build_load_group(self):
        grp = QGroupBox("Параметры нагрузки")
        lay = QGridLayout(grp)
        lay.setSpacing(8)
        lay.setColumnStretch(1, 1)

        lay.addWidget(self._lbl("Режим"), 0, 0)
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItems([
            "TCP — макс. throughput",
            "UDP flood",
            "Bidirectional TCP",
            "Reverse (сервер → клиент)",
            "Small packets UDP",
            "TCP Congestion test",
            "Jitter / latency UDP",
            "Multi-port stress",
        ])
        self.cmb_mode.currentTextChanged.connect(self._on_mode_change)
        lay.addWidget(self.cmb_mode, 0, 1)

        self.lbl_mode_desc = QLabel()
        self.lbl_mode_desc.setWordWrap(True)
        self.lbl_mode_desc.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px; padding: 2px 0 4px 0;")
        lay.addWidget(self.lbl_mode_desc, 1, 0, 1, 2)

        lay.addWidget(self._lbl("Потоки (-P)"), 2, 0)
        self.inp_parallel = QSpinBox()
        self.inp_parallel.setRange(1, 64)
        self.inp_parallel.setValue(8)
        self.inp_parallel.setToolTip("Параллельные TCP/UDP потоки. 8–16 оптимально для 10G.")
        lay.addWidget(self.inp_parallel, 2, 1)

        lay.addWidget(self._lbl("Длительность, с"), 3, 0)
        self.inp_duration = QSpinBox()
        self.inp_duration.setRange(5, 3600)
        self.inp_duration.setValue(30)
        lay.addWidget(self.inp_duration, 3, 1)

        self.lbl_window = self._lbl("TCP Window")
        lay.addWidget(self.lbl_window, 4, 0)
        self.inp_window = QComboBox()
        self.inp_window.addItems(["64K", "128K", "256K", "512K", "1M", "4M", "авто"])
        self.inp_window.setCurrentText("256K")
        self.inp_window.setToolTip(
            "Размер приёмного окна TCP.\n"
            "256K–1M оптимально для 10G на LAN.\n"
            "авто — ядро выбирает само (рекомендуется при тюнинге sysctl)."
        )
        lay.addWidget(self.inp_window, 4, 1)

        self.lbl_bw = self._lbl("UDP bandwidth")
        lay.addWidget(self.lbl_bw, 5, 0)
        self.inp_bw = QLineEdit("10G")
        self.inp_bw.setToolTip("Целевая скорость UDP: 1G, 5G, 10G и т.д.")
        lay.addWidget(self.inp_bw, 5, 1)

        self.lbl_pkt = self._lbl("UDP пакет, байт")
        lay.addWidget(self.lbl_pkt, 6, 0)
        self.inp_pkt = QLineEdit("1400")
        self.inp_pkt.setToolTip("Размер UDP-пакета. 1400 = стандарт, 64 = small packets стресс-тест.")
        lay.addWidget(self.inp_pkt, 6, 1)

        self.chk_omit = QCheckBox("Пропустить slow-start  (-O 2)")
        self.chk_omit.setChecked(True)
        self.chk_omit.setToolTip("Игнорировать первые 2 секунды TCP slow-start при подсчёте статистики.")
        lay.addWidget(self.chk_omit, 7, 0, 1, 2)

        self._on_mode_change(self.cmb_mode.currentText())
        return grp

    def _build_advanced_group(self):
        grp = QGroupBox("Дополнительно")
        lay = QGridLayout(grp)
        lay.setSpacing(8)
        lay.setColumnStretch(1, 1)

        lay.addWidget(self._lbl("MSS, байт (0 = авто)"), 0, 0)
        self.inp_mtu = QSpinBox()
        self.inp_mtu.setRange(0, 9000)
        self.inp_mtu.setValue(0)
        self.inp_mtu.setSpecialValueText("авто")
        self.inp_mtu.setToolTip(
            "Maximum Segment Size для TCP.\n"
            "0 = не задавать (ядро выбирает).\n"
            "8960 для Jumbo Frames (MTU 9000)."
        )
        lay.addWidget(self.inp_mtu, 0, 1)

        self.chk_zerocopy = QCheckBox("Zero-copy  (-Z)")
        self.chk_zerocopy.setToolTip(
            "Использовать sendfile() вместо обычного send().\n"
            "Снижает нагрузку на CPU при больших потоках."
        )
        lay.addWidget(self.chk_zerocopy, 1, 0, 1, 2)

        return grp

    def _build_control_buttons(self):
        from PyQt6.QtWidgets import QProgressBar
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(6)

        btn_row = QWidget()
        btn_lay = QHBoxLayout(btn_row)
        btn_lay.setContentsMargins(0, 0, 0, 0)
        btn_lay.setSpacing(8)
        self.btn_start = QPushButton("▶  ЗАПУСТИТЬ")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.clicked.connect(self._start_test)
        self.btn_stop = QPushButton("■  СТОП")
        self.btn_stop.setObjectName("btnStop")
        self.btn_stop.clicked.connect(self._stop_test)
        btn_lay.addWidget(self.btn_start)
        btn_lay.addWidget(self.btn_stop)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%  %v / %m с")
        self.progress_bar.setFixedHeight(18)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {PANEL_BG};
                border: 1px solid {BORDER};
                border-radius: 3px;
                color: {TEXT_MUTED};
                font-size: 10px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {ACCENT_GREEN};
                border-radius: 2px;
            }}
        """)
        self.progress_bar.setVisible(False)

        self._progress_timer = QTimer()
        self._progress_timer.setInterval(1000)
        self._progress_timer.timeout.connect(self._tick_progress)

        lay.addWidget(btn_row)
        lay.addWidget(self.progress_bar)
        return w

    def _tick_progress(self):
        v = self.progress_bar.value() + 1
        m = self.progress_bar.maximum()
        if v >= m:
            self._progress_timer.stop()
            self.progress_bar.setValue(m)
        else:
            self.progress_bar.setValue(v)

    def _build_stats_panel(self):
        grp = QGroupBox("Статистика теста")
        lay = QGridLayout(grp)
        lay.setSpacing(6)

        def row(label):
            n = QLabel(label)
            n.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 11px;")
            v = QLabel("—")
            v.setStyleSheet(f"font-size: 19px; font-weight: bold; color: {ACCENT_GREEN};")
            v.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return n, v

        n0, self.lbl_cur = row("Текущая")
        n1, self.lbl_max = row("Максимум")
        n2, self.lbl_avg = row("Среднее")
        n3, self.lbl_min = row("Минимум")

        for i, (n, v) in enumerate([(n0, self.lbl_cur), (n1, self.lbl_max),
                                     (n2, self.lbl_avg), (n3, self.lbl_min)]):
            lay.addWidget(n, i, 0)
            lay.addWidget(v, i, 1)

        return grp

    def _build_graph_area(self):
        grp = QGroupBox("Скорость в реальном времени")
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(4, 10, 4, 4)

        pg.setConfigOptions(antialias=True, background=PANEL_BG, foreground=TEXT_MUTED)
        self.plot_widget = pg.PlotWidget(background=PANEL_BG)
        self.plot_widget.setLabel("left",   "Гбит/с", color=TEXT_MUTED)
        self.plot_widget.setLabel("bottom", "Время, с", color=TEXT_MUTED)
        self.plot_widget.showGrid(x=True, y=True, alpha=0.15)
        self.plot_widget.setYRange(0, 11)
        self.plot_widget.getAxis("left").setTextPen(TEXT_MUTED)
        self.plot_widget.getAxis("bottom").setTextPen(TEXT_MUTED)

        self.curve = self.plot_widget.plot(
            pen=pg.mkPen(color=ACCENT_GREEN, width=2),
            fillLevel=0,
            brush=pg.mkBrush(color=(63, 185, 80, 35))
        )
        lay.addWidget(self.plot_widget)
        return grp

    def _build_log_area(self):
        grp = QGroupBox("Лог")
        grp.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(4, 10, 4, 4)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        
        self.log_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        btn_clear = QPushButton("Очистить")
        btn_clear.setFixedWidth(100)
        btn_clear.clicked.connect(self.log_box.clear)

        lay.addWidget(self.log_box)
        lay.addWidget(btn_clear, alignment=Qt.AlignmentFlag.AlignRight)
        return grp

    
    def _setup_graph(self):
        self._plot_x.clear()
        self._plot_y.clear()
        self.curve.setData([], [])

    
    def _lbl(self, text):
        l = QLabel(text)
        l.setStyleSheet(f"color: {TEXT_MUTED};")
        return l

    
    def _on_ssh_toggle(self, checked: bool):
        for w in self._ssh_widgets:
            w.setEnabled(checked)

    MODE_DESCRIPTIONS = {
        "TCP — макс. throughput":   "Максимальная скорость по TCP. Параллельные потоки насыщают линк.",
        "UDP flood":                "UDP без контроля потока. Задайте bandwidth и размер пакета.",
        "Bidirectional TCP":        "Одновременная передача в обе стороны (требует iperf3 ≥ 3.7).",
        "Reverse (сервер → клиент)":"Трафик идёт с сервера на клиент — тест входящего канала.",
        "Small packets UDP":        "UDP пакеты 64 байт. Стресс-тест CPU и очередей коммутатора.",
        "TCP Congestion test":      "TCP с логированием cwnd каждую секунду. Визуализирует работу алгоритма перегрузки.",
        "Jitter / latency UDP":     "UDP с измерением jitter и потерь. Имитирует голосовой/видео трафик (VoIP).",
        "Multi-port stress":        "Параллельные потоки на N портах подряд. Нагрузка на таблицы NAT/firewall.",
    }

    def _on_mode_change(self, mode: str):
        self.lbl_mode_desc.setText(self.MODE_DESCRIPTIONS.get(mode, ""))
        is_udp = "UDP" in mode or mode == "Jitter / latency UDP"
        show_pkt = is_udp and mode not in ("Small packets UDP", "Jitter / latency UDP")
        self.lbl_window.setVisible(not is_udp)
        self.inp_window.setVisible(not is_udp)
        self.lbl_bw.setVisible(is_udp)
        self.inp_bw.setVisible(is_udp)
        self.lbl_pkt.setVisible(show_pkt)
        self.inp_pkt.setVisible(show_pkt)

    def _start_test(self):
        self._plot_x.clear()
        self._plot_y.clear()
        self.curve.setData([], [])
        for l in (self.lbl_cur, self.lbl_max, self.lbl_avg, self.lbl_min):
            l.setText("—")

        mtu_val = self.inp_mtu.value()
        cfg = {
            "server_ip": self.inp_server.text().strip(),
            "port":      self.inp_port.value(),
            "mode":      self.cmb_mode.currentText(),
            "parallel":  self.inp_parallel.value(),
            "duration":  self.inp_duration.value(),
            "window":    self.inp_window.currentText(),
            "bandwidth": self.inp_bw.text().strip(),
            "pkt_size":  self.inp_pkt.text().strip(),
            "omit":      self.chk_omit.isChecked(),
            "zerocopy":  self.chk_zerocopy.isChecked(),
            "mtu":       mtu_val if mtu_val > 0 else None,
            "use_ssh":   self.chk_ssh.isChecked(),
            "ssh_user":  self.inp_ssh_user.text().strip(),
            "ssh_pass":  self.inp_ssh_pass.text(),
            "ssh_port":  self.inp_ssh_port.value(),
        }

        if not cfg["server_ip"]:
            QMessageBox.warning(self, "Ошибка", "Укажите IP сервера")
            return

        self._log(f"\n{'─'*52}")
        self._log(f"  Тест запущен: {datetime.now().strftime('%H:%M:%S')}")
        self._log(f"  Режим:    {cfg['mode']}")
        self._log(f"  Потоки:   {cfg['parallel']}   Длит.: {cfg['duration']}с")
        self._log(f"{'─'*52}\n")

        self.worker = IperfWorker(cfg)
        self.worker.data_point.connect(self._on_data_point)
        self.worker.log_line.connect(self._log)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()
        self._test_running = True
        
        dur = cfg["duration"]
        self.progress_bar.setRange(0, dur)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"%v / {dur} с  (%p%)")
        self.progress_bar.setVisible(True)
        self._progress_timer.start()
        self._update_ui_state()

    def _stop_test(self):
        if self.worker:
            self.worker.stop()
            self._log("\n[!] Тест остановлен пользователем")
        self._test_running = False
        self._progress_timer.stop()
        self.progress_bar.setVisible(False)
        self._update_ui_state()

    def _on_data_point(self, ts: float, gbps: float):
        self._plot_x.append(ts)
        self._plot_y.append(gbps)
        self.curve.setData(list(self._plot_x), list(self._plot_y))
        self.lbl_cur.setText(f"{gbps:.2f} Гбит/с")
        if self._plot_y:
            self.lbl_max.setText(f"{max(self._plot_y):.2f} Гбит/с")
            self.lbl_min.setText(f"{min(self._plot_y):.2f} Гбит/с")
            self.lbl_avg.setText(f"{sum(self._plot_y)/len(self._plot_y):.2f} Гбит/с")

    def _on_finished(self, stats: dict):
        self._test_running = False
        self._progress_timer.stop()
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setVisible(False)
        self._update_ui_state()
        self._log(f"\n{'─'*52}")
        self._log(f"  Тест завершён")
        self._log(f"  Макс.:   {stats.get('max_gbps', 0):.3f} Гбит/с")
        self._log(f"  Среднее: {stats.get('avg_gbps', 0):.3f} Гбит/с")
        self._log(f"  Мин.:    {stats.get('min_gbps', 0):.3f} Гбит/с")
        if stats.get("jitter_ms") is not None:
            self._log(f"  Jitter:  {stats['jitter_ms']:.3f} мс")
        if stats.get("loss_pct") is not None:
            color = "⚠" if stats["loss_pct"] > 1 else "✓"
            self._log(f"  Потери:  {color} {stats['loss_pct']:.2f}%")
        if stats.get("retransmits"):
            self._log(f"  Retr:    {stats['retransmits']}")
        self._log(f"{'─'*52}")
        if stats.get("avg_gbps", 0) > 0:
            self.lbl_max.setText(f"{stats['max_gbps']:.2f} Гбит/с")
            self.lbl_avg.setText(f"{stats['avg_gbps']:.2f} Гбит/с")
            self.lbl_min.setText(f"{stats['min_gbps']:.2f} Гбит/с")

    def _on_error(self, msg: str):
        self._test_running = False
        self._update_ui_state()
        self._log(f"\n[ERROR] {msg}")
        QMessageBox.critical(self, "Ошибка", msg)

    def _log(self, text: str):
        self.log_box.append(text)
        self.log_box.moveCursor(QTextCursor.MoveOperation.End)

    def _update_ui_state(self):
        r = self._test_running
        self.btn_start.setEnabled(not r)
        self.btn_stop.setEnabled(r)
        self.inp_server.setEnabled(not r)
        self.inp_port.setEnabled(not r)
        self.cmb_mode.setEnabled(not r)
        self.inp_parallel.setEnabled(not r)
        self.inp_duration.setEnabled(not r)
        self.chk_ssh.setEnabled(not r)


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)

    try:
        import base64
        from PyQt6.QtGui import QPixmap, QIcon, QImage, QColor
        from PyQt6.QtCore import QByteArray, Qt
    
        raw = base64.b64decode(ICON_B64)
        ba = QByteArray(raw)
        img = QImage()
        img.loadFromData(ba)
        img = img.convertToFormat(QImage.Format.Format_ARGB32)
    
        if not img.isNull():
            side = min(img.width(), img.height())
            x = (img.width()  - side) // 2
            y = (img.height() - side) // 2
            img = img.copy(x, y, side, side)
        

            for py in range(img.height()):
                for px in range(img.width()):
                    c = QColor(img.pixel(px, py))
       
                    if c.red() > 240 and c.green() > 240 and c.blue() > 240:
                        img.setPixel(px, py, Qt.GlobalColor.transparent.value if hasattr(Qt.GlobalColor.transparent, 'value') else 0x00000000)
        
            pixmap = QPixmap.fromImage(img).scaled(
                256, 256,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            app.setWindowIcon(QIcon(pixmap))
    except Exception as e:
        print(f"Icon error: {e}")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor(DARK_BG))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.Base,            QColor(PANEL_BG))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor(DARK_BG))
    palette.setColor(QPalette.ColorRole.Text,            QColor(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.Button,          QColor(PANEL_BG))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor(TEXT_PRIMARY))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor(ACCENT_BLUE))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(DARK_BG))
    app.setPalette(palette)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
