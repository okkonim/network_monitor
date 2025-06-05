#!/usr/bin/env python3
"""
Advanced Network Connection Monitor for Linux
Comprehensive tool for detecting hidden and suspicious network connections
"""

import argparse
import hashlib
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

import psutil


class NetworkMonitor:
    def __init__(self, config=None):
        self.config = config or {}
        self.suspicious_patterns = [
            # Подозрительные порты
            r':(6667|6668|6669|6697|7000|31337|12345|54321|1337)',
            # Подозрительные IP-адреса (Tor nodes, известные C&C)
            r'(185\.220\.|199\.87\.|176\.10\.)',
            # Необычные процессы
            r'(python|nc|ncat|telnet|socat).*-[el]',
        ]
        self.baseline_connections = set()
        self.alerts = []
        self.db_path = 'network_monitor.db'
        self.init_database()

    def init_database(self):
        """Инициализация базы данных для хранения результатов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                local_addr TEXT,
                local_port INTEGER,
                remote_addr TEXT,
                remote_port INTEGER,
                protocol TEXT,
                state TEXT,
                pid INTEGER,
                process_name TEXT,
                process_path TEXT,
                suspicious BOOLEAN,
                hash TEXT UNIQUE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                description TEXT,
                severity TEXT,
                details TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def get_network_connections(self):
        """Получение всех сетевых подключений с максимальной детализацией"""
        connections = []

        # Используем psutil для базового анализа
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'laddr': conn.laddr,
                    'raddr': conn.raddr,
                    'status': conn.status,
                    'pid': conn.pid,
                    'type': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                }

                # Получаем информацию о процессе
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        conn_info.update({
                            'name': process.name(),
                            'exe': process.exe(),
                            'cmdline': ' '.join(process.cmdline()),
                            'create_time': process.create_time(),
                            'ppid': process.ppid(),
                            'username': process.username()
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connections.append(conn_info)
        except psutil.AccessDenied:
            print("Недостаточно прав для получения полной информации о соединениях")

        return connections

    def parse_proc_net(self):
        """Анализ /proc/net/* для низкоуровневой информации"""
        connections = {}

        # TCP соединения
        try:
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]  # Пропускаем заголовок
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        local_addr = self.parse_proc_address(parts[1])
                        remote_addr = self.parse_proc_address(parts[2])
                        state = self.parse_tcp_state(parts[3])
                        uid = int(parts[7])
                        inode = parts[9]

                        connections[inode] = {
                            'local_addr': local_addr,
                            'remote_addr': remote_addr,
                            'state': state,
                            'uid': uid,
                            'protocol': 'tcp',
                            'inode': inode
                        }
        except FileNotFoundError:
            pass

        # UDP соединения
        try:
            with open('/proc/net/udp', 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 8:
                        local_addr = self.parse_proc_address(parts[1])
                        remote_addr = self.parse_proc_address(parts[2])
                        uid = int(parts[7])
                        inode = parts[9]

                        connections[inode] = {
                            'local_addr': local_addr,
                            'remote_addr': remote_addr,
                            'state': 'ESTABLISHED',
                            'uid': uid,
                            'protocol': 'udp',
                            'inode': inode
                        }
        except FileNotFoundError:
            pass

        return connections

    def parse_proc_address(self, addr_str):
        """Парсинг адреса из /proc/net/*"""
        if ':' in addr_str:
            ip_hex, port_hex = addr_str.split(':')

            # Преобразование IP из hex
            ip_int = int(ip_hex, 16)
            ip_bytes = struct.pack('<I', ip_int)  # Little endian
            ip = socket.inet_ntoa(ip_bytes)

            # Преобразование порта
            port = int(port_hex, 16)

            return (ip, port)
        return None

    def parse_tcp_state(self, state_hex):
        """Преобразование состояния TCP из hex"""
        states = {
            '01': 'ESTABLISHED',
            '02': 'SYN_SENT',
            '03': 'SYN_RECV',
            '04': 'FIN_WAIT1',
            '05': 'FIN_WAIT2',
            '06': 'TIME_WAIT',
            '07': 'CLOSE',
            '08': 'CLOSE_WAIT',
            '09': 'LAST_ACK',
            '0A': 'LISTEN',
            '0B': 'CLOSING'
        }
        return states.get(state_hex, 'UNKNOWN')

    def get_process_by_inode(self, inode):
        """Поиск процесса по inode сокета"""
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue

            try:
                fd_path = f'/proc/{pid}/fd'
                for fd in os.listdir(fd_path):
                    try:
                        link = os.readlink(f'{fd_path}/{fd}')
                        if f'socket:[{inode}]' in link:
                            # Получаем информацию о процессе
                            with open(f'/proc/{pid}/cmdline', 'r') as f:
                                cmdline = f.read().replace('\x00', ' ').strip()
                            with open(f'/proc/{pid}/comm', 'r') as f:
                                comm = f.read().strip()

                            return {
                                'pid': int(pid),
                                'name': comm,
                                'cmdline': cmdline,
                                'exe': os.readlink(f'/proc/{pid}/exe') if os.path.exists(f'/proc/{pid}/exe') else None
                            }
                    except (OSError, FileNotFoundError, PermissionError):
                        continue
            except (OSError, FileNotFoundError, PermissionError):
                continue
        return None

    def scan_network_namespaces(self):
        """Сканирование сетевых пространств имен"""
        namespaces = []

        try:
            # Поиск всех сетевых namespace
            result = subprocess.run(['ip', 'netns', 'list'],
                                    capture_output=True, text=True, check=True)

            for line in result.stdout.strip().split('\n'):
                if line:
                    ns_name = line.split()[0]
                    namespaces.append(ns_name)

                    # Анализ соединений в namespace
                    try:
                        ns_result = subprocess.run(
                            ['ip', 'netns', 'exec', ns_name, 'ss', '-tuln'],
                            capture_output=True, text=True, check=True
                        )
                        print(f"Namespace {ns_name}:")
                        print(ns_result.stdout)
                    except subprocess.CalledProcessError:
                        pass

        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        return namespaces

    def check_hidden_processes(self):
        """Поиск скрытых процессов с сетевой активностью"""
        hidden_processes = []

        # Сравнение /proc с ps
        proc_pids = set()
        ps_pids = set()

        # PIDs из /proc
        for item in os.listdir('/proc'):
            if item.isdigit():
                proc_pids.add(int(item))

        # PIDs из ps
        try:
            result = subprocess.run(['ps', 'axo', 'pid'],
                                    capture_output=True, text=True, check=True)
            for line in result.stdout.strip().split('\n')[1:]:
                if line.strip().isdigit():
                    ps_pids.add(int(line.strip()))
        except subprocess.CalledProcessError:
            pass

        # Поиск различий
        hidden_pids = proc_pids - ps_pids

        for pid in hidden_pids:
            try:
                # Проверяем наличие сетевых соединений
                fd_path = f'/proc/{pid}/fd'
                has_sockets = False

                for fd in os.listdir(fd_path):
                    try:
                        link = os.readlink(f'{fd_path}/{fd}')
                        if 'socket:' in link:
                            has_sockets = True
                            break
                    except OSError:
                        continue

                if has_sockets:
                    try:
                        with open(f'/proc/{pid}/cmdline', 'r') as f:
                            cmdline = f.read().replace('\x00', ' ').strip()
                        hidden_processes.append({
                            'pid': pid,
                            'cmdline': cmdline,
                            'reason': 'Hidden from ps but has network activity'
                        })
                    except OSError:
                        pass

            except (OSError, PermissionError):
                continue

        return hidden_processes

    def analyze_traffic_patterns(self):
        """Анализ паттернов сетевого трафика"""
        patterns = {
            'suspicious_ports': [],
            'unusual_connections': [],
            'high_frequency_connections': [],
            'encryption_tunnels': []
        }

        connections = self.get_network_connections()

        # Анализ портов
        port_counter = Counter()
        for conn in connections:
            if conn.get('raddr'):
                port = conn['raddr'][1]
                port_counter[port] += 1

                # Проверка подозрительных портов
                if port in [6667, 6668, 6669, 6697, 7000, 31337, 12345, 54321, 1337]:
                    patterns['suspicious_ports'].append({
                        'port': port,
                        'connection': conn,
                        'reason': 'Known suspicious port'
                    })

        # Поиск высокочастотных соединений
        for port, count in port_counter.most_common(10):
            if count > 10:
                patterns['high_frequency_connections'].append({
                    'port': port,
                    'count': count,
                    'reason': 'High frequency connections'
                })

        return patterns

    def check_rootkit_network_hiding(self):
        """Проверка сокрытия сетевых соединений руткитами"""
        discrepancies = []

        # Сравнение результатов разных методов
        psutil_connections = set()
        proc_connections = set()

        # Получаем соединения через psutil
        for conn in psutil.net_connections():
            if conn.laddr and conn.raddr:
                psutil_connections.add(f"{conn.laddr}:{conn.raddr}")

        # Получаем соединения из /proc
        proc_data = self.parse_proc_net()
        for inode, conn in proc_data.items():
            if conn['local_addr'] and conn['remote_addr']:
                proc_connections.add(f"{conn['local_addr']}:{conn['remote_addr']}")

        # Ищем различия
        hidden_from_psutil = proc_connections - psutil_connections
        hidden_from_proc = psutil_connections - proc_connections

        if hidden_from_psutil:
            discrepancies.append({
                'type': 'hidden_from_psutil',
                'connections': list(hidden_from_psutil),
                'severity': 'high'
            })

        if hidden_from_proc:
            discrepancies.append({
                'type': 'hidden_from_proc',
                'connections': list(hidden_from_proc),
                'severity': 'medium'
            })

        return discrepancies

    def deep_packet_inspection(self):
        """Глубокий анализ пакетов (требует root)"""
        suspicious_traffic = []

        if os.geteuid() != 0:
            return [{'error': 'Root privileges required for packet inspection'}]

        try:
            # Используем tcpdump для захвата трафика
            cmd = ['tcpdump', '-i', 'any', '-c', '100', '-n', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # Анализ захваченного трафика
            for line in result.stdout.split('\n'):
                if any(pattern in line for pattern in ['base64', 'encrypted', 'tunnel']):
                    suspicious_traffic.append({
                        'packet': line,
                        'reason': 'Potentially encrypted or encoded traffic'
                    })

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return suspicious_traffic

    def check_docker_containers(self):
        """Анализ сетевых соединений Docker контейнеров"""
        container_connections = []

        try:
            # Получаем список контейнеров
            result = subprocess.run(['docker', 'ps', '-q'],
                                    capture_output=True, text=True, check=True)

            for container_id in result.stdout.strip().split('\n'):
                if container_id:
                    # Анализ сетевых соединений контейнера
                    try:
                        net_result = subprocess.run(
                            ['docker', 'exec', container_id, 'netstat', '-tuln'],
                            capture_output=True, text=True, check=True
                        )

                        container_connections.append({
                            'container_id': container_id,
                            'connections': net_result.stdout,
                            'timestamp': datetime.now().isoformat()
                        })
                    except subprocess.CalledProcessError:
                        pass

        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        return container_connections

    def generate_baseline(self):
        """Создание базовой линии нормальной активности"""
        print("Создание базовой линии сетевой активности...")

        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'connections': [],
            'processes': [],
            'listening_ports': []
        }

        # Собираем текущие соединения
        connections = self.get_network_connections()
        for conn in connections:
            conn_hash = hashlib.md5(str(conn).encode()).hexdigest()
            self.baseline_connections.add(conn_hash)
            baseline_data['connections'].append(conn)

        # Сохраняем базовую линию
        with open('network_baseline.json', 'w') as f:
            json.dump(baseline_data, f, indent=2, default=str)

        print(f"Базовая линия создана: {len(baseline_data['connections'])} соединений")

    def compare_with_baseline(self):
        """Сравнение текущего состояния с базовой линией"""
        anomalies = []

        try:
            with open('network_baseline.json', 'r') as f:
                baseline = json.load(f)
        except FileNotFoundError:
            return [{'error': 'Baseline not found. Run with --baseline first'}]

        current_connections = self.get_network_connections()
        current_hashes = set()

        for conn in current_connections:
            conn_hash = hashlib.md5(str(conn).encode()).hexdigest()
            current_hashes.add(conn_hash)

            if conn_hash not in self.baseline_connections:
                anomalies.append({
                    'type': 'new_connection',
                    'connection': conn,
                    'severity': 'medium',
                    'timestamp': datetime.now().isoformat()
                })

        # Поиск исчезнувших соединений
        disappeared = self.baseline_connections - current_hashes
        if disappeared:
            anomalies.append({
                'type': 'disappeared_connections',
                'count': len(disappeared),
                'severity': 'low',
                'timestamp': datetime.now().isoformat()
            })

        return anomalies

    def continuous_monitoring(self, duration=3600):
        """Непрерывный мониторинг"""
        print(f"Запуск непрерывного мониторинга на {duration} секунд...")

        start_time = time.time()
        previous_connections = set()

        while time.time() - start_time < duration:
            current_connections = set()

            for conn in self.get_network_connections():
                conn_str = f"{conn.get('laddr', '')}:{conn.get('raddr', '')}:{conn.get('pid', '')}"
                current_connections.add(conn_str)

            # Поиск новых соединений
            new_connections = current_connections - previous_connections
            if new_connections:
                timestamp = datetime.now().isoformat()
                for conn in new_connections:
                    self.log_alert('new_connection', f'New connection detected: {conn}', 'medium')

            previous_connections = current_connections
            time.sleep(5)  # Проверка каждые 5 секунд

    def log_alert(self, alert_type, description, severity):
        """Логирование предупреждений"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'description': description,
            'severity': severity
        }

        self.alerts.append(alert)

        # Сохранение в базу данных
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, description, severity, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert['timestamp'], alert_type, description, severity, json.dumps(alert)))
        conn.commit()
        conn.close()

        print(f"[{severity.upper()}] {alert['timestamp']}: {description}")

    def export_results(self, format='json'):
        """Экспорт результатов"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'connections': self.get_network_connections(),
            'suspicious_patterns': self.analyze_traffic_patterns(),
            'rootkit_check': self.check_rootkit_network_hiding(),
            'hidden_processes': self.check_hidden_processes(),
            'alerts': self.alerts
        }

        if format == 'json':
            filename = f'network_scan_{int(time.time())}.json'
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"Результаты сохранены в {filename}")

        elif format == 'html':
            self.generate_html_report(results)

        return results

    def generate_html_report(self, results):
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .alert-high {{ color: red; font-weight: bold; }}
                .alert-medium {{ color: orange; }}
                .alert-low {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Network Security Scan Report</h1>
            <p>Generated: {results['timestamp']}</p>

            <h2>Summary</h2>
            <ul>
                <li>Total Connections: {len(results['connections'])}</li>
                <li>Suspicious Patterns: {len(results['suspicious_patterns'].get('suspicious_ports', []))}</li>
                <li>Alerts: {len(results['alerts'])}</li>
            </ul>

            <h2>Active Connections</h2>
            <table>
                <tr>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>Process</th>
                    <th>Status</th>
                </tr>
        """

        for conn in results['connections']:
            local_addr = f"{conn.get('laddr', ['', ''])[0]}:{conn.get('laddr', ['', ''])[1]}"
            remote_addr = f"{conn.get('raddr', ['', ''])[0]}:{conn.get('raddr', ['', ''])[1]}" if conn.get(
                'raddr') else ""
            process = conn.get('name', 'Unknown')
            status = conn.get('status', 'Unknown')

            html_template += f"""
                <tr>
                    <td>{local_addr}</td>
                    <td>{remote_addr}</td>
                    <td>{process}</td>
                    <td>{status}</td>
                </tr>
            """

        html_template += """
            </table>

            <h2>Alerts</h2>
            <ul>
        """

        for alert in results['alerts']:
            severity_class = f"alert-{alert.get('severity', 'low')}"
            html_template += f'<li class="{severity_class}">{alert.get("description", "")}</li>'

        html_template += """
            </ul>
        </body>
        </html>
        """

        filename = f'network_report_{int(time.time())}.html'
        with open(filename, 'w') as f:
            f.write(html_template)
        print(f"HTML отчет сохранен в {filename}")

    def run_comprehensive_scan(self):
        """Полное сканирование системы"""
        print("Запуск комплексного сканирования сетевой безопасности...")
        print("=" * 60)

        # 1. Основной анализ соединений
        print("\n1. Анализ активных соединений...")
        connections = self.get_network_connections()
        print(f"Найдено активных соединений: {len(connections)}")

        # 2. Низкоуровневый анализ
        print("\n2. Низкоуровневый анализ /proc/net...")
        proc_connections = self.parse_proc_net()
        print(f"Соединений в /proc/net: {len(proc_connections)}")

        # 3. Поиск скрытых процессов
        print("\n3. Поиск скрытых процессов...")
        hidden_processes = self.check_hidden_processes()
        if hidden_processes:
            print(f"ВНИМАНИЕ: Найдено {len(hidden_processes)} скрытых процессов с сетевой активностью!")
            for proc in hidden_processes:
                self.log_alert('hidden_process', f"Hidden process: PID {proc['pid']} - {proc['cmdline']}", 'high')
        else:
            print("Скрытых процессов не найдено")

        # 4. Анализ паттернов трафика
        print("\n4. Анализ паттернов трафика...")
        patterns = self.analyze_traffic_patterns()
        for pattern_type, items in patterns.items():
            if items:
                print(f"  {pattern_type}: {len(items)} обнаружено")
                for item in items:
                    self.log_alert('suspicious_pattern', f"{pattern_type}: {item.get('reason', '')}", 'medium')

        # 5. Проверка руткитов
        print("\n5. Проверка сокрытия соединений руткитами...")
        rootkit_check = self.check_rootkit_network_hiding()
        if rootkit_check:
            print(f"ВНИМАНИЕ: Обнаружены расхождения в данных о соединениях!")
            for discrepancy in rootkit_check:
                self.log_alert('rootkit_hiding', f"Network hiding detected: {discrepancy['type']}",
                               discrepancy['severity'])
        else:
            print("Признаков сокрытия соединений не найдено")

        # 6. Анализ Docker контейнеров
        print("\n6. Анализ Docker контейнеров...")
        docker_connections = self.check_docker_containers()
        if docker_connections:
            print(f"Найдено {len(docker_connections)} активных контейнеров")
        else:
            print("Docker контейнеры не найдены или Docker не установлен")

        # 7. Сканирование сетевых пространств имен
        print("\n7. Сканирование network namespaces...")
        namespaces = self.scan_network_namespaces()
        if namespaces:
            print(f"Найдено {len(namespaces)} сетевых пространств имен")
        else:
            print("Дополнительных network namespaces не найдено")

        # 8. Глубокий анализ пакетов (если root)
        if os.geteuid() == 0:
            print("\n8. Глубокий анализ пакетов...")
            packet_analysis = self.deep_packet_inspection()
            if packet_analysis and not any('error' in item for item in packet_analysis):
                print(f"Проанализировано пакетов: {len(packet_analysis)}")
        else:
            print("\n8. Глубокий анализ пакетов пропущен (требуются root права)")

        print("\n" + "=" * 60)
        print("Сканирование завершено!")

        # Экспорт результатов
        results = self.export_results()

        # Вывод сводки
        if self.alerts:
            print(f"\nВНИМАНИЕ: Обнаружено {len(self.alerts)} потенциальных угроз!")
            high_severity = [a for a in self.alerts if a.get('severity') == 'high']
            if high_severity:
                print(f"Критических угроз: {len(high_severity)}")
        else:
            print("\nСерьезных угроз не обнаружено")

        return results


def print_detailed_help():
    """Выводит детальную справку по использованию программы"""
    help_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Advanced Network Connection Monitor                       ║
║                     Комплексный мониторинг сетевых подключений               ║
╚══════════════════════════════════════════════════════════════════════════════╝

ОПИСАНИЕ:
    Продвинутый инструмент для обнаружения скрытых и подозрительных сетевых 
    соединений в Linux системах. Может обнаруживать руткиты, скрытые процессы,
    подозрительные соединения и аномальную сетевую активность.

ИСПОЛЬЗОВАНИЕ:
    python3 network_monitor.py [ОПЦИИ]

ОСНОВНЫЕ КОМАНДЫ:
    --scan                  Запуск полного комплексного сканирования системы
                           (рекомендуется для первого использования)

    --baseline             Создание базовой линии нормальной сетевой активности
                          (сохраняется в network_baseline.json)

    --compare              Сравнение текущего состояния с базовой линией
                          (требует предварительного создания baseline)

    --monitor СЕКУНДЫ      Непрерывный мониторинг в реальном времени
                          Пример: --monitor 3600 (мониторинг на 1 час)

ОПЦИИ ЭКСПОРТА:
    --export FORMAT        Формат экспорта результатов
                          json - JSON файл (по умолчанию)
                          html - HTML отчет с графическим интерфейсом

    --verbose, -v          Подробный вывод информации

ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:

    1. Быстрое сканирование (без параметров):
       python3 network_monitor.py

    2. Полное комплексное сканирование:
       sudo python3 network_monitor.py --scan --export html

    3. Создание базовой линии:
       python3 network_monitor.py --baseline

    4. Проверка на аномалии:
       python3 network_monitor.py --compare --verbose

    5. Мониторинг в реальном времени:
       python3 network_monitor.py --monitor 1800

    6. Полный анализ с экспортом в HTML:
       sudo python3 network_monitor.py --scan --export html --verbose

ВОЗМОЖНОСТИ ОБНАРУЖЕНИЯ:

    ✓ Скрытые процессы с сетевой активностью
    ✓ Подозрительные порты и соединения
    ✓ Сокрытие соединений руткитами
    ✓ Аномальные паттерны трафика
    ✓ Высокочастотные соединения
    ✓ Туннелирование и шифрование
    ✓ Docker контейнеры
    ✓ Network namespaces
    ✓ Глубокий анализ пакетов (root)

ПОДОЗРИТЕЛЬНЫЕ ИНДИКАТОРЫ:

    • Порты: 6667-6669, 6697, 7000, 31337, 12345, 54321, 1337
    • IP-адреса: Tor nodes, известные C&C серверы
    • Процессы: Необычные сетевые утилиты
    • Поведение: Сокрытие от стандартных утилит

ТРЕБОВАНИЯ:

    Python 3.6+
    Модули: psutil, netaddr

    Установка зависимостей:
    pip3 install psutil netaddr

    Для полного функционала требуются root права:
    sudo python3 network_monitor.py --scan

ФАЙЛЫ РЕЗУЛЬТАТОВ:

    network_baseline.json       - Базовая линия активности
    network_scan_[timestamp].json - Результаты сканирования
    network_report_[timestamp].html - HTML отчет
    network_monitor.db          - База данных результатов

УРОВНИ СЕРЬЕЗНОСТИ УГРОЗ:

    HIGH    - Критические угрозы (скрытые процессы, руткиты)
    MEDIUM  - Подозрительная активность (новые соединения, порты)  
    LOW     - Аномалии (изменения в baseline)

ПРИМЕЧАНИЯ:

    • Некоторые функции требуют root привилегий
    • Первый запуск рекомендуется с --scan
    • Для регулярного мониторинга используйте --baseline и --compare
    • HTML отчеты удобны для документирования результатов

АВТОР: Advanced Network Security Tools
ВЕРСИЯ: 2.0
    """
    print(help_text)


def print_usage_examples():
    """Выводит примеры использования"""
    examples = """
ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ NETWORK MONITOR:

1. Базовое сканирование:
   python3 network_monitor.py

2. Полное сканирование безопасности:
   sudo python3 network_monitor.py --scan

3. Создание эталона и мониторинг:
   python3 network_monitor.py --baseline
   # ... через некоторое время ...
   python3 network_monitor.py --compare

4. Непрерывный мониторинг на 2 часа:
   python3 network_monitor.py --monitor 7200

5. Детальный анализ с HTML отчетом:
   sudo python3 network_monitor.py --scan --export html --verbose

6. Быстрая проверка изменений:
   python3 network_monitor.py --compare --verbose

СЦЕНАРИИ ИСПОЛЬЗОВАНИЯ:

Расследование инцидента:
    1. sudo python3 network_monitor.py --scan --export html
    2. Анализ HTML отчета на предмет аномалий
    3. python3 network_monitor.py --monitor 600 (наблюдение 10 мин)

Регулярный мониторинг:
    1. python3 network_monitor.py --baseline (еженедельно)
    2. python3 network_monitor.py --compare (ежедневно)
    3. Автоматизация через cron

Аудит безопасности:
    1. sudo python3 network_monitor.py --scan --export html
    2. Документирование результатов
    3. Сравнение с предыдущими аудитами
    """
    print(examples)


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Connection Monitor - Комплексный мониторинг сетевых подключений',
        epilog='Для детальной справки используйте: python3 network_monitor.py --detailed-help',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Добавляем новую опцию для детальной справки
    parser.add_argument('--detailed-help', action='store_true',
                        help='Показать детальную справку с примерами использования')

    parser.add_argument('--examples', action='store_true',
                        help='Показать примеры использования программы')

    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Запустить интерактивный режим выбора операций')

    parser.add_argument('--baseline', action='store_true',
                        help='Создать базовую линию нормальной сетевой активности')

    parser.add_argument('--compare', action='store_true',
                        help='Сравнить текущее состояние с базовой линией')

    parser.add_argument('--monitor', type=int, metavar='SECONDS',
                        help='Непрерывный мониторинг на указанное количество секунд')

    parser.add_argument('--scan', action='store_true',
                        help='Запустить полное комплексное сканирование безопасности')

    parser.add_argument('--export', choices=['json', 'html'], default='json',
                        help='Формат экспорта результатов: json или html (по умолчанию: json)')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Подробный вывод информации о процессе сканирования')

    args = parser.parse_args()

    if args.detailed_help:
        print_detailed_help()
        return

    if args.examples:
        print_usage_examples()
        return

    if args.interactive:
        interactive_help()
        return

    monitor = NetworkMonitor()

    # Остальная логика остается без изменений
    if args.baseline:
        monitor.generate_baseline()
    elif args.compare:
        anomalies = monitor.compare_with_baseline()
        if anomalies:
            print("Обнаружены аномалии:")
            for anomaly in anomalies:
                if args.verbose:
                    print(f"  Детально: {anomaly}")
                else:
                    print(f"  {anomaly.get('type', 'Unknown')}: {anomaly.get('description', 'No description')}")
        else:
            print("Аномалий не обнаружено")
    elif args.monitor:
        print(f"Запуск мониторинга на {args.monitor} секунд...")
        if args.verbose:
            print("Режим подробного вывода включен")
        monitor.continuous_monitoring(args.monitor)
    elif args.scan:
        if args.verbose:
            print("Запуск полного сканирования в подробном режиме...")
        monitor.run_comprehensive_scan()
    else:
        # По умолчанию запускаем быстрое сканирование
        print("Запуск быстрого сканирования сети...")
        if args.verbose:
            print("Для полного сканирования используйте: --scan")
            print("Для создания базовой линии: --baseline")
            print("Для помощи: --help или --detailed-help")

        connections = monitor.get_network_connections()
        patterns = monitor.analyze_traffic_patterns()
        print(f"Активных соединений: {len(connections)}")

        if args.verbose:
            print(f"Анализируемые типы паттернов: {list(patterns.keys())}")

        # Показываем подозрительные соединения
        suspicious_found = False
        for pattern_type, items in patterns.items():
            if items:
                suspicious_found = True
                print(f"\n{pattern_type.upper()}:")
                display_count = 5 if not args.verbose else len(items)
                for item in items[:display_count]:
                    if args.verbose:
                        print(f"  - {item}")
                    else:
                        print(f"  - {item.get('reason', 'Unknown')}")

                if len(items) > 5 and not args.verbose:
                    print(f"  ... и еще {len(items) - 5} элементов (используйте --verbose)")

        if not suspicious_found:
            print("Подозрительной активности не обнаружено")
            if args.verbose:
                print("Это хороший знак! Система выглядит чистой.")

        if args.export:
            print(f"Экспорт результатов в формате {args.export}...")
            monitor.export_results(args.export)


def interactive_help():
    """Интерактивная справка с выбором режима"""
    print("\n" + "=" * 60)
    print("             ИНТЕРАКТИВНАЯ СПРАВКА")
    print("=" * 60)

    options = {
        '1': ('Быстрое сканирование', 'python3 network_monitor.py'),
        '2': ('Полное сканирование безопасности', 'sudo python3 network_monitor.py --scan'),
        '3': ('Создать базовую линию', 'python3 network_monitor.py --baseline'),
        '4': ('Проверить аномалии', 'python3 network_monitor.py --compare'),
        '5': ('Мониторинг в реальном времени', 'python3 network_monitor.py --monitor 3600'),
        '6': ('Экспорт в HTML', 'python3 network_monitor.py --scan --export html'),
        '0': ('Выход', None)
    }

    while True:
        print("\nВыберите режим работы:")
        for key, (desc, cmd) in options.items():
            print(f"  {key}. {desc}")

        choice = input("\nВаш выбор (0-6): ").strip()

        if choice == '0':
            break
        elif choice in options and choice != '0':
            desc, cmd = options[choice]
            print(f"\nВыбран режим: {desc}")
            print(f"Команда: {cmd}")

            if choice in ['2', '6']:  # Команды, требующие root
                print("⚠️  Требуются root права для полного функционала")

            confirm = input("Запустить? (y/n): ").strip().lower()
            if confirm in ['y', 'yes', 'да', 'д']:
                print(f"Выполняется: {cmd}")
                try:
                    os.system(cmd)
                except KeyboardInterrupt:
                    print("\nВыполнение прервано")
            break
        else:
            print("Неправильный выбор. Попробуйте еще раз.")


def show_banner():
    """Показывает баннер программы"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║              Advanced Network Connection Monitor              ║
    ║                     v2.0 Security Edition                    ║
    ║                                                              ║
    ║  Обнаружение скрытых соединений, руткитов и угроз           ║
    ║  Detection of hidden connections, rootkits and threats       ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            print("ПРЕДУПРЕЖДЕНИЕ: Скрипт запущен без root прав.")
            print("Некоторые функции будут недоступны.")
            print("Для полного анализа запустите: sudo python3 network_monitor.py")
            print()

        main()
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"Ошибка выполнения: {e}")
        sys.exit(1)
