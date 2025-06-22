#!/usr/bin/env python3
"""
Advanced Network Connection Monitor for Linux
Comprehensive tool for detecting hidden and suspicious network connections
"""

import argparse
import hashlib
import json
import logging
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

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class NetworkMonitor:
    def __init__(self, config=None):
        self.config = config or {}
        self.filters = {
            'connection_types': self.config.get('connection_types', []),  # tcp, udp, tcp6, udp6
            'connection_states': self.config.get('connection_states', []),  # ESTABLISHED, LISTEN, etc.
            'pids': self.config.get('pids', []),  # Конкретные PID
            'process_names': self.config.get('process_names', []),  # Имена процессов
            'ports': self.config.get('ports', []),  # Конкретные порты
            'exclude_local': self.config.get('exclude_local', False),  # Исключить локальные соединения
            'only_external': self.config.get('only_external', False),  # Только внешние соединения
            'min_port': self.config.get('min_port', None),  # Минимальный порт
            'max_port': self.config.get('max_port', None),  # Максимальный порт
        }
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
        try:
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
        except sqlite3.Error as e:
            logging.error(f"Database initialization error: {e}")
            # В этом случае дальнейшая работа с БД невозможна, но скрипт может продолжить работу без нее
            self.db_path = "" # Используем пустую строку вместо None

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
                    'type': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                    'family': conn.family,  # Добавляем family для совместимости
                    'conn_type': conn.type  # Добавляем type для совместимости
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
            print("Insufficient privileges to get full connection details.")
            # На Windows без прав администратора это может быть частой проблемой
            # Логируем, но не прерываем выполнение
            logging.warning("Access denied when getting connection details. Run as admin/root for full info.")

        return connections

    def parse_proc_net(self):
        """Анализ /proc/net/* для низкоуровневой информации. Доступно только на Linux."""
        if not sys.platform.startswith('linux'):
            logging.info("/proc/net parsing is only available on Linux.")
            return {}

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
            logging.debug("File /proc/net/tcp not found, skipping TCP analysis.")
            pass
        except Exception as e:
            logging.error(f"Error reading /proc/net/tcp: {e}")
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
                            'state': 'ESTABLISHED', # UDP is stateless
                            'uid': uid,
                            'protocol': 'udp',
                            'inode': inode
                        }
        except FileNotFoundError:
            logging.debug("File /proc/net/udp not found, skipping UDP analysis.")
            pass
        except Exception as e:
            logging.error(f"Error reading /proc/net/udp: {e}")
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
        """Поиск процесса по inode сокета. Доступно только на Linux."""
        if not sys.platform.startswith('linux'):
            return None

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
        """Сканирование сетевых пространств имен. Доступно только на Linux."""
        if not sys.platform.startswith('linux'):
            logging.info("Network namespace scanning is only available on Linux.")
            return []
        
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
            logging.warning("Could not run 'ip netns list'. Make sure 'ip' command is available.")
            pass

        return namespaces

    def check_hidden_processes(self):
        """Поиск скрытых процессов с сетевой активностью. Доступно только на Linux."""
        if not sys.platform.startswith('linux'):
            logging.info("Hidden process check is only available on Linux.")
            return []

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
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.warning("Could not run 'ps' command. Hidden process check may be inaccurate.")
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

    def analyze_traffic_patterns(self, connections=None):
        """Анализ паттернов сетевого трафика"""
        if connections is None:
            connections = self.get_network_connections()
        
        patterns = {
            'suspicious_ports': [],
            'unusual_connections': [],
            'high_frequency_connections': [],
            'encryption_tunnels': []
        }

        # Анализ портов
        port_counter = Counter()
        for conn in connections:
            if conn.get('raddr'):
                try:
                    port = conn['raddr'][1]
                except (IndexError, TypeError):
                    continue
                    
                port_counter[port] += 1

                # Проверка подозрительных портов
                if port in [6667, 6668, 6669, 6697, 7000, 31337, 12345, 54321, 1337]:
                    patterns['suspicious_ports'].append({
                        'port': port,
                        'connection': conn,
                        'reason': 'Known suspicious port'
                    })
            
            # Анализ необычных соединений
            process_name = conn.get('name', '').lower()
            if process_name in ['nc', 'ncat', 'telnet', 'socat', 'python', 'python3']:
                patterns['unusual_connections'].append({
                    'process': process_name,
                    'connection': conn,
                    'reason': f'Potentially suspicious process: {process_name}'
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
        """Проверка сокрытия сетевых соединений руткитами. Доступно только на Linux."""
        if not sys.platform.startswith('linux'):
            logging.info("Rootkit network hiding check is only available on Linux.")
            return []
        
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
        """Глубокий анализ пакетов (требует root и доступно только на Linux)"""
        if not sys.platform.startswith('linux'):
            logging.info("Packet inspection is only available on Linux.")
            return []

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
            logging.warning("Could not run 'tcpdump'. Packet inspection skipped.")
            pass

        return suspicious_traffic

    def check_docker_containers(self):
        """Анализ сетевых соединений Docker контейнеров"""
        container_connections = []

        try:
            # Получаем список контейнеров
            result = subprocess.run(['docker', 'ps', '-q'],
                                    capture_output=True, text=True, check=True)

            container_ids = [cid.strip() for cid in result.stdout.strip().split('\n') if cid.strip()]

            if not container_ids:
                logging.info("No active Docker containers found.")
                return container_connections

            logging.info(f"Found {len(container_ids)} active containers.")

            for container_id in container_ids:
                logging.info(f"Processing container: {container_id}")

                try:
                    # Анализ сетевых соединений контейнера
                    net_result = subprocess.run(
                        ['docker', 'exec', container_id, 'netstat', '-tuln'],
                        capture_output=True, text=True, check=True, timeout=10
                    )

                    container_connections.append({
                        'container_id': container_id,
                        'connections': net_result.stdout,
                        'timestamp': datetime.now().isoformat()
                    })

                    logging.info(f"Container {container_id} processed successfully.")

                except subprocess.CalledProcessError as e:
                    reason = "netstat command unavailable in container"
                    if e.returncode == 126:
                        reason = "netstat not installed in container"
                    elif e.returncode == 127:
                        reason = "netstat not found in container"
                    else:
                        reason = f"error executing netstat (code {e.returncode})"

                    logging.warning(f"Container {container_id} not processed: {reason}")

                    # Добавляем запись об ошибке
                    container_connections.append({
                        'container_id': container_id,
                        'error': reason,
                        'timestamp': datetime.now().isoformat()
                    })

                except subprocess.TimeoutExpired:
                    reason = "netstat command timed out"
                    logging.warning(f"Container {container_id} not processed: {reason}")

                    container_connections.append({
                        'container_id': container_id,
                        'error': reason,
                        'timestamp': datetime.now().isoformat()
                    })

        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing 'docker ps'. Make sure Docker is running and you have permissions. Error: {e}")
            return [{'error': f'Docker error: {e}'}]
        except FileNotFoundError:
            logging.error("The 'docker' command was not found. Docker is not installed or not in PATH.")
            return [{'error': 'Docker is not installed'}]
        except Exception as e:
            logging.error(f"Unexpected error while working with Docker: {e}")
            return [{'error': f'Unexpected Docker error: {e}'}]

        logging.info(f"Analysis complete. Processed {len(container_connections)} records.")
        return container_connections

    def generate_baseline(self):
        """Исправленная версия создания базовой линии"""
        print("Creating network activity baseline...")

        baseline_data = {
            'timestamp': datetime.now().isoformat(),
            'connection_hashes': [],
            'connection_count': 0,
            'listening_ports': []
        }

        # Собираем текущие соединения
        connections = self.get_network_connections()
        connection_hashes = []

        for conn in connections:
            # Создаем уникальный отпечаток соединения
            conn_fingerprint = {
                'family': str(conn.get('family', '')),
                'type': str(conn.get('conn_type', '')),
                'laddr': self._safe_format_address(conn.get('laddr')),
                'raddr': self._safe_format_address(conn.get('raddr')),
                'status': conn.get('status', ''),
                'pid': conn.get('pid', '')
            }

            conn_hash = hashlib.md5(json.dumps(conn_fingerprint, sort_keys=True).encode()).hexdigest()
            connection_hashes.append(conn_hash)
            self.baseline_connections.add(conn_hash)

        baseline_data['connection_hashes'] = connection_hashes
        baseline_data['connection_count'] = len(connections)

        # Сохраняем базовую линию
        with open('network_baseline.json', 'w') as f:
            json.dump(baseline_data, f, indent=2)

        print(f"Baseline created: {len(connections)} connections recorded.")

    def _safe_format_address(self, addr):
        """Безопасное форматирование адреса"""
        if addr is None:
            return "none"
        try:
            if isinstance(addr, tuple) and len(addr) >= 2:
                return f"{addr[0]}:{addr[1]}"
            elif isinstance(addr, tuple) and len(addr) == 1:
                return str(addr[0])
            elif isinstance(addr, str):
                return addr
            else:
                return str(addr)
        except (AttributeError, IndexError, TypeError):
            # Убрал 'e' из f-строки, т.к. переменная не была определена
            return "error(invalid_address_format)"

    def compare_with_baseline(self):
        """Сравнение текущего состояния с базовой линией"""
        anomalies = []

        try:
            with open('network_baseline.json', 'r') as f:
                baseline = json.load(f)
        except FileNotFoundError:
            return [{'error': 'Baseline not found. Run with --baseline first.'}]

        # Загружаем хеши соединений из базовой линии
        baseline_hashes = set(baseline.get('connection_hashes', []))

        current_connections = self.get_network_connections()
        current_hashes = set()

        for conn in current_connections:
            # Создаем такой же отпечаток, как в baseline
            conn_fingerprint = {
                'family': str(conn.get('family', '')),
                'type': str(conn.get('conn_type', '')),
                'laddr': self._safe_format_address(conn.get('laddr')),
                'raddr': self._safe_format_address(conn.get('raddr')),
                'status': conn.get('status', ''),
                'pid': conn.get('pid', '')
            }

            conn_hash = hashlib.md5(json.dumps(conn_fingerprint, sort_keys=True).encode()).hexdigest()
            current_hashes.add(conn_hash)

            if conn_hash not in baseline_hashes:
                description = f"New connection: {conn_fingerprint['laddr']} -> {conn_fingerprint['raddr']}"
                anomalies.append({
                    'type': 'new_connection',
                    'connection': conn_fingerprint,
                    'description': description,
                    'severity': 'medium',
                    'timestamp': datetime.now().isoformat()
                })

        # Поиск исчезнувших соединений
        disappeared = baseline_hashes - current_hashes
        for disappeared_hash in disappeared:
            anomalies.append({
                'type': 'disappeared_connection',
                'connection_hash': disappeared_hash,
                'description': f"Connection from baseline is no longer active",
                'severity': 'low',
                'timestamp': datetime.now().isoformat()
            })

        return anomalies

    def continuous_monitoring(self, duration=3600):
        """Непрерывный мониторинг"""
        print(f"Starting continuous monitoring for {duration} seconds...")

        start_time = time.time()
        previous_connections = set()

        while time.time() - start_time < duration:
            current_connections = set()

            for conn in self.get_network_connections():
                laddr_str = self._safe_format_address(conn.get('laddr'))
                raddr_str = self._safe_format_address(conn.get('raddr'))
                conn_str = f"{laddr_str}:{raddr_str}:{conn.get('pid', '')}"
                current_connections.add(conn_str)

            # Поиск новых соединений
            new_connections = current_connections - previous_connections
            if new_connections:
                timestamp = datetime.now().isoformat()
                for conn_str in new_connections:
                    self.log_alert('new_connection', f'New connection detected: {conn_str}', 'medium')

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

        # Сохранение в базу данных, если она доступна
        if not self.db_path:
            logging.warning("Database is not available, alert not saved to DB.")
            print(f"[{severity.upper()}] {alert['timestamp']}: {description}")
            return

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, description, severity, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (alert['timestamp'], alert_type, description, severity, json.dumps(alert)))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logging.error(f"Failed to write alert to database: {e}")

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
            print(f"Results saved to {filename}")

        elif format == 'html':
            self.generate_html_report(results)

        return results

    def generate_html_report(self, results):
        """Генерация HTML отчета на основе результатов сканирования."""
        
        def escape_html(text):
            """Простое экранирование HTML для безопасности."""
            if not isinstance(text, str):
                text = str(text)
            return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

        # Формирование строк для таблицы соединений
        connection_rows = []
        for conn in results.get('connections', []):
            local_addr = escape_html(self._safe_format_address(conn.get('laddr')))
            remote_addr = escape_html(self._safe_format_address(conn.get('raddr')))
            process = escape_html(conn.get('name', 'Unknown'))
            status = escape_html(conn.get('status', 'Unknown'))
            connection_rows.append(f"""
                <tr>
                    <td>{local_addr}</td>
                    <td>{remote_addr}</td>
                    <td>{process}</td>
                    <td>{status}</td>
                </tr>
            """)

        # Формирование списка предупреждений
        alert_items = []
        for alert in results.get('alerts', []):
            severity = escape_html(alert.get('severity', 'low'))
            description = escape_html(alert.get("description", ""))
            alert_items.append(f'<li class="alert-{severity}">{description}</li>')

        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Network Security Scan Report</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 20px; background-color: #f9f9f9; color: #333; }}
                h1, h2 {{ color: #1a237e; }}
                .alert-high {{ color: #d32f2f; font-weight: bold; }}
                .alert-medium {{ color: #f57c00; }}
                .alert-low {{ color: #388e3c; }}
                table {{ border-collapse: collapse; width: 100%; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #3949ab; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                ul {{ list-style-type: square; }}
                .container {{ background-color: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Security Scan Report</h1>
                <p>Generated: {escape_html(results.get('timestamp'))}</p>

                <h2>Summary</h2>
                <ul>
                    <li>Total Connections: {len(results.get('connections', []))}</li>
                    <li>Suspicious Patterns (Ports): {len(results.get('suspicious_patterns', {}).get('suspicious_ports', []))}</li>
                    <li>Alerts: {len(results.get('alerts', []))}</li>
                </ul>

                <h2>Active Connections</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Local Address</th>
                            <th>Remote Address</th>
                            <th>Process</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(connection_rows)}
                    </tbody>
                </table>

                <h2>Alerts</h2>
                <ul>
                    {''.join(alert_items)}
                </ul>
            </div>
        </body>
        </html>
        """

        filename = f'network_report_{int(time.time())}.html'
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_template)
            print(f"HTML report saved to {filename}")
        except IOError as e:
            logging.error(f"Failed to save HTML report: {e}")

    def run_comprehensive_scan(self):
        """Полное сканирование системы"""
        print("Starting comprehensive network security scan...")
        print("=" * 60)

        # 1. Основной анализ соединений
        print("\n1. Analyzing active connections...")
        connections = self.get_network_connections()
        print(f"Found {len(connections)} active connections.")

        # 2. Низкоуровневый анализ
        print("\n2. Low-level analysis of /proc/net...")
        proc_connections = self.parse_proc_net()
        print(f"Found {len(proc_connections)} connections in /proc/net.")

        # 3. Поиск скрытых процессов
        print("\n3. Checking for hidden processes...")
        hidden_processes = self.check_hidden_processes()
        if hidden_processes:
            print(f"WARNING: Found {len(hidden_processes)} hidden processes with network activity!")
            for proc in hidden_processes:
                self.log_alert('hidden_process', f"Hidden process: PID {proc['pid']} - {proc['cmdline']}", 'high')
        else:
            print("No hidden processes found.")

        # 4. Анализ паттернов трафика
        print("\n4. Analyzing traffic patterns...")
        patterns = self.analyze_traffic_patterns()
        for pattern_type, items in patterns.items():
            if items:
                logging.info(f"  {pattern_type}: {len(items)} found.")
                for item in items:
                    self.log_alert('suspicious_pattern', f"{pattern_type}: {item.get('reason', '')}", 'medium')

        # 5. Проверка руткитов
        print("\n5. Checking for rootkit network hiding...")
        rootkit_check = self.check_rootkit_network_hiding()
        if rootkit_check:
            print(f"WARNING: Discrepancies found in connection data!")
            for discrepancy in rootkit_check:
                self.log_alert('rootkit_hiding', f"Network hiding detected: {discrepancy['type']}",
                               discrepancy['severity'])
        else:
            print("No signs of connection hiding found.")

        # 6. Анализ Docker контейнеров
        print("\n6. Analyzing Docker containers...")
        docker_info = self.check_docker_containers()
        if docker_info and not any('error' in item for item in docker_info):
            print(f"Found {len(docker_info)} container records.")
        else:
            logging.info("Docker containers not found or Docker is not installed/available.")

        # 7. Сканирование сетевых пространств имен
        print("\n7. Scanning network namespaces...")
        namespaces = self.scan_network_namespaces()
        if namespaces:
            print(f"Found {len(namespaces)} network namespaces.")
        else:
            print("No additional network namespaces found.")

        # 8. Глубокий анализ пакетов (если root)
        if sys.platform.startswith('linux') and os.geteuid() == 0:
            print("\n8. Deep packet inspection...")
            packet_analysis = self.deep_packet_inspection()
            if packet_analysis and not any('error' in item for item in packet_analysis):
                print(f"Analyzed {len(packet_analysis)} packets.")
        else:
            print("\n8. Deep packet inspection skipped (requires root privileges or only available on Linux).")

        print("\n" + "=" * 60)
        print("Scan complete!")

        # Экспорт результатов
        results = self.export_results()

        # Вывод сводки
        if self.alerts:
            print(f"\nWARNING: Found {len(self.alerts)} potential threats!")
            high_severity = [a for a in self.alerts if a.get('severity') == 'high']
            if high_severity:
                print(f"Critical threats: {len(high_severity)}")
        else:
            print("\nNo serious threats found.")

        return results

    def apply_connection_filters(self, connections):
        """Применение фильтров к списку соединений"""
        filtered_connections = []

        for conn in connections:
            # Фильтр по типу соединения
            if self.filters['connection_types']:
                conn_type = conn.get('type', '').lower()
                if conn_type not in [t.lower() for t in self.filters['connection_types']]:
                    continue

            # Фильтр по состоянию соединения
            if self.filters['connection_states']:
                conn_status = conn.get('status', '').upper()
                if conn_status not in [s.upper() for s in self.filters['connection_states']]:
                    continue

            # Фильтр по PID
            if self.filters['pids']:
                conn_pid = conn.get('pid')
                if conn_pid not in self.filters['pids']:
                    continue

            # Фильтр по имени процесса
            if self.filters['process_names']:
                process_name = conn.get('name', '').lower()
                if not any(name.lower() in process_name for name in self.filters['process_names']):
                    continue

            # Фильтр по портам
            local_port = conn.get('laddr', [None, None])[1] if conn.get('laddr') else None
            remote_port = conn.get('raddr', [None, None])[1] if conn.get('raddr') else None

            if self.filters['ports']:
                if local_port not in self.filters['ports'] and remote_port not in self.filters['ports']:
                    continue

            # Фильтр по диапазону портов
            if self.filters['min_port'] is not None or self.filters['max_port'] is not None:
                ports_to_check = [p for p in [local_port, remote_port] if p is not None]
                if not ports_to_check:
                    continue

                port_in_range = False
                for port in ports_to_check:
                    if (self.filters['min_port'] is None or port >= self.filters['min_port']) and \
                            (self.filters['max_port'] is None or port <= self.filters['max_port']):
                        port_in_range = True
                        break

                if not port_in_range:
                    continue

            # Фильтр локальных соединений
            if self.filters['exclude_local']:
                remote_addr = conn.get('raddr', [None, None])[0] if conn.get('raddr') else None
                if remote_addr and self._is_local_address(remote_addr):
                    continue

            # Только внешние соединения
            if self.filters['only_external']:
                remote_addr = conn.get('raddr', [None, None])[0] if conn.get('raddr') else None
                if not remote_addr or self._is_local_address(remote_addr):
                    continue

            filtered_connections.append(conn)

        return filtered_connections

    def _is_local_address(self, addr):
        """Проверка, является ли адрес локальным"""
        if not addr:
            return True

        local_ranges = [
            '127.',  # localhost
            '10.',  # Private Class A
            '172.16.',  # Private Class B (начало)
            '192.168.',  # Private Class C
            '169.254.',  # Link-local
            '::1',  # IPv6 localhost
            'fe80:',  # IPv6 link-local
        ]

        for local_range in local_ranges:
            if addr.startswith(local_range):
                return True

        # Проверка диапазона 172.16.0.0 - 172.31.255.255
        if addr.startswith('172.'):
            try:
                second_octet = int(addr.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass

        return False

    def get_filtered_connections(self):
        """Получение отфильтрованных сетевых соединений"""
        all_connections = self.get_network_connections()
        return self.apply_connection_filters(all_connections)

    def filter_by_process_pattern(self, connections, pattern):
        """Фильтрация по паттерну в имени процесса или командной строке"""
        import re
        filtered = []

        regex = re.compile(pattern, re.IGNORECASE)

        for conn in connections:
            process_name = conn.get('name', '')
            cmdline = conn.get('cmdline', '')
            exe_path = conn.get('exe', '')

            if (regex.search(process_name) or
                    regex.search(cmdline) or
                    regex.search(exe_path)):
                filtered.append(conn)

        return filtered

    def get_connections_by_pid(self, target_pid):
        """Получение всех соединений для конкретного PID"""
        connections = self.get_network_connections()
        return [conn for conn in connections if conn.get('pid') == target_pid]

    def get_connections_by_port_range(self, min_port, max_port, include_local=True):
        """Получение соединений в определенном диапазоне портов"""
        connections = self.get_network_connections()
        filtered = []

        for conn in connections:
            local_port = conn.get('laddr', [None, None])[1] if conn.get('laddr') else None
            remote_port = conn.get('raddr', [None, None])[1] if conn.get('raddr') else None

            ports_to_check = []
            if include_local and local_port:
                ports_to_check.append(local_port)
            if remote_port:
                ports_to_check.append(remote_port)

            for port in ports_to_check:
                if min_port <= port <= max_port:
                    filtered.append(conn)
                    break

        return filtered

    def get_external_connections_only(self):
        """Получение только внешних соединений (исключая локальные)"""
        connections = self.get_network_connections()
        external = []

        for conn in connections:
            remote_addr = conn.get('raddr', [None, None])[0] if conn.get('raddr') else None
            if remote_addr and not self._is_local_address(remote_addr):
                external.append(conn)

        return external

    def get_listening_ports(self, protocol=None):
        """Получение всех прослушиваемых портов"""
        connections = self.get_network_connections()
        listening = []

        for conn in connections:
            if conn.get('status') == 'LISTEN':
                if protocol is None or conn.get('type', '').lower() == protocol.lower():
                    listening.append(conn)

        return listening

    def group_connections_by_process(self, connections=None):
        """Группировка соединений по процессам"""
        if connections is None:
            connections = self.get_network_connections()

        grouped = {}

        for conn in connections:
            pid = conn.get('pid', 'Unknown')
            process_name = conn.get('name', 'Unknown')
            key = f"{process_name} (PID: {pid})"

            if key not in grouped:
                grouped[key] = {
                    'process_info': {
                        'pid': pid,
                        'name': process_name,
                        'exe': conn.get('exe', ''),
                        'cmdline': conn.get('cmdline', '')
                    },
                    'connections': []
                }

            grouped[key]['connections'].append(conn)

        return grouped

    def print_filtered_connections(self, connections, show_details=False):
        """Красивый вывод отфильтрованных соединений"""
        if not connections:
            print("No connections found with the specified filters.")
            return

        print(f"\n{'=' * 80}")
        print(f"CONNECTIONS FOUND: {len(connections)}")
        print(f"{'=' * 80}")

        # Группируем по процессам для лучшего отображения
        grouped = self.group_connections_by_process(connections)

        for process_key, process_data in grouped.items():
            print(f"\n📋 {process_key}")
            print("-" * 60)

            process_info = process_data['process_info']
            if show_details:
                print(f"   Executable: {process_info.get('exe', 'N/A')}")
                print(f"   Command Line: {process_info.get('cmdline', 'N/A')}")

            for i, conn in enumerate(process_data['connections'], 1):
                local_addr = conn.get('laddr', [None, None])
                remote_addr = conn.get('raddr', [None, None])

                local_str = f"{local_addr[0]}:{local_addr[1]}" if local_addr and local_addr[0] else "N/A"
                remote_str = f"{remote_addr[0]}:{remote_addr[1]}" if remote_addr and remote_addr[0] else "N/A"

                status = conn.get('status', 'N/A')
                conn_type = conn.get('type', 'N/A').upper()

                print(f"   {i:2d}. {conn_type:4s} {local_str:22s} -> {remote_str:22s} [{status}]")

                if show_details:
                    create_time = conn.get('create_time')
                    if create_time:
                        from datetime import datetime
                        create_dt = datetime.fromtimestamp(create_time)
                        print(f"       Created: {create_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    def run_filtered_scan(self, filters=None):
        """Запуск сканирования с применением фильтров"""
        if filters:
            self.filters.update(filters)

        print("Running scan with filters...")
        print("Active filters:")

        for filter_name, filter_value in self.filters.items():
            if filter_value:
                print(f"  - {filter_name}: {filter_value}")

        # Получаем отфильтрованные соединения
        filtered_connections = self.get_filtered_connections()

        # Применяем анализ к отфильтрованным данным
        all_connections_count = len(self.get_network_connections())
        print(f"\nTotal connections: {all_connections_count}")
        print(f"After applying filters: {len(filtered_connections)}")

        if filtered_connections:
            self.print_filtered_connections(filtered_connections, show_details=True)

            # Анализ паттернов только для отфильтрованных соединений
            patterns = self.analyze_traffic_patterns(filtered_connections)

            if any(patterns.values()):
                print(f"\n{'=' * 60}")
                print("PATTERNS DETECTED IN FILTERED DATA:")
                print(f"{'=' * 60}")

                for pattern_type, items in patterns.items():
                    if items:
                        print(f"\n{pattern_type.upper().replace('_', ' ')}:")
                        for item in items:
                            print(f"  - {item.get('reason', 'Unknown')}")

        return filtered_connections


def print_detailed_help():
    """Выводит детальную справку по использованию программы"""
    help_text = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Advanced Network Connection Monitor                       ║
║                     Comprehensive Network Connection Monitoring              ║
╚══════════════════════════════════════════════════════════════════════════════╝

DESCRIPTION:
    An advanced tool for detecting hidden and suspicious network connections 
    on Linux systems. It can detect rootkits, hidden processes, suspicious 
    connections, and anomalous network activity.

USAGE:
    python3 network_monitor.py [OPTIONS]

MAIN COMMANDS:
    --scan                  Run a full, comprehensive system scan
                           (recommended for first-time use).

    --baseline              Create a baseline of normal network activity
                           (saved to network_baseline.json).

    --compare               Compare the current state against the baseline
                           (requires a pre-existing baseline).

    --monitor SECONDS       Continuous real-time monitoring.
                           Example: --monitor 3600 (monitors for 1 hour).

EXPORT OPTIONS:
    --export FORMAT         Export format for the results.
                           json - JSON file (default).
                           html - User-friendly HTML report.

    --verbose, -v           Enable verbose output for detailed information.

USAGE EXAMPLES:

    1. Quick Scan (default, no parameters):
       python3 network_monitor.py

    2. Full Comprehensive Scan:
       sudo python3 network_monitor.py --scan --export html

    3. Create a Baseline:
       python3 network_monitor.py --baseline

    4. Check for Anomalies:
       python3 network_monitor.py --compare --verbose

    5. Real-time Monitoring:
       python3 network_monitor.py --monitor 1800

    6. Full Analysis with HTML Export:
       sudo python3 network_monitor.py --scan --export html --verbose

DETECTION CAPABILITIES:

    ✓ Hidden processes with network activity
    ✓ Suspicious ports and connections
    ✓ Connection hiding by rootkits
    ✓ Anomalous traffic patterns
    ✓ High-frequency connections
    ✓ Tunneling and encryption
    ✓ Docker containers
    ✓ Network namespaces
    ✓ Deep packet inspection (root)

SUSPICIOUS INDICATORS:

    • Ports: 6667-6669, 6697, 7000, 31337, 12345, 54321, 1337
    • IP Addresses: Known Tor nodes, C&C servers
    • Processes: Unusual network utilities
    • Behavior: Hiding from standard utilities

REQUIREMENTS:

    Python 3.6+
    Modules: psutil

    Install dependencies:
    pip3 install psutil

    Root privileges are required for full functionality:
    sudo python3 network_monitor.py --scan

RESULT FILES:

    network_baseline.json       - Baseline activity data
    network_scan_[timestamp].json - Scan results
    network_report_[timestamp].html - HTML report
    network_monitor.db          - Database for results and alerts

THREAT SEVERITY LEVELS:

    HIGH    - Critical threats (hidden processes, rootkits)
    MEDIUM  - Suspicious activity (new connections, unusual ports)  
    LOW     - Anomalies (changes from baseline)

NOTES:

    • Some features require root privileges.
    • The first run is recommended with --scan.
    • For regular monitoring, use --baseline and --compare.
    • HTML reports are convenient for documenting results.

AUTHOR: Advanced Network Security Tools
VERSION: 2.1
    """
    print(help_text)


def print_usage_examples():
    """Выводит примеры использования"""
    examples = """
NETWORK MONITOR USAGE EXAMPLES:

1. Basic Scan:
   python3 network_monitor.py

2. Full Security Scan:
   sudo python3 network_monitor.py --scan

3. Create a Baseline and Monitor:
   python3 network_monitor.py --baseline
   # ... some time later ...
   python3 network_monitor.py --compare

4. Continuous Monitoring for 2 Hours:
   python3 network_monitor.py --monitor 7200

5. Detailed Analysis with HTML Report:
   sudo python3 network_monitor.py --scan --export html --verbose

6. Quick Check for Changes:
   python3 network_monitor.py --compare --verbose

USAGE SCENARIOS:

Incident Response:
    1. sudo python3 network_monitor.py --scan --export html
    2. Analyze the HTML report for anomalies.
    3. python3 network_monitor.py --monitor 600 (watch for 10 mins)

Regular Monitoring:
    1. python3 network_monitor.py --baseline (weekly)
    2. python3 network_monitor.py --compare (daily)
    3. Automate with cron.

Security Audit:
    1. sudo python3 network_monitor.py --scan --export html
    2. Document the results.
    3. Compare with previous audits.
    """
    print(examples)


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Connection Monitor - Comprehensive network connection monitoring',
        epilog='For detailed help, use: python3 network_monitor.py --detailed-help',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--detailed-help', action='store_true',
                        help='Show detailed help with usage examples')

    parser.add_argument('--examples', action='store_true',
                        help='Show usage examples')

    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Run in interactive mode')

    parser.add_argument('--baseline', action='store_true',
                        help='Create a baseline of normal network activity')

    parser.add_argument('--compare', action='store_true',
                        help='Compare current state with the baseline')

    parser.add_argument('--monitor', type=int, metavar='SECONDS',
                        help='Continuous monitoring for a specified number of seconds')

    parser.add_argument('--scan', action='store_true',
                        help='Run a full comprehensive security scan')

    parser.add_argument('--export', choices=['json', 'html'], default='json',
                        help='Export format for results: json or html (default: json)')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output for detailed scan information')

    add_filter_arguments(parser)
    args = parser.parse_args()

    if sys.platform.startswith('linux'):
        if os.geteuid() != 0:
            print("WARNING: Script running without root privileges.")
            print("Some features, like deep packet inspection, will be unavailable.")
            print("For a full analysis, run with: sudo python3 network_monitor.py")
            print()

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

    if handle_filter_arguments(args, monitor):
        return

    # Остальная логика остается без изменений
    if args.baseline:
        monitor.generate_baseline()
    elif args.compare:
        anomalies = monitor.compare_with_baseline()
        if anomalies:
            print("Anomalies found:")
            for anomaly in anomalies:
                if args.verbose:
                    print(f"  Details: {anomaly}")
                else:
                    print(f"  {anomaly.get('type', 'Unknown')}: {anomaly.get('description', 'No description')}")
        else:
            print("No anomalies found.")
    elif args.monitor:
        print(f"Starting monitoring for {args.monitor} seconds...")
        if args.verbose:
            print("Verbose mode enabled.")
        monitor.continuous_monitoring(args.monitor)
    elif args.scan:
        if args.verbose:
            print("Running full scan in verbose mode...")
        monitor.run_comprehensive_scan()
    else:
        # По умолчанию запускаем быстрое сканирование
        print("Running a quick network scan...")
        if args.verbose:
            print("For a full scan, use: --scan")
            print("To create a baseline, use: --baseline")
            print("For help, use: --help or --detailed-help")

        connections = monitor.get_network_connections()
        patterns = monitor.analyze_traffic_patterns(connections)
        print(f"Active connections: {len(connections)}")

        if args.verbose:
            print(f"Analyzed pattern types: {list(patterns.keys())}")

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
                    print(f"  ... and {len(items) - 5} more items (use --verbose for details)")

        if not suspicious_found:
            print("No suspicious activity detected.")
            if args.verbose:
                print("This is a good sign! The system appears clean.")

        if args.export:
            print(f"Exporting results to {args.export} format...")
            monitor.export_results(args.export)


def add_filter_arguments(parser):
    """Добавление аргументов фильтрации в парсер"""
    filter_group = parser.add_argument_group('Connection Filters')

    filter_group.add_argument('--filter-type', nargs='+',
                              choices=['tcp', 'udp', 'tcp6', 'udp6'],
                              help='Filter by connection type')

    filter_group.add_argument('--filter-state', nargs='+',
                              choices=['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT'],
                              help='Filter by connection state')

    filter_group.add_argument('--filter-pid', nargs='+', type=int,
                              help='Filter by process ID (PID)')

    filter_group.add_argument('--filter-process', nargs='+',
                              help='Filter by process name (supports partial matching)')

    filter_group.add_argument('--filter-port', nargs='+', type=int,
                              help='Filter by specific port numbers')

    filter_group.add_argument('--filter-port-range', nargs=2, type=int, metavar=('MIN', 'MAX'),
                              help='Filter by a range of port numbers')

    filter_group.add_argument('--exclude-local', action='store_true',
                              help='Exclude local connections (e.g., to 127.0.0.1)')

    filter_group.add_argument('--only-external', action='store_true',
                              help='Show only external connections')

    filter_group.add_argument('--listening-only', action='store_true',
                              help='Show only listening ports')

    filter_group.add_argument('--process-pattern',
                              help='Filter by a regex pattern in the process name/cmdline')


def handle_filter_arguments(args, monitor):
    """Обработка аргументов фильтрации"""
    filters = {}

    if hasattr(args, 'filter_type') and args.filter_type:
        filters['connection_types'] = args.filter_type

    if hasattr(args, 'filter_state') and args.filter_state:
        filters['connection_states'] = args.filter_state

    if hasattr(args, 'filter_pid') and args.filter_pid:
        filters['pids'] = args.filter_pid

    if hasattr(args, 'filter_process') and args.filter_process:
        filters['process_names'] = args.filter_process

    if hasattr(args, 'filter_port') and args.filter_port:
        filters['ports'] = args.filter_port

    if hasattr(args, 'filter_port_range') and args.filter_port_range:
        filters['min_port'] = args.filter_port_range[0]
        filters['max_port'] = args.filter_port_range[1]

    if hasattr(args, 'exclude_local') and args.exclude_local:
        filters['exclude_local'] = True

    if hasattr(args, 'only_external') and args.only_external:
        filters['only_external'] = True

    # Применяем фильтры
    monitor.filters.update(filters)

    # Специальные случаи
    if hasattr(args, 'listening_only') and args.listening_only:
        connections = monitor.get_listening_ports()
        monitor.print_filtered_connections(connections, show_details=args.verbose)
        return True

    if hasattr(args, 'process_pattern') and args.process_pattern:
        connections = monitor.get_network_connections()
        filtered = monitor.filter_by_process_pattern(connections, args.process_pattern)
        monitor.print_filtered_connections(filtered, show_details=args.verbose)
        return True

    # Если есть любые фильтры, кроме специальных, запускаем фильтрованное сканирование
    if any(filters.values()):
        monitor.run_filtered_scan()
        return True

    return False


def print_filter_examples():
    """Примеры использования фильтров"""
    examples = """
FILTER USAGE EXAMPLES:

1. Show only TCP connections:
   python3 network_monitor.py --filter-type tcp

2. Show only established connections:
   python3 network_monitor.py --filter-state ESTABLISHED

3. Show connections for a specific process ID:
   python3 network_monitor.py --filter-pid 1234

4. Show connections for processes by name:
   python3 network_monitor.py --filter-process firefox chrome

5. Show connections on specific ports:
   python3 network_monitor.py --filter-port 80 443 8080

6. Show connections in a port range:
   python3 network_monitor.py --filter-port-range 8000 9000

7. Show only external connections:
   python3 network_monitor.py --only-external

8. Show only listening ports:
   python3 network_monitor.py --listening-only

9. Find processes by a regex pattern:
   python3 network_monitor.py --process-pattern "python.*server"

10. Combined filters:
    python3 network_monitor.py --filter-type tcp --filter-state ESTABLISHED --only-external

11. Filter with verbose output:
    python3 network_monitor.py --filter-process ssh --verbose

12. Analyze suspicious port ranges:
    python3 network_monitor.py --filter-port-range 1337 31337 --verbose

SPECIAL SCENARIOS:

Monitor web traffic:
    python3 network_monitor.py --filter-port 80 443 8080 8443

Find SSH connections:
    python3 network_monitor.py --filter-port 22 --filter-type tcp

Analyze a process by PID:
    python3 network_monitor.py --filter-pid $(pgrep firefox)

Find suspicious connections:
    python3 network_monitor.py --only-external --filter-port-range 1024 65535 --process-pattern "python|nc|telnet"
    """
    print(examples)


def interactive_help():
    """Интерактивная справка с выбором режима."""
    print("\n" + "=" * 60)
    print("             INTERACTIVE HELP")
    print("=" * 60)

    options = {
        '1': ('Quick Scan', ['--scan']), # Изменено на --scan для большей пользы
        '2': ('Full Security Scan', ['--scan', '--verbose']),
        '3': ('Create Baseline', ['--baseline']),
        '4': ('Check for Anomalies', ['--compare']),
        '5': ('Monitor for 10 Minutes', ['--monitor', '600']),
        '6': ('Export to HTML', ['--scan', '--export', 'html']),
        '0': ('Exit', None)
    }

    while True:
        print("\nSelect an operating mode:")
        for key, (desc, _) in options.items():
            print(f"  {key}. {desc}")

        choice = input("\nYour choice (0-6): ").strip()

        if choice == '0':
            break
        elif choice in options:
            desc, args = options[choice]
            if args is None: # Exit case
                break

            # Формируем команду для выполнения
            command = [sys.executable, __file__] + args
            
            print(f"\nSelected mode: {desc}")
            print(f"Command: {' '.join(command)}")

            if sys.platform.startswith('linux') and os.geteuid() != 0 and choice in ['2', '6']:
                print("⚠️ This operation may require superuser privileges (sudo).")
                # Note: We won't automatically add sudo here for security reasons,
                # but we inform the user.

            try:
                confirm = input("Run? (y/n): ").strip().lower()
                if confirm in ['y', 'yes']:
                    print(f"Executing: {' '.join(command)}...")
                    # Используем subprocess.run для безопасного запуска
                    subprocess.run(command)
                else:
                    print("Cancelled.")
                break 
            except KeyboardInterrupt:
                print("\nOperation interrupted.")
                break
            except Exception as e:
                logging.error(f"Error running command in interactive mode: {e}")
                break
        else:
            print("Invalid choice. Please try again.")


def show_banner():
    """Показывает баннер программы"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║              Advanced Network Connection Monitor             ║
    ║                     v2.1 Security Edition                    ║
    ║                                                              ║
    ║  Detection of hidden connections, rootkits and threats       ║
    ║  (Обнаружение скрытых соединений, руткитов и угроз)           ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


if __name__ == "__main__":
    try:
        # Переносим проверку прав внутрь main, чтобы скрипт мог быть импортирован на других ОС
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        # Улучшаем вывод ошибок
        logging.error(f"A critical error occurred: {e}", exc_info=True)
        print(f"\nExecution error: {e}")
        sys.exit(1)
