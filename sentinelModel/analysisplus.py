import os
import glob
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# --- CONFIGURATION ---
LOG_DIRECTORY = 'exports/cowrie'  # Dossier surveillé avec les exports Logstash
OUTPUT_DIR = 'reports'
# --- END CONFIGURATION ---

@dataclass
class AttackPattern:
    """Classe pour stocker les patterns d'attaque détectés"""
    recon: int = 0
    download: int = 0
    destructive: int = 0
    persistence: int = 0
    privilege_escalation: int = 0
    lateral_movement: int = 0
    data_exfiltration: int = 0
    network_scanning: int = 0
    exploitation: int = 0
    credential_access: int = 0
    defense_evasion: int = 0
    backdoor_installation: int = 0
    cryptomining: int = 0
    botnet_activity: int = 0
    web_shell: int = 0
    
    def total_score(self) -> int:
        return sum([
            self.recon, self.download, self.destructive, 
            self.persistence, self.privilege_escalation, self.lateral_movement,
            self.data_exfiltration, self.network_scanning, self.exploitation,
            self.credential_access, self.defense_evasion, self.backdoor_installation,
            self.cryptomining, self.botnet_activity, self.web_shell
        ])
    
    def get_active_categories(self) -> List[str]:
        """Retourne les catégories actives"""
        categories = []
        for field_name in self.__dataclass_fields__:
            if getattr(self, field_name) > 0:
                categories.append(field_name.replace('_', ' ').title())
        return categories

# --- KEYWORDS ---
KEYWORDS = {
    'recon': {
        'whoami', 'uname', 'ls', 'pwd', 'ifconfig', 'ip a', 'ip addr', 'ip route',
        'netstat', 'ps', 'top', 'cat /etc/passwd', 'cat /etc/shadow', 'cat /etc/hosts',
        'id', 'groups', 'w', 'who', 'last', 'env', 'printenv', 'set',
        'df', 'mount', 'lsblk', 'hostname', 'uptime', 'free', 'vmstat',
        'arp', 'route', 'ss', 'lsof', 'netstat -a', 'netstat -tulpn', 'ss -tulpn',
        'cat /proc/version', 'cat /proc/cpuinfo', 'cat /etc/issue', 
        'cat /etc/*release', 'lsb_release', 'hostnamectl',
        'getent passwd', 'getent group', 'cat /etc/group',
        'find /', 'find /home', 'find /var', 'locate', 'which', 'whereis',
        'cat /var/log', 'dmesg', 'journalctl', 'lastlog'
    },
    'download': {
        'wget', 'curl', 'tftp', 'ftpget', 'fetch', 'lynx -dump',
        'nc -l', 'ncat', 'socat', 'netcat',
        'scp', 'rsync', 'ftp', 'sftp',
        'python -c', 'perl -e', 'php -r',
        'urllib', 'requests.get', 'file_get_contents',
        'base64 -d', 'echo -n',
        'git clone', 'svn checkout', 'wget http', 'curl http'
    },
    'destructive': {
        'rm -rf', 'rm -rf /', 'rm -rf /*', 'rm -r',
        'mkfs', 'mkfs.ext', 'dd if=/dev/zero', 'dd if=/dev/random',
        ':(){', 'fork bomb', ':(){ :|:& };:',
        'shred', '> /dev/sda', '> /dev/hda', 
        'fdisk', 'parted', 'gdisk',
        'shutdown', 'reboot', 'halt', 'poweroff', 'init 0',
        '> /var/log', 'rm /var/log', 'echo > /var/log',
        'echo c > /proc/sysrq-trigger'
    },
    'persistence': {
        'crontab', 'crontab -e', '* * * * *', '/etc/cron',
        'echo "* * * * *', '/var/spool/cron',
        'systemctl enable', 'systemctl start', '/etc/init.d', 
        'rc.local', 'service ', 'chkconfig',
        '.bashrc', '.bash_profile', '.profile', '.bash_login',
        '.zshrc', '/etc/profile', '/etc/bash.bashrc',
        'authorized_keys', '.ssh/authorized_keys', 'ssh-keygen',
        'at ', '@reboot', '/etc/rc.local',
        'systemd', '/etc/systemd/system', '.service'
    },
    'privilege_escalation': {
        'sudo', 'sudo -i', 'sudo su', 'su -', 'su root',
        'passwd', 'passwd root', 'echo root:',
        'chmod +s', 'chmod 4755', 'chmod u+s', 'find / -perm -4000',
        'visudo', '/etc/sudoers', 'echo "ALL=(ALL) NOPASSWD',
        'pkexec', 'polkit', 'CVE-', 'exploit',
        'dirty', 'overlayfs', 'mempodipper'
    },
    'lateral_movement': {
        'ssh ', 'ssh -i', 'ssh root@', 'ssh user@',
        'scp ', 'rsync', 'rsync -avz',
        'rcp', 'rsh', 'rlogin', 'telnet',
        'nc ', 'netcat', '/bin/bash -i', 'bash -i',
        'bash -c', '/dev/tcp/', 'mkfifo', 'mknod',
        'xfreerdp', 'rdesktop'
    },
    'network_scanning': {
        'nmap', 'nmap -sS', 'nmap -sV', 'nmap -sT', 'nmap -p', 'masscan', 'zmap',
        'ping -c', 'fping', 'hping', 'hping3',
        'nc -zv', 'netcat -zv', 'telnet', 'for port in', 'while read port',
        'curl -I', 'wget --spider', 'echo "" |', 'timeout 1',
        'dig', 'nslookup', 'host', 'dnsenum', 'fierce', 'dnsrecon',
        'arp-scan', 'arping', 'arp -a'
    },
    'exploitation': {
        'msfvenom', 'meterpreter', 'metasploit', 'msfconsole',
        '/bin/sh', '/bin/bash', 'sh -i', 'bash -i', '/bin/dash',
        'python -c "import', 'python3 -c', 'pty.spawn', 'socket.socket',
        'perl -e', 'perl -MIO', 'use Socket',
        'php -r', 'system(', 'exec(', 'passthru(', 'shell_exec(',
        'ruby -rsocket', 'ruby -e',
        'shellshock', 'heartbleed', 'struts', 'log4j', 'log4shell',
        'CVE-', 'exploit', 'poc', 'proof of concept',
        '\\x90', 'AAAA', 'shellcode', 'payload', 'ropchain'
    },
    'credential_access': {
        'cat /etc/shadow', 'cat /etc/passwd', 'cat ~/.ssh', 'cat id_rsa',
        'cat ~/.bash_history', 'cat ~/.zsh_history', 'history', 'cat ~/.profile',
        'cat ~/.aws', 'cat ~/.docker', 'cat ~/.kube', 'cat config.json',
        'cat .git/config', 'git config --list', 'cat .gitconfig',
        'grep -i pass', 'grep -i pwd', 'grep password', 'grep -r password',
        'find / -name "*pass*"', 'find / -name "*.key"',
        'cat id_rsa', 'cat id_dsa', 'cat id_ecdsa', 'cat id_ed25519',
        'cat cookies', 'cat Login Data', 'cat Cookies.sqlite',
        'john', 'hashcat', 'hydra', 'medusa', 'ncrack'
    },
    'defense_evasion': {
        'rm /var/log', 'echo > /var/log', '> .bash_history', 'cat /dev/null >',
        'history -c', 'unset HISTFILE', 'export HISTFILE=/dev/null',
        'touch -r', 'touch -t', 'touch -d',
        'unlink /proc', 'mount -o bind', 'mount --bind',
        'ld.so.preload', 'LD_PRELOAD', '/etc/ld.so.preload',
        'openssl enc', 'gpg -c', 'gpg --encrypt',
        'tar czf', 'zip -P', '7z a -p',
        'base64', 'xxd', 'hexdump', 'uuencode', 'od',
        '\\x', '$((', '${', 'eval',
        'shred -n', 'wipe', 'srm', 'dd if=/dev/urandom',
        'rm -rf /tmp/*', 'rm -rf /var/tmp/*', 'pkill'
    },
    'backdoor_installation': {
        'nc -lvp', 'ncat -lvp', 'socat TCP-LISTEN', 'socat -',
        'nc -lp', 'bash -i >& /dev/tcp', 'sh -i >& /dev/tcp',
        'mkfifo', 'mknod', 'nc -l < /tmp/f',
        'echo "<?php', '<?php system', '<?php eval', 'eval(base64_decode(',
        'python -m SimpleHTTPServer', 'python3 -m http.server',
        'flask run', 'uvicorn',
        'systemctl daemon-reload', '/etc/systemd/system',
        '* * * * *', 'crontab -e', '@reboot', '@hourly',
        '/etc/init.d/', 'update-rc.d', 'chkconfig --add'
    },
    'cryptomining': {
        'xmrig', 'minerd', 'cpuminer', 'ccminer', 'ethminer',
        'xmr-stak', 'xmr-stack', 'claymore', 'phoenixminer', 'nanominer',
        't-rex', 'gminer', 'lolminer', 'nbminer',
        'stratum+tcp', 'stratum+ssl', 'stratum://', 'pool.', 'mining',
        'supportxmr', 'nanopool', 'f2pool', 'antpool',
        'wallet', 'monero', 'xmr', 'btc', 'eth', 'ethereum',
        '--donate-level', '--url', '--user', '--pass', '--algo',
        'pool=', 'wallet=', 'algo=', 'coin=',
        'nice -n -20', 'taskset', 'cpulimit', 'threads=',
        'coinhive', 'cryptonight', 'randomx', 'kawpow'
    },
    'botnet_activity': {
        'busybox', 'ECCHI', 'MIRAI', '/bin/busybox', 'DVR',
        'gafgyt', 'bashlite', 'HIHI', 'LOLOL', 'qbot',
        'flood', 'udpflood', 'synflood', 'syn flood', 'attack', 'ddos',
        'method=', 'target=', 'time=', 'threads=',
        'PRIVMSG', 'NICK', 'JOIN #', 'irc.', 'TOPIC', 'MODE',
        'beacon', 'checkin', 'heartbeat', 'callback', 'phone home',
        'range', 'scan', 'target', 'list', 'default login',
        '.scan', '.attack', '.kill', '.load', '.stop'
    },
    'web_shell': {
        'c99.php', 'r57.php', 'wso.php', 'shell.php', 'b374k',
        'c99shell', 'r57shell', 'webshell', 'phpshell',
        'antichat', 'cybershell', 'caidao',
        'system(', 'exec(', 'passthru(', 'shell_exec(', 'popen(',
        'proc_open(', 'pcntl_exec(',
        'eval($_', '$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
        '$_SERVER', 'assert($_',
        '.asp', '.aspx', 'Response.Write', 'Request.Form',
        '.jsp', 'Runtime.getRuntime', 'ProcessBuilder',
        'flask', 'django', 'bottle', '@app.route'
    },
    'data_exfiltration': {
        'tar czf', 'tar -czf', 'zip -r', '7z a', 'gzip', 'bzip2',
        'curl -F', 'curl --upload-file', 'wget --post-file', 'wget --post-data',
        'nc ', 'netcat', 'scp ', 'rsync', 'rcp',
        'aws s3', 'gsutil', 'rclone', 's3cmd', 'aws s3 cp',
        'ftp -n', 'put ', 'mput', 'ncftp',
        'curl -X POST', 'curl --data', 'wget --post',
        'nslookup', 'dig @', 'host ',
        'mail -s', 'sendmail', 'mailx', 'mutt',
        'pastebin', 'hastebin', 'ix.io', 'termbin',
        'ssh -D', 'ssh -L', 'ssh -R', 'ngrok'
    }
}
# Patterns de malware connus
MALWARE_PATTERNS = {
    'mirai': ['busybox', 'ECCHI', 'MIRAI', '/bin/busybox', 'DVR', 'default login'],
    'gafgyt': ['gafgyt', 'bashlite', 'HIHI', 'LOLOL', 'qbot', 'torlus'],
    'xorddos': ['xorddos', 'lolxx', 'bb2', 'Bill Gates'],
    'tsunami': ['kaiten', 'tsunami', 'knight', 'rider'],
    'coinminer': ['xmrig', 'minerd', 'cpuminer', 'stratum+tcp', 'xmr-stak', 'mining', 'cryptonight'],
    'webshell': ['c99.php', 'r57.php', 'wso.php', 'shell.php', 'b374k', 'webshell', 'eval($_'],
    'ransomware': ['encrypt', '.locked', '.encrypted', 'ransom', 'bitcoin', 'decrypt', 'crypto'],
    'rootkit': ['ld.so.preload', 'knark', 'adore-ng', 'kernel module', 'LKM', '/dev/kmem'],
    'worm': ['replicat', 'propag', 'self-copy', 'auto-spread', 'mass scan'],
    'trojan': ['backdoor', 'reverse_shell', 'remote_access', 'RAT'],
    'meterpreter': ['meterpreter', 'msfvenom', 'metasploit', 'staged', 'reverse_tcp'],
    'emotet': ['emotet', 'powershell', 'iex', 'downloadstring'],
    'wannacry': ['wannacry', 'wcry', 'wana decrypt', '@wanadecrypt'],
    'conficker': ['conficker', 'downadup', 'kido'],
    'zeus': ['zeus', 'zbot', 'banker', 'credential'],
    'dark_iot': ['dark iot', 'dvr', 'rtsp', 'onvif']
}

# Techniques MITRE ATT&CK mapping
MITRE_TECHNIQUES = {
    'T1595': 'Active Scanning',  # network_scanning
    'T1018': 'Remote System Discovery',  # lateral_movement
    'T1082': 'System Information Discovery',  # recon
    'T1059': 'Command and Scripting Interpreter',  # exploitation
    'T1105': 'Ingress Tool Transfer',  # download
    'T1543': 'Create or Modify System Process',  # persistence
    'T1548': 'Abuse Elevation Control Mechanism',  # privilege_escalation
    'T1070': 'Indicator Removal on Host',  # defense_evasion
    'T1552': 'Unsecured Credentials',  # credential_access
    'T1567': 'Exfiltration Over Web Service',  # data_exfiltration
    'T1071': 'Application Layer Protocol',  # backdoor_installation
    'T1496': 'Resource Hijacking',  # cryptomining
    'T1489': 'Service Stop',  # destructive
    'T1505': 'Server Software Component',  # web_shell
    'T1583': 'Acquire Infrastructure'  # botnet_activity
   
}

# Ports suspects couramment utilisés
SUSPICIOUS_PORTS = {
    '1337', '31337', '4444', '5555', '6666', '7777', '8080', '8888', '9999',
    '12345', '54321', '65535', '3333', '6667', '6668', '6669', '1234', '8443',
    '3389', '5900', '5901', '23', '21', '69', '445', '139'
}

# Chemins suspects
SUSPICIOUS_PATHS = {
    '/tmp/', '/dev/shm/', '/var/tmp/', '/var/run/',
    '/dev/tcp/', '/dev/udp/', '/proc/self/', '/.ssh/',
    '/root/.ssh/', '/home/', '/.config/', '/.local/'
}
class CowrieLogAnalyzer:
    """Analyseur principal pour les logs Cowrie"""
    
    def __init__(self, log_directory: str = LOG_DIRECTORY, output_dir: str = OUTPUT_DIR):
        self.log_directory = Path(log_directory)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.events = []
        self.sessions_df = None
        
    def read_log_files(self) -> List[Dict[str, Any]]:
        """Lit tous les fichiers de log Cowrie (tous formats possibles)"""
        # Rechercher tous les fichiers JSON dans le dossier
        all_json_files = glob.glob(str(self.log_directory / '*.json*'))
        
        # Filtrer pour ne garder que les fichiers Cowrie (tous les formats)
        log_files = []
        for file_path in all_json_files:
            filename = os.path.basename(file_path)
            # Accepter tous les fichiers qui commencent par "cowrie" ou contiennent "cowrie"
            if filename.startswith('cowrie') or 'cowrie' in filename.lower():
                log_files.append(file_path)
        
        # Fonction de tri personnalisée pour gérer les dates dans les noms de fichiers
        def sort_key(filepath):
            filename = os.path.basename(filepath)
            # Extraire la date du format cowrie.json.YYYY-MM-DD
            date_match = re.search(r'\.(\d{4}-\d{2}-\d{2})$', filename)
            if date_match:
                # Retourner la date pour tri chronologique (plus ancien d'abord)
                return (0, date_match.group(1))
            # Fichiers sans date (cowrie.json, cowrie_1.json, etc.) en dernier
            return (1, os.path.getmtime(filepath))
        
        # Trier par date (fichiers datés d'abord par ordre chronologique, puis autres par date de modification)
        log_files = sorted(log_files, key=sort_key)
        
        if not log_files:
            print(f"[ERROR] Aucun fichier de log trouvé dans: {self.log_directory}")
            print(f"[INFO] Formats recherchés: cowrie*.json, cowrie.json.*, cowrie_*.json, etc.")
            print(f"[INFO] Le script recherche tous les fichiers JSON contenant 'cowrie' dans leur nom")
            return []

        print(f"[INFO] {len(log_files)} fichier(s) de log trouvé(s)")
        
        # Classifier les fichiers par type pour statistiques
        files_by_pattern = {
            'cowrie.json': [],           # Fichier principal
            'cowrie_N.json': [],         # cowrie_1.json, cowrie_2.json, etc.
            'cowrieN.json': [],          # cowrie1.json, cowrie2.json, etc.
            'cowrie.json.YYYY-MM-DD': [],      # cowrie.json.2024-10-23
            'autres': []
        }
        
        # Classifier
        for file_path in log_files:
            filename = os.path.basename(file_path)
            
            if filename == 'cowrie.json':
                files_by_pattern['cowrie.json'].append(file_path)
            elif re.match(r'^cowrie_\d+\.json$', filename):  # cowrie_1.json, cowrie_2.json
                files_by_pattern['cowrie_N.json'].append(file_path)
            elif re.match(r'^cowrie\d+\.json$', filename):   # cowrie1.json, cowrie2.json
                files_by_pattern['cowrieN.json'].append(file_path)
            elif re.match(r'^cowrie\.json\.\d{4}-\d{2}-\d{2}$', filename):  # cowrie.json.2024-10-23
                files_by_pattern['cowrie.json.YYYY-MM-DD'].append(file_path)
            else:
                files_by_pattern['autres'].append(file_path)
        
        # Afficher les statistiques par pattern
        print(f"[INFO] Formats détectés:")
        for pattern, files in files_by_pattern.items():
            if files:
                print(f"   - {pattern}: {len(files)} fichier(s)")
        
        print()
        
        all_events = []
        
        for file_path in log_files:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            file_size_mb = file_size / (1024 * 1024)
            
            print(f"   Lecture: {filename} ({file_size_mb:.2f} MB)")
            
            try:
                events_in_file = 0
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        try:
                            event = json.loads(line)
                            all_events.append(event)
                            events_in_file += 1
                        except json.JSONDecodeError:
                            print(f"      [WARNING] Ligne {line_num} corrompue, ignorée")
                
                print(f"      [SUCCESS] {events_in_file} événements chargés")
                
            except Exception as e:
                print(f"      [ERROR] Erreur lecture fichier {file_path}: {e}")
        
        print(f"\n[SUCCESS] {len(all_events)} événements totaux chargés depuis {len(log_files)} fichier(s)\n")
        self.events = all_events
        return all_events

    def extract_credentials(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extrait les tentatives de connexion avec identifiants"""
        login_attempts = df[df['eventid'] == 'cowrie.login.success'].copy()
        
        if not login_attempts.empty:
            creds_summary = login_attempts.groupby(['username', 'password']).agg(
                attempts=('username', 'count'),
                source_ips=('src_ip', lambda x: list(set(x)))
            ).reset_index().sort_values('attempts', ascending=False)
            
            return creds_summary
        return pd.DataFrame()

    def detect_malware_family(self, commands: List[str]) -> str:
        """Détecte la famille de malware basée sur les commandes"""
        command_text = ' '.join(commands).lower()
        detected = []
        
        for malware, patterns in MALWARE_PATTERNS.items():
            if any(pattern.lower() in command_text for pattern in patterns):
                detected.append(malware.upper())
        
        return ', '.join(detected) if detected else "Unknown"
    
    def detect_mitre_techniques(self, patterns: AttackPattern) -> List[str]:
        """Identifie les techniques MITRE ATT&CK utilisées"""
        techniques = []
        
        if patterns.network_scanning > 0:
            techniques.append("T1595 - Active Scanning")
        if patterns.recon > 0:
            techniques.append("T1082 - System Information Discovery")
        if patterns.download > 0:
            techniques.append("T1105 - Ingress Tool Transfer")
        if patterns.persistence > 0:
            techniques.append("T1543 - Create/Modify System Process")
        if patterns.privilege_escalation > 0:
            techniques.append("T1548 - Abuse Elevation Control")
        if patterns.defense_evasion > 0:
            techniques.append("T1070 - Indicator Removal")
        if patterns.credential_access > 0:
            techniques.append("T1552 - Unsecured Credentials")
        if patterns.data_exfiltration > 0:
            techniques.append("T1567 - Exfiltration Over Web Service")
        if patterns.backdoor_installation > 0:
            techniques.append("T1071 - Application Layer Protocol")
        if patterns.cryptomining > 0:
            techniques.append("T1496 - Resource Hijacking")
        if patterns.destructive > 0:
            techniques.append("T1489 - Service Stop")
        if patterns.web_shell > 0:
            techniques.append("T1505 - Server Software Component")
        if patterns.botnet_activity > 0:
            techniques.append("T1583 - Acquire Infrastructure")
        if patterns.lateral_movement > 0:
            techniques.append("T1018 - Remote System Discovery")
        if patterns.exploitation > 0:
            techniques.append("T1059 - Command Scripting Interpreter")
            
        return techniques
    
    def detect_suspicious_patterns(self, commands: List[str]) -> Dict[str, List[str]]:
        """Détecte des patterns suspects spécifiques"""
        suspicious = {
            'ports': [],
            'paths': [],
            'encoding': [],
            'obfuscation': []
        }
        
        for command in commands:
            # Ports suspects
            for port in SUSPICIOUS_PORTS:
                if port in command:
                    suspicious['ports'].append(port)
            
            # Chemins suspects
            for path in SUSPICIOUS_PATHS:
                if path in command:
                    suspicious['paths'].append(path)
            
            # Encodage/obfuscation
            if any(pattern in command for pattern in ['base64', 'xxd', 'hexdump', 'uuencode']):
                suspicious['encoding'].append(command[:50])
            
            # Techniques d'obfuscation
            if re.search(r'\\x[0-9a-f]{2}', command) or '$((' in command or '$[' in command:
                suspicious['obfuscation'].append(command[:50])
        
        # Dédupliquer
        for key in suspicious:
            suspicious[key] = list(set(suspicious[key]))[:5]  # Limiter à 5
        
        return suspicious

    def extract_iocs(self, commands: List[str]) -> Dict[str, List[str]]:
        """Extrait les indicateurs de compromission (IOCs)"""
        iocs = {
            'urls': [],
            'ips': [],
            'domains': [],
            'file_paths': [],
            'emails': [],
            'hashes': []
        }
        
        for command in commands:
            # URLs (HTTP/HTTPS/FTP)
            urls = re.findall(
                r'(?:http[s]?|ftp)://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                command
            )
            iocs['urls'].extend(urls)
            
            # Adresses IP (exclure localhost et réseaux privés)
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', command)
            for ip in ips:
                # Filtrer localhost et IPs privées
                if not any(ip.startswith(prefix) for prefix in 
                          ['127.', '0.0.0.0', '192.168.', '10.', '172.16.', '172.17.', 
                           '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', 
                           '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                           '172.28.', '172.29.', '172.30.', '172.31.']):
                    iocs['ips'].append(ip)
            
            # Noms de domaine
            domains = re.findall(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                command
            )
            iocs['domains'].extend(domains)
            
            # Emails
            emails = re.findall(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                command
            )
            iocs['emails'].extend(emails)
            
            # Hashes (MD5, SHA1, SHA256)
            hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', command)
            iocs['hashes'].extend(hashes)
            
            # Chemins de fichiers suspects
            file_paths = re.findall(
                r'/(?:tmp|dev|var|home|root|opt|usr/local)/[^\s;|&<>]+',
                command
            )
            iocs['file_paths'].extend(file_paths)
        
        # Dédupliquer et limiter
        for key in iocs:
            iocs[key] = list(set(iocs[key]))[:10]  # Maximum 10 par catégorie
        
        return iocs

    def analyze_session(self, session_id: str, commands: List[str], src_ip: str) -> Dict[str, Any]:
        """Analyse détaillée d'une session avec toutes les catégories"""
        patterns = AttackPattern()
        iocs = self.extract_iocs(commands)
        suspicious = self.detect_suspicious_patterns(commands)
        
        for command in commands:
            cmd_lower = command.lower()
            
            # Comptage des patterns pour toutes les catégories
            for category, keywords in KEYWORDS.items():
                if any(keyword in cmd_lower for keyword in keywords):
                    setattr(patterns, category, getattr(patterns, category) + 1)
        
        # Détection avancée
        intent = self._determine_intent(patterns)
        skill_level = self._assess_skill_level(patterns, commands)
        malware_family = self.detect_malware_family(commands)
        mitre_techniques = self.detect_mitre_techniques(patterns)
        threat_score = self._calculate_threat_score(patterns, len(commands))
        attack_chain = self._identify_attack_chain(patterns)
        
        return {
            'session_id': session_id,
            'src_ip': src_ip,
            'command_count': len(commands),
            'intent': intent,
            'skill_level': skill_level,
            'malware_family': malware_family,
            'threat_score': threat_score,
            'attack_chain': attack_chain,
            
            # Scores par catégorie
            'recon_score': patterns.recon,
            'download_score': patterns.download,
            'destructive_score': patterns.destructive,
            'persistence_score': patterns.persistence,
            'privesc_score': patterns.privilege_escalation,
            'lateral_score': patterns.lateral_movement,
            'exfil_score': patterns.data_exfiltration,
            'scan_score': patterns.network_scanning,
            'exploit_score': patterns.exploitation,
            'cred_score': patterns.credential_access,
            'evasion_score': patterns.defense_evasion,
            'backdoor_score': patterns.backdoor_installation,
            'crypto_score': patterns.cryptomining,
            'botnet_score': patterns.botnet_activity,
            'webshell_score': patterns.web_shell,
            
            # IOCs
            'ioc_urls': ', '.join(iocs['urls']) if iocs['urls'] else 'None',
            'ioc_ips': ', '.join(iocs['ips']) if iocs['ips'] else 'None',
            'ioc_domains': ', '.join(iocs['domains']) if iocs['domains'] else 'None',
            'ioc_emails': ', '.join(iocs['emails']) if iocs['emails'] else 'None',
            'ioc_hashes': ', '.join(iocs['hashes']) if iocs['hashes'] else 'None',
            'ioc_files': ', '.join(iocs['file_paths'][:5]) if iocs['file_paths'] else 'None',
            
            # Patterns suspects
            'suspicious_ports': ', '.join(suspicious['ports']) if suspicious['ports'] else 'None',
            'suspicious_paths': ', '.join(suspicious['paths']) if suspicious['paths'] else 'None',
            'encoding_detected': 'Yes' if suspicious['encoding'] else 'No',
            'obfuscation_detected': 'Yes' if suspicious['obfuscation'] else 'No',
            
            # MITRE ATT&CK
            'mitre_techniques': ' | '.join(mitre_techniques) if mitre_techniques else 'None',
            'active_categories': ', '.join(patterns.get_active_categories()),
            
            # Échantillons
            'sample_commands': ' | '.join(commands[:3])
        }

    def _determine_intent(self, patterns: AttackPattern) -> str:
        """Détermine l'intention de l'attaquant - Version étendue"""
        # Ordre de priorité par gravité
        if patterns.destructive > 0:
            return "CRITICAL - Destructive Attack"
        elif patterns.cryptomining > 2:
            return "CRITICAL - Cryptomining Operation"
        elif patterns.backdoor_installation > 1:
            return "CRITICAL - Backdoor Installation"
        elif patterns.web_shell > 0:
            return "HIGH - Web Shell Deployment"
        elif patterns.botnet_activity > 1:
            return "HIGH - Botnet Activity"
        elif patterns.data_exfiltration > 1:
            return "HIGH - Data Exfiltration Attempt"
        elif patterns.persistence > 1:
            return "HIGH - Persistence Establishment"
        elif patterns.credential_access > 2:
            return "MEDIUM - Credential Harvesting"
        elif patterns.privilege_escalation > 0:
            return "MEDIUM - Privilege Escalation"
        elif patterns.exploitation > 0:
            return "MEDIUM - Exploitation Attempt"
        elif patterns.lateral_movement > 0:
            return "MEDIUM - Lateral Movement"
        elif patterns.defense_evasion > 1:
            return "MEDIUM - Defense Evasion"
        elif patterns.download > 2:
            return "MEDIUM - Malware Download"
        elif patterns.network_scanning > 2:
            return "LOW - Network Scanning"
        elif patterns.recon > 5:
            return "LOW - Active Reconnaissance"
        elif patterns.recon > 0:
            return "INFO - Basic Reconnaissance"
        else:
            return "UNKNOWN - Scanning/Probing"
    
    def _identify_attack_chain(self, patterns: AttackPattern) -> str:
        """Identifie la chaîne d'attaque (kill chain)"""
        phases = []
        
        if patterns.recon > 0 or patterns.network_scanning > 0:
            phases.append("1-Reconnaissance")
        if patterns.exploitation > 0:
            phases.append("2-Initial Access")
        if patterns.download > 0:
            phases.append("3-Payload Delivery")
        if patterns.privilege_escalation > 0:
            phases.append("4-Privilege Escalation")
        if patterns.defense_evasion > 0:
            phases.append("5-Defense Evasion")
        if patterns.credential_access > 0:
            phases.append("6-Credential Access")
        if patterns.persistence > 0 or patterns.backdoor_installation > 0:
            phases.append("7-Persistence")
        if patterns.lateral_movement > 0:
            phases.append("8-Lateral Movement")
        if patterns.data_exfiltration > 0:
            phases.append("9-Exfiltration")
        if patterns.destructive > 0:
            phases.append("10-Impact")
        
        return " -> ".join(phases) if phases else "Single Phase Attack"

    def _assess_skill_level(self, patterns: AttackPattern, commands: List[str]) -> str:
        """Évalue le niveau de compétence """
        total_score = patterns.total_score()
        unique_categories = len(patterns.get_active_categories())
        
        # Indicateurs de sophistication
        has_evasion = patterns.defense_evasion > 0
        has_persistence = patterns.persistence > 0
        has_privesc = patterns.privilege_escalation > 0
        has_lateral = patterns.lateral_movement > 0
        has_backdoor = patterns.backdoor_installation > 0
        
        # Analyse des commandes
        command_diversity = len(set(commands))
        avg_cmd_length = sum(len(cmd) for cmd in commands) / len(commands) if commands else 0
        
        # Détection d'automatisation
        is_automated = (
            command_diversity < len(commands) * 0.3 or  # Beaucoup de répétitions
            patterns.botnet_activity > 0 or
            patterns.cryptomining > 0
        )
        
        # Évaluation sophistication
        sophistication_score = 0
        if has_evasion: sophistication_score += 20
        if has_persistence: sophistication_score += 15
        if has_privesc: sophistication_score += 15
        if has_lateral: sophistication_score += 15
        if has_backdoor: sophistication_score += 20
        if unique_categories >= 5: sophistication_score += 10
        if avg_cmd_length > 50: sophistication_score += 5
        
        # Classification
        if sophistication_score >= 60 and unique_categories >= 6:
            return "Advanced Persistent Threat (APT)"
        elif sophistication_score >= 45 or (has_persistence and has_privesc and has_evasion):
            return "Advanced Attacker"
        elif sophistication_score >= 30 or unique_categories >= 4:
            return "Intermediate Attacker"
        elif is_automated or patterns.botnet_activity > 0:
            return "Automated Bot/Scanner"
        elif total_score > 5 or len(commands) > 15:
            return "Script Kiddie (Active)"
        else:
            return "Script Kiddie (Basic)"

    def _calculate_threat_score(self, patterns: AttackPattern, cmd_count: int) -> int:
        """Calcule un score de menace (0-100) """
        score = 0
        
        # Poids par catégorie (ajusté pour les nouvelles catégories)
        score += patterns.destructive * 25          # Très critique
        score += patterns.backdoor_installation * 20 # Très critique
        score += patterns.web_shell * 20            # Très critique
        score += patterns.persistence * 18          # Haute priorité
        score += patterns.cryptomining * 15         # Haute priorité
        score += patterns.data_exfiltration * 15    # Haute priorité
        score += patterns.privilege_escalation * 14 # Haute priorité
        score += patterns.botnet_activity * 12      # Moyen-élevé
        score += patterns.credential_access * 10    # Moyen
        score += patterns.exploitation * 10         # Moyen
        score += patterns.defense_evasion * 8       # Moyen
        score += patterns.download * 7              # Moyen-bas
        score += patterns.lateral_movement * 7      # Moyen-bas
        score += patterns.network_scanning * 3      # Bas
        score += patterns.recon * 2                 # Bas
        
        # Bonus pour combinaisons dangereuses
        if patterns.persistence > 0 and patterns.backdoor_installation > 0:
            score += 20  # Compromission persistante
        if patterns.privilege_escalation > 0 and patterns.credential_access > 0:
            score += 15  # Escalade avec vol d'identifiants
        if patterns.data_exfiltration > 0 and patterns.defense_evasion > 0:
            score += 15  # Exfiltration furtive
        if patterns.cryptomining > 0 and patterns.persistence > 0:
            score += 10  # Mining persistant
        
        # Bonus pour volume et diversité
        score += min(cmd_count // 3, 15)  # Bonus pour volume d'activité
        
        return min(score, 100)

    def group_and_analyze_sessions(self, df: pd.DataFrame) -> pd.DataFrame:
        """Groupe les sessions et effectue l'analyse"""
        command_df = df[df['eventid'] == 'cowrie.command.input'].copy()
        
        if command_df.empty:
            print("[ERROR] Aucune commande trouvée dans les logs")
            return pd.DataFrame()
        
        sessions = command_df.groupby('session').agg(
            src_ip=('src_ip', 'first'),
            commands=('input', list)
        )
        
        print(f"[INFO] Analyse de {len(sessions)} sessions...\n")
        
        results = []
        for session_id, row in sessions.iterrows():
            analysis = self.analyze_session(
                session_id, 
                row['commands'], 
                row['src_ip']
            )
            results.append(analysis)
        
        return pd.DataFrame(results)

    def create_visualizations(self, results_df: pd.DataFrame):
        """Génère des visualisations améliorées et détaillées"""
        if results_df.empty:
            return
            
        print("Creating advanced visualizations...")
        sns.set_theme(style="whitegrid")
        
         
        # 1. Distribution des intentions avec niveaux de gravité
        plt.figure(figsize=(16, 8))
        intent_counts = results_df['intent'].value_counts()
        
        # Définir les couleurs selon la gravité
        color_map = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#689f38',
            'INFO': '#1976d2',
            'UNKNOWN': '#757575'
        }
        colors = [color_map.get(intent.split(' - ')[0], '#757575') for intent in intent_counts.index]
        
        bars = plt.barh(range(len(intent_counts)), intent_counts.values, color=colors)
        plt.yticks(range(len(intent_counts)), intent_counts.index)
        plt.title('Distribution des Intentions d\'Attaque par Niveau de Gravité', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Nombre de Sessions', fontsize=13, fontweight='bold')
        plt.ylabel('Intention d\'Attaque', fontsize=13, fontweight='bold')
        
        # Annotations
        for i, v in enumerate(intent_counts.values):
            percentage = (v / len(results_df)) * 100
            plt.text(v + max(intent_counts.values)*0.01, i, 
                    f'{v} ({percentage:.1f}%)', va='center', fontweight='bold', fontsize=11)
        
        # Légende
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#d32f2f', label='CRITICAL - Menace maximale'),
            Patch(facecolor='#f57c00', label='HIGH - Menace élevée'),
            Patch(facecolor='#fbc02d', label='MEDIUM - Menace moyenne'),
            Patch(facecolor='#689f38', label='LOW - Menace faible'),
            Patch(facecolor='#1976d2', label='INFO - Information'),
            Patch(facecolor='#757575', label='UNKNOWN - Non classifié')
        ]
        plt.legend(handles=legend_elements, loc='lower right', fontsize=10, framealpha=0.9)
        plt.grid(axis='x', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'attack_intent_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Niveau de compétence
        plt.figure(figsize=(12, 12))
        skill_counts = results_df['skill_level'].value_counts()
        
        # Couleurs par niveau de danger
        skill_colors = {
            'Advanced Persistent Threat (APT)': '#b71c1c',
            'Advanced Attacker': '#e64a19',
            'Intermediate Attacker': '#f57f17',
            'Automated Bot/Scanner': '#1976d2',
            'Script Kiddie (Active)': '#388e3c',
            'Script Kiddie (Basic)': '#689f38'
        }
        colors = [skill_colors.get(skill, '#757575') for skill in skill_counts.index]
        
        wedges, texts, autotexts = plt.pie(
            skill_counts, 
            labels=skill_counts.index, 
            autopct='%1.1f%%',
            startangle=90, 
            colors=colors,
            textprops={'fontsize': 12, 'fontweight': 'bold'},
            explode=[0.05 if i == 0 else 0 for i in range(len(skill_counts))]
        )
        
        # Ajouter les valeurs absolues
        for i, (text, autotext, wedge) in enumerate(zip(texts, autotexts, wedges)):
            angle = (wedge.theta2 + wedge.theta1) / 2
            autotext.set_text(f'{skill_counts.iloc[i]}\n({autotext.get_text()})')
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(11)
        
        plt.title('Distribution des Niveaux de Sophistication des Attaquants', 
                 fontsize=16, fontweight='bold', pad=20)
        
        # Légende avec explications
        legend_labels = [
            f'{skill} - {count} sessions' 
            for skill, count in zip(skill_counts.index, skill_counts.values)
        ]
        plt.legend(legend_labels, loc='upper left', bbox_to_anchor=(1, 1), 
                  fontsize=10, framealpha=0.9, title='Niveaux détectés')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'attacker_skill_level.png', dpi=300, bbox_inches='tight')
        plt.close()
        # 3. Top 15 des IPs sources avec threat score
        plt.figure(figsize=(16, 9))
        top_ips = results_df.nlargest(15, 'threat_score')[['src_ip', 'threat_score', 'intent']]
        
        # Couleurs basées sur le score
        colors_gradient = []
        for score in top_ips['threat_score']:
            if score >= 85:
                colors_gradient.append('#b71c1c')
            elif score >= 70:
                colors_gradient.append('#e64a19')
            elif score >= 50:
                colors_gradient.append('#f57f17')
            else:
                colors_gradient.append('#fbc02d')
        
        bars = plt.barh(range(len(top_ips)), top_ips['threat_score'], color=colors_gradient)
        plt.yticks(range(len(top_ips)), top_ips['src_ip'], fontsize=11)
        plt.xlabel('Score de Menace (0-100)', fontsize=13, fontweight='bold')
        plt.ylabel('Adresse IP Source', fontsize=13, fontweight='bold')
        plt.title('Top 15 des Adresses IP Attaquantes par Score de Menace', 
                 fontsize=16, fontweight='bold', pad=20)
        
        # Annotations avec score et intention
        for i, (ip, score, intent) in enumerate(zip(top_ips['src_ip'], top_ips['threat_score'], top_ips['intent'])):
            severity = intent.split(' - ')[0] if ' - ' in intent else intent
            plt.text(score + 2, i, f'{score:.0f} - {severity}', 
                    va='center', fontweight='bold', fontsize=10)
        
        # Légende zones de risque
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#b71c1c', label='CRITIQUE (85-100) - Action immédiate requise'),
            Patch(facecolor='#e64a19', label='ÉLEVÉ (70-84) - Menace sérieuse'),
            Patch(facecolor='#f57f17', label='MOYEN (50-69) - Surveillance accrue'),
            Patch(facecolor='#fbc02d', label='FAIBLE (0-49) - Vigilance normale')
        ]
        plt.legend(handles=legend_elements, loc='lower right', fontsize=10, framealpha=0.9)
        plt.grid(axis='x', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'top_attacker_ips.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 4. Distribution des scores de menace avec zones de risque
        plt.figure(figsize=(16, 8))
        
        # Histogramme
        n, bins, patches = plt.hist(results_df['threat_score'], bins=30, 
                                     edgecolor='black', linewidth=1.2, alpha=0.8)
        
        # Colorer les barres selon les zones
        for i, patch in enumerate(patches):
            bin_center = (bins[i] + bins[i+1]) / 2
            if bin_center >= 85:
                patch.set_facecolor('#b71c1c')
            elif bin_center >= 70:
                patch.set_facecolor('#e64a19')
            elif bin_center >= 50:
                patch.set_facecolor('#f57f17')
            elif bin_center >= 30:
                patch.set_facecolor('#fbc02d')
            else:
                patch.set_facecolor('#689f38')
        
        # Zones de fond
        plt.axvspan(0, 30, alpha=0.15, color='green', zorder=0)
        plt.axvspan(30, 50, alpha=0.15, color='yellow', zorder=0)
        plt.axvspan(50, 70, alpha=0.15, color='orange', zorder=0)
        plt.axvspan(70, 85, alpha=0.15, color='orangered', zorder=0)
        plt.axvspan(85, 100, alpha=0.15, color='red', zorder=0)
        
        # Statistiques
        mean_score = results_df['threat_score'].mean()
        median_score = results_df['threat_score'].median()
        plt.axvline(mean_score, color='blue', linestyle='--', linewidth=3, 
                   label=f'Moyenne: {mean_score:.1f}', zorder=5)
        plt.axvline(median_score, color='purple', linestyle=':', linewidth=3, 
                   label=f'Médiane: {median_score:.1f}', zorder=5)
        
        plt.title('Distribution des Scores de Menace avec Zones de Risque', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Score de Menace (0-100)', fontsize=13, fontweight='bold')
        plt.ylabel('Nombre de Sessions', fontsize=13, fontweight='bold')
        
        # Légende complète
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#689f38', alpha=0.8, label='Faible (0-30) - Surveillance standard'),
            Patch(facecolor='#fbc02d', alpha=0.8, label='Moyen-Bas (30-50) - Attention modérée'),
            Patch(facecolor='#f57f17', alpha=0.8, label='Moyen (50-70) - Surveillance accrue'),
            Patch(facecolor='#e64a19', alpha=0.8, label='Élevé (70-85) - Réponse rapide'),
            Patch(facecolor='#b71c1c', alpha=0.8, label='Critique (85-100) - Action immédiate'),
            plt.Line2D([0], [0], color='blue', linewidth=3, linestyle='--', label=f'Moyenne: {mean_score:.1f}'),
            plt.Line2D([0], [0], color='purple', linewidth=3, linestyle=':', label=f'Médiane: {median_score:.1f}')
        ]
        plt.legend(handles=legend_elements, loc='upper right', fontsize=10, framealpha=0.95)
        
        # Annotations statistiques
        critical_count = len(results_df[results_df['threat_score'] >= 85])
        high_count = len(results_df[(results_df['threat_score'] >= 70) & (results_df['threat_score'] < 85)])
        plt.text(0.02, 0.98, 
                f'Sessions critiques (≥85): {critical_count}\nSessions élevées (70-84): {high_count}\nTotal sessions: {len(results_df)}',
                transform=plt.gca().transAxes, fontsize=11, verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        plt.grid(axis='y', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'threat_score_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 5. Heatmap des catégories d'attaque
        plt.figure(figsize=(16, 11))
        category_cols = ['recon_score', 'download_score', 'destructive_score', 
                        'persistence_score', 'privesc_score', 'lateral_score',
                        'exfil_score', 'scan_score', 'exploit_score', 'cred_score',
                        'evasion_score', 'backdoor_score', 'crypto_score', 
                        'botnet_score', 'webshell_score']
        
        category_data = results_df[category_cols].sum().sort_values(ascending=True)
        category_labels = [col.replace('_score', '').replace('_', ' ').title() 
                          for col in category_data.index]
        
        # Colorer selon l'intensité
        colors_bars = plt.cm.RdYlGn_r(category_data.values / category_data.max())
        
        bars = plt.barh(category_labels, category_data.values, color=colors_bars)
        plt.xlabel('Nombre Total de Détections', fontsize=13, fontweight='bold')
        plt.ylabel('Catégorie d\'Attaque', fontsize=13, fontweight='bold')
        plt.title('Répartition des Catégories d\'Attaque Détectées', 
                 fontsize=16, fontweight='bold', pad=20)
        
        # Annotations avec pourcentages
        total_detections = category_data.sum()
        for i, (label, v) in enumerate(zip(category_labels, category_data.values)):
            percentage = (v / total_detections) * 100
            plt.text(v + category_data.max()*0.01, i, 
                    f'{int(v)} ({percentage:.1f}%)', 
                    va='center', fontweight='bold', fontsize=10)
        
        # Légende explicative
        severity_text = """
Catégories CRITIQUES:
• Destructive, Backdoor, Crypto, Webshell

Catégories ÉLEVÉES:
• Persistence, Exfil, Botnet

Catégories MOYENNES:
• Privesc, Cred, Evasion, Exploit, Lateral

Catégories FAIBLES:
• Recon, Download, Scan
        """
        plt.text(1.02, 0.5, severity_text, transform=plt.gca().transAxes,
                fontsize=9, verticalalignment='center',
                bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
        
        plt.grid(axis='x', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'attack_categories_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 6. Timeline/distribution des familles de malware
        if results_df['malware_family'].notna().any():
            plt.figure(figsize=(14, 8))
            malware_all = results_df['malware_family'].str.split(', ').explode()
            malware_counts = malware_all[malware_all != 'Unknown'].value_counts()
            
            if not malware_counts.empty:
                # Couleurs différentes par type de malware
                malware_colors = {
                    'MIRAI': '#e74c3c',
                    'GAFGYT': '#e67e22',
                    'XORDDOS': '#9b59b6',
                    'TSUNAMI': '#3498db',
                    'COINMINER': '#f39c12',
                    'WEBSHELL': '#1abc9c',
                    'RANSOMWARE': '#c0392b',
                    'ROOTKIT': '#34495e',
                    'WORM': '#16a085',
                    'TROJAN': '#d35400'
                }
                colors_malware = [malware_colors.get(m, '#95a5a6') for m in malware_counts.index]
                
                bars = plt.bar(range(len(malware_counts)), malware_counts.values, color=colors_malware)
                plt.xticks(range(len(malware_counts)), malware_counts.index, rotation=45, ha='right', fontsize=12)
                plt.ylabel('Nombre de Détections', fontsize=13, fontweight='bold')
                plt.xlabel('Famille de Malware', fontsize=13, fontweight='bold')
                plt.title('Familles de Malware Identifiées dans les Attaques', 
                         fontsize=16, fontweight='bold', pad=20)
                
                # Annotations
                for i, v in enumerate(malware_counts.values):
                    percentage = (v / len(results_df)) * 100
                    plt.text(i, v + malware_counts.max()*0.02, 
                            f'{v}\n({percentage:.1f}%)', 
                            ha='center', fontweight='bold', fontsize=10)
                
                # Description des malwares
                malware_info = """
Familles détectées:
• MIRAI: Botnet IoT, attaques DDoS
• GAFGYT/BASHLITE: Botnet DDoS
• COINMINER: Mining de crypto
• XORDDOS: Botnet Linux DDoS
• TSUNAMI: IRC botnet
• WEBSHELL: Backdoor web PHP
• RANSOMWARE: Chiffrement données
• ROOTKIT: Dissimulation avancée
                """
                plt.text(1.01, 0.5, malware_info, transform=plt.gca().transAxes,
                        fontsize=9, verticalalignment='center',
                        bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
                
                plt.grid(axis='y', alpha=0.3, linestyle='--')
                plt.tight_layout()
                plt.savefig(self.output_dir / 'malware_families.png', dpi=300, bbox_inches='tight')
                plt.close()
        
        # 7. Corrélation Sophistication vs Menace
        plt.figure(figsize=(14, 9))
        skill_threat = results_df.groupby('skill_level').agg({
            'threat_score': ['mean', 'count', 'std']
        }).round(1)
        skill_threat.columns = ['mean', 'count', 'std']
        skill_threat = skill_threat.sort_values('mean', ascending=True)
        
        # Couleurs par sophistication
        colors_skill = {
            'Script Kiddie (Basic)': '#689f38',
            'Script Kiddie (Active)': '#8bc34a',
            'Automated Bot/Scanner': '#1976d2',
            'Intermediate Attacker': '#f57f17',
            'Advanced Attacker': '#e64a19',
            'Advanced Persistent Threat (APT)': '#b71c1c'
        }
        bar_colors = [colors_skill.get(skill, '#757575') for skill in skill_threat.index]
        
        bars = plt.barh(range(len(skill_threat)), skill_threat['mean'], color=bar_colors, alpha=0.8)
        plt.yticks(range(len(skill_threat)), skill_threat.index, fontsize=11)
        plt.xlabel('Score de Menace Moyen (0-100)', fontsize=13, fontweight='bold')
        plt.ylabel('Niveau de Sophistication', fontsize=13, fontweight='bold')
        plt.title('Corrélation entre Niveau de Sophistication et Score de Menace', 
                 fontsize=16, fontweight='bold', pad=20)
        
        # Annotations détaillées
        for i, (skill, row) in enumerate(skill_threat.iterrows()):
            mean_val = row['mean']
            count_val = int(row['count'])
            std_val = row['std']
            plt.text(mean_val + 2, i, 
                    f'{mean_val:.1f} (n={count_val}, σ={std_val:.1f})', 
                    va='center', fontweight='bold', fontsize=10)
        
        # Barres d'erreur (écart-type)
        plt.errorbar(skill_threat['mean'], range(len(skill_threat)), 
                    xerr=skill_threat['std'], fmt='none', ecolor='black', 
                    elinewidth=2, capsize=5, alpha=0.6, label='Écart-type')
        
        # Légende
        legend_text = """
Observations:
• APT: Menace maximale (très sophistiqué)
• Advanced: Menace élevée (techniques avancées)
• Intermediate: Menace moyenne (combinaisons)
• Bot/Scanner: Variable (automatisé)
• Script Kiddie: Menace faible (basique)

n = nombre de sessions
σ = écart-type (variabilité)
        """
        plt.text(1.01, 0.5, legend_text, transform=plt.gca().transAxes,
                fontsize=9, verticalalignment='center',
                bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
        
        plt.grid(axis='x', alpha=0.3, linestyle='--')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'skill_vs_threat.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"[SUCCESS] {7} visualisations haute résolution sauvegardées dans: {self.output_dir}/")

    def generate_report(self, results_df: pd.DataFrame):
        """Génère un rapport détaillé avec statistiques avancées"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Statistiques avancées
        high_risk = len(results_df[results_df['threat_score'] >= 70])
        medium_risk = len(results_df[(results_df['threat_score'] >= 50) & (results_df['threat_score'] < 70)])
        low_risk = len(results_df[results_df['threat_score'] < 50])
        
        # Top menaces
        top_threats = results_df.nlargest(5, 'threat_score')[['session_id', 'src_ip', 'threat_score', 'intent']]
        
        # Catégories les plus actives
        category_cols = ['recon_score', 'download_score', 'destructive_score', 
                        'persistence_score', 'privesc_score', 'lateral_score',
                        'exfil_score', 'scan_score', 'exploit_score', 'cred_score',
                        'evasion_score', 'backdoor_score', 'crypto_score', 
                        'botnet_score', 'webshell_score']
        top_categories = results_df[category_cols].sum().sort_values(ascending=False).head(5)
        
        # CSV complet
        csv_path = self.output_dir / 'cowrie_analysis_detailed.csv'
        results_df.to_csv(csv_path, index=False, encoding='utf-8-sig')
        
        # HTML avec mise en forme avancée
        html_path = self.output_dir / 'cowrie_analysis_report.html'
        
        html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Analyse Cowrie - Détaillé</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 4px solid #3498db;
            padding-bottom: 15px;
            font-size: 2.5em;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
            border-left: 5px solid #e74c3c;
            padding-left: 15px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            text-align: center;
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .risk-indicator {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            margin: 5px;
        }}
        .risk-critical {{ background: #e74c3c; color: white; }}
        .risk-high {{ background: #e67e22; color: white; }}
        .risk-medium {{ background: #f39c12; color: white; }}
        .risk-low {{ background: #2ecc71; color: white; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: bold;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .alert {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-style: italic;
        }}
        .category-badge {{
            display: inline-block;
            background: #3498db;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            margin: 3px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'Analyse Cowrie Honeypot - Détaillé</h1>
        <p class="timestamp">Généré le: {timestamp}</p>
        
        <h2>Statistiques Globales</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Sessions Totales</h3>
                <div class="value">{len(results_df)}</div>
            </div>
            <div class="stat-card">
                <h3>IPs Uniques</h3>
                <div class="value">{results_df['src_ip'].nunique()}</div>
            </div>
            <div class="stat-card">
                <h3>Commandes Totales</h3>
                <div class="value">{results_df['command_count'].sum():,}</div>
            </div>
            <div class="stat-card">
                <h3>Score Moyen</h3>
                <div class="value">{results_df['threat_score'].mean():.1f}</div>
            </div>
        </div>
        
        <h2>Répartition par Niveau de Risque</h2>
        <div style="margin: 20px 0;">
            <span class="risk-indicator risk-critical">Critique: {high_risk}</span>
            <span class="risk-indicator risk-high">Élevé: {medium_risk}</span>
            <span class="risk-indicator risk-low">Faible: {low_risk}</span>
        </div>
        
        {f'''<div class="alert">
            <strong>WARNING:</strong> {high_risk} session(s) à haut risque détectée(s) nécessitant une action immédiate!
        </div>''' if high_risk > 0 else ''}
        
        <h2>Top 5 des Menaces les Plus Graves</h2>
        {top_threats.to_html(index=False, escape=False, classes='table')}
        
        <h2>Attack Categories Most Active</h2>
        <div style="margin: 20px 0;">
        {''.join([f'<span class="category-badge">{cat.replace("_score", "").replace("_", " ").title()}: {val:.0f}</span>' 
                  for cat, val in top_categories.items()])}
        </div>
        
        <h2>Malware Families Detected</h2>
        <p>{', '.join(results_df['malware_family'].value_counts().index[:10]) if 'malware_family' in results_df else 'Aucune'}</p>
        
        <h2>Complete Session Details</h2>
        {results_df.to_html(index=False, escape=False, classes='table')}
        
        <hr style="margin: 40px 0; border: none; border-top: 2px solid #eee;">
        <p style="text-align: center; color: #7f8c8d;">
            Rapport généré automatiquement par Cowrie Log Analyzer v2.0<br>
            Pour plus d'informations, consultez les visualisations graphiques
        </p>
    </div>
</body>
</html>
        """
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[SUCCESS] Rapport CSV détaillé: {csv_path}")
        print(f"[SUCCESS] Rapport HTML interactif: {html_path}")

    def run_analysis(self):
        """Lance l'analyse complète"""
        print("=" * 60)
        print("COWRIE HONEYPOT LOG ANALYZER")
        print("=" * 60 + "\n")
        
        events = self.read_log_files()
        
        if not events:
            print("[ERROR] Aucun événement à analyser")
            return
        
        df = pd.DataFrame(events)
        
        # Analyse des identifiants
        creds = self.extract_credentials(df)
        if not creds.empty:
            print("[INFO] Top 5 des identifiants utilisés:")
            print(creds.head(5).to_string(index=False))
            print()
        
        # Analyse des sessions
        results_df = self.group_and_analyze_sessions(df)
        
        if results_df.empty:
            print("[ERROR] Aucune session à analyser")
            return
        
        # Trier par score de menace
        results_df = results_df.sort_values('threat_score', ascending=False)
        
        # Génération des rapports
        self.generate_report(results_df)
        self.create_visualizations(results_df)
        
        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)

# --- Point d'entrée principal ---
if __name__ == '__main__':
    analyzer = CowrieLogAnalyzer()
    analyzer.run_analysis()