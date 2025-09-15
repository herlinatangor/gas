#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Ultra-Optimized Platform-Specific Credential Extractor v4.1.0 FINAL
# Complete solution with advanced platform parsers, optimized performance, and robust error handling
# Features: Platform-specific parsing, regex mode, bulk processing, real-time output, error recovery

import os
import time
import sys
import threading
import logging
import signal
import uuid
import socket
import argparse
import errno
import re
import json
import hashlib
from typing import Set, Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    from tqdm import tqdm
except ImportError:
    print("📦 Installing required dependency: tqdm")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import tqdm

# --- CONFIGURATION ---
APP_NAME = "Ultra-Optimized Platform-Specific Credential Extractor"
APP_VERSION = "4.1.0 FINAL"
BASE_OUTPUT_DIR = './platform_extraction_output'
OUTPUT_FILE_TEMPLATE = 'credentials_{platform}_{instance_id}.txt'
PROCESSED_FILES_LOG_TEMPLATE = 'processed_files_{instance_id}.log'
ERROR_LOG_TEMPLATE = 'extraction_errors_{instance_id}.log'
DEFAULT_INPUT_DIR = r'./input'

# Instance identification
INSTANCE_ID = f"{socket.gethostname()}_{os.getpid()}_{uuid.uuid4().hex[:6]}"

# --- ADVANCED PLATFORM DEFINITIONS ---
PLATFORM_DEFINITIONS = {
    'wordpress': {
        'name': 'WordPress CMS',
        'description': 'WordPress admin panels, login pages, and content management',
        'keywords': ['wp-admin', 'wp-login', 'wp-content', 'wordpress', 'wp-includes'],
        'regex_patterns': [
            r'https?://[^/\s]+/wp-admin[/\w\-]*',
            r'https?://[^/\s]+/wp-login\.php',
            r'https?://[^/\s]+/wp-content[/\w\-]*',
            r'https?://[^/\s]+/wp-includes[/\w\-]*'
        ],
        'path_indicators': ['/wp-admin/', '/wp-login.php', '/wp-content/', '/wp-includes/'],
        'port_indicators': [],
        'priority_keywords': ['wp-admin', 'wp-login'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 4,
            'exclude_passwords': ['wordpress', 'admin', '123456']
        }
    },
    'joomla': {
        'name': 'Joomla CMS',
        'description': 'Joomla administrator interface and components',
        'keywords': ['administrator', 'joomla', 'com_admin', 'components/com_'],
        'regex_patterns': [
            r'https?://[^/\s]+/administrator[/\w\-]*',
            r'https?://[^/\s]+/administrator/index\.php',
            r'https?://[^/\s]+/administrator/components[/\w\-]*'
        ],
        'path_indicators': ['/administrator/', '/administrator/index.php', '/components/com_'],
        'port_indicators': [],
        'priority_keywords': ['administrator', 'joomla'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 4,
            'exclude_passwords': ['joomla', 'admin', '123456']
        }
    },
    'moodle': {
        'name': 'Moodle LMS',
        'description': 'Moodle learning management system',
        'keywords': ['moodle', 'login/index.php', 'mod/forum', 'course/view'],
        'regex_patterns': [
            r'https?://[^/\s]+/moodle[/\w\-]*',
            r'https?://[^/\s]+/login/index\.php',
            r'https?://[^/\s]+/mod/[^/\s]+'
        ],
        'path_indicators': ['/moodle/', '/login/index.php', '/mod/', '/course/'],
        'port_indicators': [],
        'priority_keywords': ['moodle'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 5,
            'exclude_passwords': ['moodle', 'student', 'teacher']
        }
    },
    'cpanel': {
        'name': 'cPanel/WHM',
        'description': 'cPanel and WHM hosting control panels',
        'keywords': ['cpanel', 'whm', ':2083', ':2087', ':2082', ':2086', ':2095', ':2096'],
        'regex_patterns': [
            r'https?://[^/\s]+:208[23567][/\w\-]*',
            r'https?://[^/\s]+:209[56][/\w\-]*',
            r'[^/\s]+:208[23567]\b',
            r'[^/\s]+:209[56]\b'
        ],
        'path_indicators': ['/cpanel', '/whm', '/frontend/', '/login/'],
        'port_indicators': [':2082', ':2083', ':2086', ':2087', ':2095', ':2096'],
        'priority_keywords': [':2083', ':2087', 'cpanel'],
        'validation_rules': {
            'min_username_length': 4,
            'min_password_length': 6,
            'exclude_passwords': ['cpanel', 'hosting', '123456']
        }
    },
    'plesk': {
        'name': 'Plesk Panel',
        'description': 'Plesk hosting control panel',
        'keywords': ['plesk', ':8443', ':8880', 'login_up.php'],
        'regex_patterns': [
            r'https?://[^/\s]+:8443[/\w\-]*',
            r'https?://[^/\s]+:8880[/\w\-]*',
            r'[^/\s]+:8443\b',
            r'[^/\s]+:8880\b'
        ],
        'path_indicators': ['/login_up.php', '/admin/index.php', '/smb/web/'],
        'port_indicators': [':8443', ':8880'],
        'priority_keywords': [':8443', 'plesk'],
        'validation_rules': {
            'min_username_length': 4,
            'min_password_length': 6,
            'exclude_passwords': ['plesk', 'admin', '123456']
        }
    },
    'directadmin': {
        'name': 'DirectAdmin',
        'description': 'DirectAdmin hosting control panel',
        'keywords': ['directadmin', ':2222', 'CMD_LOGIN', 'CMD_ADMIN'],
        'regex_patterns': [
            r'https?://[^/\s]+:2222[/\w\-]*',
            r'[^/\s]+:2222\b'
        ],
        'path_indicators': ['/CMD_LOGIN', '/CMD_ADMIN_STATS', '/CMD_FILE_MANAGER'],
        'port_indicators': [':2222'],
        'priority_keywords': [':2222', 'directadmin'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 5,
            'exclude_passwords': ['directadmin', 'admin', '123456']
        }
    },
    'ssh': {
        'name': 'SSH Access',
        'description': 'Secure Shell remote access',
        'keywords': ['ssh', ':22', 'ssh://', 'root@', 'user@'],
        'regex_patterns': [
            r'ssh://[^/\s]+',
            r'[^/\s]+:22\b',
            r'\w+@[^/\s]+:22'
        ],
        'path_indicators': [],
        'port_indicators': [':22'],
        'priority_keywords': ['ssh://', ':22'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 6,
            'exclude_passwords': ['ssh', 'password', '123456']
        }
    },
    'ftp': {
        'name': 'FTP Access',
        'description': 'File Transfer Protocol access',
        'keywords': ['ftp', ':21', 'ftp://', 'sftp://'],
        'regex_patterns': [
            r'ftp://[^/\s]+',
            r'sftp://[^/\s]+',
            r'[^/\s]+:21\b'
        ],
        'path_indicators': [],
        'port_indicators': [':21'],
        'priority_keywords': ['ftp://', ':21'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 4,
            'exclude_passwords': ['ftp', 'anonymous', '123456']
        }
    },
    'database': {
        'name': 'Database Access',
        'description': 'MySQL, PostgreSQL, and web database interfaces',
        'keywords': ['mysql', 'postgresql', 'phpmyadmin', ':3306', ':5432', 'adminer'],
        'regex_patterns': [
            r'https?://[^/\s]+/phpmyadmin[/\w\-]*',
            r'https?://[^/\s]+/adminer[/\w\-]*',
            r'[^/\s]+:3306\b',
            r'[^/\s]+:5432\b'
        ],
        'path_indicators': ['/phpmyadmin', '/adminer', '/mysql', '/postgresql'],
        'port_indicators': [':3306', ':5432'],
        'priority_keywords': ['phpmyadmin', ':3306', ':5432'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 6,
            'exclude_passwords': ['mysql', 'root', '123456']
        }
    },
    'webmin': {
        'name': 'Webmin/Virtualmin',
        'description': 'Webmin system administration interface',
        'keywords': ['webmin', 'virtualmin', ':10000'],
        'regex_patterns': [
            r'https?://[^/\s]+:10000[/\w\-]*',
            r'[^/\s]+:10000\b'
        ],
        'path_indicators': ['/session_login.cgi', '/virtual-server/', '/config.cgi'],
        'port_indicators': [':10000'],
        'priority_keywords': [':10000', 'webmin'],
        'validation_rules': {
            'min_username_length': 3,
            'min_password_length': 6,
            'exclude_passwords': ['webmin', 'admin', '123456']
        }
    }
}

# --- ENHANCED LOGGING SYSTEM ---
class EnhancedLoggingHandler(logging.Handler):
    """Enhanced logging handler with tqdm compatibility"""
    
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self.stream = sys.stdout
        self.use_tqdm = False
        
    def emit(self, record):
        if self.use_tqdm and 'tqdm' in sys.modules and hasattr(tqdm, 'write'):
            try:
                msg = self.format(record)
                tqdm.write(msg, file=self.stream)
                self.flush()
            except:
                self._fallback_emit(record)
        else:
            self._fallback_emit(record)
    
    def _fallback_emit(self, record):
        self.stream.write(self.format(record) + '\n')
        self.stream.flush()
    
    def enable_tqdm(self):
        self.use_tqdm = True
    
    def flush(self):
        if hasattr(self.stream, 'flush'):
            self.stream.flush()

def setup_enhanced_logging(output_dir: str, error_log_file: str, level=logging.INFO):
    """Setup enhanced logging system"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Create formatter
    formatter = logging.Formatter(
        f'%(asctime)s [%(levelname)-8s] [ID: {INSTANCE_ID[:8]}] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)
    
    # Error file handler
    try:
        error_path = os.path.join(output_dir, error_log_file)
        error_handler = logging.FileHandler(error_path, mode='a', encoding='utf-8')
        error_handler.setFormatter(formatter)
        error_handler.setLevel(logging.ERROR)
        root_logger.addHandler(error_handler)
    except Exception as e:
        print(f"⚠️ Could not setup error logging: {e}")
    
    # Console handler
    console_handler = EnhancedLoggingHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    root_logger.addHandler(console_handler)
    
    # Enable tqdm if in TTY
    if sys.stdout.isatty():
        console_handler.enable_tqdm()
    
    logging.info(f"{APP_NAME} v{APP_VERSION} - System initialized")
    logging.info(f"Instance ID: {INSTANCE_ID}")
    logging.info(f"Output directory: {os.path.abspath(output_dir)}")

# --- ADVANCED PLATFORM PARSER ---
class AdvancedPlatformParser:
    """Advanced platform-specific credential parser"""
    
    def __init__(self, platform_key: str, platform_config: Dict[str, Any]):
        self.platform_key = platform_key
        self.config = platform_config
        self.name = platform_config['name']
        self.keywords = [k.lower() for k in platform_config['keywords']]
        self.priority_keywords = [k.lower() for k in platform_config.get('priority_keywords', [])]
        self.compiled_patterns = []
        
        # Compile regex patterns
        for pattern in platform_config['regex_patterns']:
            try:
                self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logging.warning(f"Invalid regex pattern for {self.name}: {pattern} - {e}")
        
        self.validation_rules = platform_config.get('validation_rules', {})
        logging.debug(f"Initialized parser for {self.name} with {len(self.keywords)} keywords")
    
    def calculate_match_confidence(self, line: str) -> float:
        """Calculate confidence score for platform match"""
        line_lower = line.lower()
        confidence = 0.0
        
        # Priority keyword matches (higher weight)
        for keyword in self.priority_keywords:
            if keyword in line_lower:
                confidence += 0.3
        
        # Regular keyword matches
        for keyword in self.keywords:
            if keyword in line_lower:
                confidence += 0.1
        
        # Regex pattern matches
        for pattern in self.compiled_patterns:
            if pattern.search(line):
                confidence += 0.2
        
        # Path indicator matches
        for path in self.config.get('path_indicators', []):
            if path.lower() in line_lower:
                confidence += 0.15
        
        # Port indicator matches
        for port in self.config.get('port_indicators', []):
            if port in line:
                confidence += 0.25
        
        return min(confidence, 1.0)  # Cap at 1.0
    
    def matches_platform(self, line: str, min_confidence: float = 0.1) -> bool:
        """Check if line matches this platform with confidence threshold"""
        return self.calculate_match_confidence(line) >= min_confidence
    
    def extract_credentials(self, line: str) -> Optional[Tuple[str, str, str, float]]:
        """Extract credentials with confidence score"""
        confidence = self.calculate_match_confidence(line)
        if confidence < 0.1:
            return None
        
        result = self._advanced_parse(line)
        if result:
            url, username, password = result
            if self._validate_credentials(url, username, password):
                return (url, username, password, confidence)
        
        return None
    
    def _advanced_parse(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Advanced multi-strategy parsing"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        # Strategy 1: Pipe separator (highest accuracy)
        if '|' in line and line.count('|') >= 2:
            result = self._parse_delimited(line, '|')
            if result:
                return result
        
        # Strategy 2: Semicolon separator
        if ';' in line and line.count(';') >= 2:
            result = self._parse_delimited(line, ';')
            if result:
                return result
        
        # Strategy 3: Advanced colon parsing (platform-aware)
        if ':' in line and line.count(':') >= 2:
            result = self._parse_colon_advanced(line)
            if result:
                return result
        
        # Strategy 4: Comma separator
        if ',' in line and line.count(',') >= 2:
            result = self._parse_delimited(line, ',')
            if result:
                return result
        
        # Strategy 5: Space-separated (intelligent parsing)
        if ' ' in line:
            result = self._parse_space_intelligent(line)
            if result:
                return result
        
        # Strategy 6: Email-like format (user@domain password url)
        if '@' in line:
            result = self._parse_email_format(line)
            if result:
                return result
        
        return None
    
    def _parse_delimited(self, line: str, delimiter: str) -> Optional[Tuple[str, str, str]]:
        """Parse delimited format with platform intelligence"""
        parts = [p.strip() for p in line.split(delimiter)]
        if len(parts) < 3:
            return None
        
        # Standard order: URL|username|password
        if len(parts) == 3:
            return self._clean_and_order(parts[0], parts[1], parts[2])
        
        # More than 3 parts - use platform intelligence
        url_candidates = []
        user_candidates = []
        pass_candidates = []
        
        for part in parts:
            if self._looks_like_url(part):
                url_candidates.append(part)
            elif self._looks_like_username(part):
                user_candidates.append(part)
            else:
                pass_candidates.append(part)
        
        # Try to match best candidates
        if user_candidates and pass_candidates:
            url = url_candidates[0] if url_candidates else ""
            return self._clean_and_order(url, user_candidates[0], pass_candidates[0])
        
        # Fallback: take first 3 parts
        return self._clean_and_order(parts[0], parts[1], parts[2])
    
    def _parse_colon_advanced(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Advanced colon parsing with platform awareness"""
        # Handle URLs with protocols and ports
        if any(protocol in line.lower() for protocol in ['http://', 'https://', 'ftp://', 'ssh://']):
            return self._parse_url_with_protocol(line)
        
        # Handle port-based services
        if any(port in line for port in self.config.get('port_indicators', [])):
            return self._parse_port_based_service(line)
        
        # Standard colon parsing
        parts = line.split(':')
        if len(parts) >= 3:
            if len(parts) == 3:
                return self._clean_and_order(parts[0], parts[1], parts[2])
            else:
                # Rejoin based on context
                if parts[0].lower() in ['http', 'https', 'ftp', 'ssh']:
                    url = ':'.join(parts[:2])
                    if len(parts) >= 4:
                        return self._clean_and_order(url, parts[2], parts[3])
                else:
                    # Take last two as credentials
                    url = ':'.join(parts[:-2])
                    return self._clean_and_order(url, parts[-2], parts[-1])
        
        return None
    
    def _parse_url_with_protocol(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parse line containing URL with protocol"""
        # Extract URL part
        url_match = re.search(r'(https?://[^\s:]+(?::\d+)?(?:/[^\s]*)?)', line, re.IGNORECASE)
        if url_match:
            url = url_match.group(1)
            remaining = line.replace(url, '').strip()
            
            # Parse remaining for credentials
            if ':' in remaining:
                parts = [p.strip() for p in remaining.split(':') if p.strip()]
                if len(parts) >= 2:
                    return self._clean_and_order(url, parts[0], parts[1])
            
            # Try other separators
            for sep in ['|', ';', ',', ' ']:
                if sep in remaining:
                    parts = [p.strip() for p in remaining.split(sep) if p.strip()]
                    if len(parts) >= 2:
                        return self._clean_and_order(url, parts[0], parts[1])
        
        return None
    
    def _parse_port_based_service(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parse port-based service credentials"""
        # Find host:port combination
        port_pattern = r'([^:\s]+):(\d+)'
        match = re.search(port_pattern, line)
        if match:
            host_port = match.group(0)
            remaining = line.replace(host_port, '').strip()
            
            # Parse remaining for credentials
            if ':' in remaining:
                parts = [p.strip() for p in remaining.split(':') if p.strip()]
                if len(parts) >= 2:
                    return self._clean_and_order(host_port, parts[0], parts[1])
            
            # Try other patterns
            parts = re.split(r'[|;,\s]+', remaining)
            parts = [p.strip() for p in parts if p.strip()]
            if len(parts) >= 2:
                return self._clean_and_order(host_port, parts[0], parts[1])
        
        return None
    
    def _parse_space_intelligent(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Intelligent space-separated parsing"""
        parts = line.split()
        if len(parts) < 3:
            return None
        
        # Classify parts
        urls = []
        users = []
        passwords = []
        others = []
        
        for part in parts:
            if self._looks_like_url(part):
                urls.append(part)
            elif self._looks_like_username(part):
                users.append(part)
            elif self._looks_like_password(part):
                passwords.append(part)
            else:
                others.append(part)
        
        # Smart assignment
        if urls and users and passwords:
            return self._clean_and_order(urls[0], users[0], passwords[0])
        elif users and passwords:
            url = urls[0] if urls else (others[0] if others else "")
            return self._clean_and_order(url, users[0], passwords[0])
        elif len(parts) >= 3:
            # Default assignment based on platform
            return self._assign_by_platform_logic(parts)
        
        return None
    
    def _parse_email_format(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parse email-like format: user@domain password url"""
        email_pattern = r'([^\s@]+@[^\s@]+\.[^\s@]+)'
        match = re.search(email_pattern, line)
        if match:
            email = match.group(1)
            remaining = line.replace(email, '').strip()
            
            parts = remaining.split()
            if parts:
                password = parts[0]
                url = ' '.join(parts[1:]) if len(parts) > 1 else ""
                return self._clean_and_order(url, email, password)
        
        return None
    
    def _assign_by_platform_logic(self, parts: List[str]) -> Optional[Tuple[str, str, str]]:
        """Assign parts based on platform-specific logic"""
        if self.platform_key in ['ssh', 'ftp']:
            # For SSH/FTP: host user password or protocol://host user password
            if len(parts) >= 3:
                return self._clean_and_order(parts[0], parts[1], parts[2])
        
        elif self.platform_key in ['cpanel', 'plesk', 'directadmin']:
            # For hosting panels: URL user password
            if len(parts) >= 3:
                return self._clean_and_order(parts[0], parts[1], parts[2])
        
        elif self.platform_key in ['wordpress', 'joomla', 'moodle']:
            # For CMS: URL user password
            if len(parts) >= 3:
                return self._clean_and_order(parts[0], parts[1], parts[2])
        
        # Default assignment
        if len(parts) >= 3:
            return self._clean_and_order(parts[0], parts[1], parts[2])
        
        return None
    
    def _looks_like_url(self, text: str) -> bool:
        """Check if text looks like a URL"""
        text_lower = text.lower()
        return any([
            text_lower.startswith(('http://', 'https://', 'ftp://', 'ssh://')),
            '.' in text and ('/' in text or any(port in text for port in [':80', ':443', ':21', ':22', ':2083', ':8443'])),
            any(tld in text_lower for tld in ['.com', '.org', '.net', '.edu', '.gov']),
            re.match(r'^[\d\.]+:\d+$', text)  # IP:port
        ])
    
    def _looks_like_username(self, text: str) -> bool:
        """Check if text looks like a username"""
        return any([
            '@' in text and '.' in text,  # Email format
            any(keyword in text.lower() for keyword in ['admin', 'user', 'root', 'manager']),
            3 <= len(text) <= 50 and not self._looks_like_password(text)
        ])
    
    def _looks_like_password(self, text: str) -> bool:
        """Check if text looks like a password"""
        return any([
            any(keyword in text.lower() for keyword in ['pass', 'pwd', '123']),
            len(text) >= 4 and any(c.isdigit() for c in text) and any(c.isalpha() for c in text)
        ])
    
    def _clean_and_order(self, url: str, username: str, password: str) -> Optional[Tuple[str, str, str]]:
        """Clean and properly order the extracted components"""
        url = url.strip()
        username = username.strip()
        password = password.strip()
        
        # Basic cleaning
        url = re.sub(r'^[|;,:\s]+|[|;,:\s]+$', '', url)
        username = re.sub(r'^[|;,:\s]+|[|;,:\s]+$', '', username)
        password = re.sub(r'^[|;,:\s]+|[|;,:\s]+$', '', password)
        
        # URL preprocessing
        if url and not url.startswith(('http://', 'https://', 'ftp://', 'ssh://')):
            if any(port in url for port in [':443', ':8443']):
                url = 'https://' + url.replace('https://', '')
            elif any(port in url for port in [':80', ':8080']):
                url = 'http://' + url.replace('http://', '')
            elif ':21' in url:
                url = 'ftp://' + url.replace('ftp://', '')
            elif ':22' in url:
                url = 'ssh://' + url.replace('ssh://', '')
            elif self.platform_key in ['wordpress', 'joomla', 'moodle'] and '.' in url:
                url = 'https://' + url
        
        return (url, username, password)
    
    def _validate_credentials(self, url: str, username: str, password: str) -> bool:
        """Validate extracted credentials against platform rules"""
        rules = self.validation_rules
        
        # Check minimum lengths
        if len(username) < rules.get('min_username_length', 3):
            return False
        if len(password) < rules.get('min_password_length', 4):
            return False
        
        # Check excluded passwords
        excluded = rules.get('exclude_passwords', [])
        if password.lower() in [p.lower() for p in excluded]:
            return False
        
        # Check for obvious placeholders
        if password.lower() in ['password', 'pass', '123456', '12345', '[unk]', 'n/a']:
            return False
        
        return True

# --- ADVANCED USER INTERFACE ---
def show_enhanced_menu() -> str:
    """Display enhanced platform selection menu"""
    print("\n" + "="*80)
    print(f"🚀 {APP_NAME}")
    print(f"📦 Version {APP_VERSION}")
    print("="*80)
    print("\n🎯 PLATFORM-SPECIFIC CREDENTIAL EXTRACTION")
    print("\n📋 Available Platforms:")
    
    platforms = list(PLATFORM_DEFINITIONS.items())
    
    print("1.  🌐 All Platforms (Auto-detect all systems)")
    for i, (key, config) in enumerate(platforms, 2):
        emoji = get_platform_emoji(key)
        print(f"{i:<3} {emoji} {config['name']:<25} - {config['description']}")
    
    print(f"{len(platforms)+2:<3} 🔤 Custom Keywords")
    print(f"{len(platforms)+3:<3} 🔧 Custom Regex Patterns")
    print(f"{len(platforms)+4:<3} ❓ Help & Examples")
    
    max_choice = len(platforms) + 4
    
    while True:
        try:
            choice = input(f"\n🎯 Select platform (1-{max_choice}): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= max_choice:
                return choice
            else:
                print(f"❌ Invalid choice. Please enter 1-{max_choice}.")
        except (EOFError, KeyboardInterrupt):
            print("\n\n⚠️ Operation cancelled by user.")
            sys.exit(0)

def get_platform_emoji(platform_key: str) -> str:
    """Get emoji for platform"""
    emoji_map = {
        'wordpress': '📝',
        'joomla': '🎨',
        'moodle': '🎓',
        'cpanel': '⚙️',
        'plesk': '🔧',
        'directadmin': '🛠️',
        'ssh': '🔐',
        'ftp': '📁',
        'database': '🗄️',
        'webmin': '💻'
    }
    return emoji_map.get(platform_key, '🔹')

def get_enhanced_platform_config(choice: str) -> Tuple[List[AdvancedPlatformParser], str, List[str]]:
    """Get enhanced platform configuration"""
    total_platforms = len(PLATFORM_DEFINITIONS)
    
    if choice == '1':
        # All platforms
        parsers = []
        keywords = []
        for key, config in PLATFORM_DEFINITIONS.items():
            parsers.append(AdvancedPlatformParser(key, config))
            keywords.extend(config['keywords'])
        return parsers, 'all_platforms', list(set(keywords))
    
    elif 2 <= int(choice) <= total_platforms + 1:
        # Specific platform
        platform_keys = list(PLATFORM_DEFINITIONS.keys())
        selected_key = platform_keys[int(choice) - 2]
        config = PLATFORM_DEFINITIONS[selected_key]
        parser = AdvancedPlatformParser(selected_key, config)
        return [parser], selected_key, config['keywords']
    
    elif choice == str(total_platforms + 2):
        # Custom keywords
        keywords_input = input("\n🔤 Enter custom keywords (comma-separated): ").strip()
        if keywords_input:
            keywords = [k.strip() for k in keywords_input.split(',') if k.strip()]
            return [], 'custom_keywords', keywords
        else:
            print("❌ No keywords provided.")
            return [], 'invalid', []
    
    elif choice == str(total_platforms + 3):
        # Custom regex
        print("\n🔧 Custom Regex Mode")
        print("📝 Enter regex patterns to match specific formats.")
        print("💡 Example: 'https?://[^/]+/wp-admin.*' for WordPress admin")
        regex_input = input("\n📝 Enter regex patterns (comma-separated): ").strip()
        if regex_input:
            patterns = [p.strip() for p in regex_input.split(',') if p.strip()]
            return [], 'custom_regex', patterns
        else:
            print("❌ No regex patterns provided.")
            return [], 'invalid', []
    
    elif choice == str(total_platforms + 4):
        # Help
        show_help_examples()
        return get_enhanced_platform_config(show_enhanced_menu())
    
    return [], 'invalid', []

def show_help_examples():
    """Show help and examples"""
    print("\n" + "="*80)
    print("📚 HELP & EXAMPLES")
    print("="*80)
    
    print("\n🔍 Supported Input Formats:")
    examples = [
        "Pipe-separated: https://example.com/wp-admin|admin|password123",
        "Colon-separated: https://example.com:2083:cpanel_user:cpanel_pass",
        "Semicolon-separated: example.com;username;password",
        "Space-separated: ssh://example.com:22 root secretpass",
        "Mixed formats are automatically detected and parsed"
    ]
    
    for example in examples:
        print(f"  • {example}")
    
    print("\n🎯 Platform-Specific Examples:")
    platform_examples = {
        'WordPress': 'https://site.com/wp-admin|admin|wp_password',
        'cPanel': 'https://cpanel.site.com:2083|user|cpanel_pass',
        'SSH': 'ssh://server.com:22|root|ssh_password',
        'FTP': 'ftp://ftp.site.com:21|ftpuser|ftp_pass'
    }
    
    for platform, example in platform_examples.items():
        print(f"  🔹 {platform:<12}: {example}")
    
    print(f"\n📊 Output Format:")
    print(f"  All results are saved in standardized pipe-separated format:")
    print(f"  URL|Username|Password")
    
    input(f"\n📖 Press Enter to continue...")

# --- ENHANCED PROCESSING ENGINE ---
def enhanced_file_processor(
    file_path: str,
    parsers: List[AdvancedPlatformParser],
    keywords: List[str],
    output_file,
    unique_lines: Set[str],
    progress_bar: Optional[tqdm] = None,
    regex_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Enhanced file processing with detailed statistics"""
    
    stats = {
        'lines_processed': 0,
        'lines_matched': 0,
        'credentials_extracted': 0,
        'platform_matches': {},
        'errors': []
    }
    
    try:
        # File preparation
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            logging.warning(f"Skipping empty file: {os.path.basename(file_path)}")
            return stats
        
        encoding = detect_encoding_advanced(file_path)
        logging.debug(f"Processing {os.path.basename(file_path)} ({file_size:,} bytes, {encoding} encoding)")
        
        if progress_bar:
            progress_bar.reset(total=file_size)
            progress_bar.set_description(f"📄 {os.path.basename(file_path)[:30]}")
        
        # Initialize platform stats
        for parser in parsers:
            stats['platform_matches'][parser.platform_key] = 0
        
        # Compile regex patterns if provided
        compiled_regex = []
        if regex_patterns:
            for pattern in regex_patterns:
                try:
                    compiled_regex.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    stats['errors'].append(f"Invalid regex: {pattern} - {e}")
        
        # Process file
        bytes_processed = 0
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            for line in f:
                stats['lines_processed'] += 1
                bytes_processed += len(line.encode(encoding, errors='replace'))
                
                # Update progress
                if progress_bar and stats['lines_processed'] % 500 == 0:
                    progress_bar.update(bytes_processed - progress_bar.n)
                    progress_bar.set_postfix_str(f"Extracted: {stats['credentials_extracted']}")
                
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                
                # Keyword filtering
                if keywords:
                    line_lower = line_stripped.lower()
                    if not any(keyword.lower() in line_lower for keyword in keywords):
                        continue
                
                # Regex filtering
                if compiled_regex:
                    if not any(pattern.search(line_stripped) for pattern in compiled_regex):
                        continue
                
                stats['lines_matched'] += 1
                
                # Platform-specific parsing
                best_result = None
                best_confidence = 0.0
                best_parser = None
                
                for parser in parsers:
                    result = parser.extract_credentials(line_stripped)
                    if result:
                        url, username, password, confidence = result
                        if confidence > best_confidence:
                            best_result = (url, username, password)
                            best_confidence = confidence
                            best_parser = parser
                
                # Fallback to generic parsing if no parser worked
                if not best_result and not parsers:
                    generic_result = generic_parse_advanced(line_stripped)
                    if generic_result:
                        best_result = generic_result
                        best_confidence = 0.5
                
                # Process result
                if best_result:
                    url, username, password = best_result
                    output_line = f"{url}|{username}|{password}"
                    
                    if output_line not in unique_lines:
                        unique_lines.add(output_line)
                        output_file.write(output_line + '\n')
                        output_file.flush()
                        stats['credentials_extracted'] += 1
                        
                        if best_parser:
                            stats['platform_matches'][best_parser.platform_key] += 1
                        
                        logging.debug(f"Extracted: {output_line} (confidence: {best_confidence:.2f})")
        
        # Final progress update
        if progress_bar:
            progress_bar.update(file_size - progress_bar.n)
            progress_bar.set_postfix_str(f"✅ Extracted: {stats['credentials_extracted']}")
        
        logging.info(f"Completed {os.path.basename(file_path)}: {stats['credentials_extracted']} credentials extracted from {stats['lines_processed']} lines")
        
    except Exception as e:
        error_msg = f"Error processing {os.path.basename(file_path)}: {e}"
        stats['errors'].append(error_msg)
        logging.error(error_msg)
    
    return stats

def detect_encoding_advanced(file_path: str) -> str:
    """Advanced encoding detection"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(8192)  # Read more data for better detection
            
            # Check for BOMs
            if raw_data.startswith(b'\xef\xbb\xbf'):
                return 'utf-8-sig'
            elif raw_data.startswith(b'\xff\xfe'):
                return 'utf-16-le'
            elif raw_data.startswith(b'\xfe\xff'):
                return 'utf-16-be'
            elif raw_data.startswith(b'\x00\x00\xfe\xff'):
                return 'utf-32-be'
            elif raw_data.startswith(b'\xff\xfe\x00\x00'):
                return 'utf-32-le'
            
            # Try UTF-8
            try:
                raw_data.decode('utf-8')
                return 'utf-8'
            except UnicodeDecodeError:
                pass
            
            # Try common encodings
            for encoding in ['latin-1', 'windows-1252', 'iso-8859-1']:
                try:
                    raw_data.decode(encoding)
                    return encoding
                except UnicodeDecodeError:
                    continue
            
            # Fallback
            return 'utf-8'
            
    except Exception as e:
        logging.warning(f"Encoding detection failed for {file_path}: {e}. Using UTF-8.")
        return 'utf-8'

def generic_parse_advanced(line: str) -> Optional[Tuple[str, str, str]]:
    """Advanced generic parsing for unknown formats"""
    line = line.strip()
    
    # Try different separators in order of preference
    separators = ['|', ';', ':', ',', '\t']
    for sep in separators:
        if sep in line and line.count(sep) >= 2:
            parts = [p.strip() for p in line.split(sep)]
            if len(parts) >= 3 and all(len(p) >= 3 for p in parts[:3]):
                return (parts[0], parts[1], parts[2])
    
    # Try space-separated with intelligent parsing
    parts = line.split()
    if len(parts) >= 3:
        # Look for URL-like, user-like, and password-like components
        url_candidates = [p for p in parts if ('.' in p and '/' in p) or ':' in p]
        user_candidates = [p for p in parts if '@' in p or any(u in p.lower() for u in ['admin', 'user', 'root'])]
        other_parts = [p for p in parts if p not in url_candidates and p not in user_candidates]
        
        if url_candidates and other_parts:
            url = url_candidates[0]
            remaining = [p for p in parts if p != url]
            if len(remaining) >= 2:
                return (url, remaining[0], remaining[1])
        
        # Fallback to first three parts
        if all(len(p) >= 3 for p in parts[:3]):
            return (parts[0], parts[1], parts[2])
    
    return None

# --- MAIN ENHANCED APPLICATION ---
def main():
    """Enhanced main application with comprehensive error handling"""
    try:
        # Initialize system
        output_dir = os.path.join(os.getcwd(), BASE_OUTPUT_DIR)
        error_log_file = ERROR_LOG_TEMPLATE.format(instance_id=INSTANCE_ID)
        
        # Parse command line arguments for non-interactive mode
        parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
        parser.add_argument('--non-interactive', '-n', action='store_true',
                          help='Run in non-interactive mode')
        parser.add_argument('--platform', '-p', type=str,
                          help='Platform selection (1-N)')
        parser.add_argument('--input', '-i', type=str, default=DEFAULT_INPUT_DIR,
                          help='Input directory')
        parser.add_argument('--keywords', '-k', type=str,
                          help='Comma-separated keywords')
        parser.add_argument('--output', '-o', type=str, default=output_dir,
                          help='Output directory')
        parser.add_argument('--debug', action='store_true',
                          help='Enable debug logging')
        
        args = parser.parse_args()
        
        # Setup logging
        log_level = logging.DEBUG if args.debug else logging.INFO
        setup_enhanced_logging(args.output, error_log_file, log_level)
        
        # Configuration
        if args.non_interactive and args.platform and args.keywords:
            # Non-interactive mode
            logging.info("Running in non-interactive mode")
            platform_choice = args.platform
            input_dir = args.input
            keywords = [k.strip() for k in args.keywords.split(',')]
            parsers = []
            
            if platform_choice == '1':
                # All platforms
                for key, config in PLATFORM_DEFINITIONS.items():
                    parsers.append(AdvancedPlatformParser(key, config))
                platform_type = 'all_platforms'
            else:
                # Specific platform
                platform_keys = list(PLATFORM_DEFINITIONS.keys())
                if 2 <= int(platform_choice) <= len(platform_keys) + 1:
                    selected_key = platform_keys[int(platform_choice) - 2]
                    config = PLATFORM_DEFINITIONS[selected_key]
                    parsers = [AdvancedPlatformParser(selected_key, config)]
                    platform_type = selected_key
                else:
                    print("❌ Invalid platform choice for non-interactive mode")
                    return 1
        else:
            # Interactive mode
            platform_choice = show_enhanced_menu()
            parsers, platform_type, keywords = get_enhanced_platform_config(platform_choice)
            
            if platform_type == 'invalid':
                print("❌ Invalid configuration. Exiting.")
                return 1
            
            # Get input directory
            default_input = args.input if args.input != DEFAULT_INPUT_DIR else DEFAULT_INPUT_DIR
            input_prompt = f"\n📁 Input directory (default: {default_input}): "
            input_dir = input(input_prompt).strip() or default_input
        
        # Validate input directory
        if not os.path.isdir(input_dir):
            print(f"❌ Input directory not found: {input_dir}")
            return 1
        
        # Display configuration
        print(f"\n🔧 Configuration Summary:")
        print(f"   Platform Type: {platform_type}")
        print(f"   Active Parsers: {len(parsers)}")
        if keywords:
            print(f"   Keywords: {', '.join(keywords[:5])}{'...' if len(keywords) > 5 else ''}")
        print(f"   Input Directory: {os.path.abspath(input_dir)}")
        print(f"   Output Directory: {os.path.abspath(args.output)}")
        
        # Scan for files
        txt_files = []
        print(f"\n🔍 Scanning for .txt files...")
        
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.lower().endswith('.txt'):
                    file_path = os.path.join(root, file)
                    # Skip hidden and system files
                    if not os.path.basename(file_path).startswith('.'):
                        txt_files.append(file_path)
        
        if not txt_files:
            print(f"❌ No .txt files found in {input_dir}")
            return 1
        
        print(f"📊 Found {len(txt_files)} .txt files to process")
        
        # Setup output
        os.makedirs(args.output, exist_ok=True)
        output_filename = OUTPUT_FILE_TEMPLATE.format(
            platform=platform_type, 
            instance_id=INSTANCE_ID
        )
        output_file_path = os.path.join(args.output, output_filename)
        
        # Processing
        print(f"\n🚀 Starting credential extraction...")
        unique_lines = set()
        total_stats = {
            'files_processed': 0,
            'files_success': 0,
            'files_error': 0,
            'total_lines': 0,
            'total_matches': 0,
            'total_extracted': 0,
            'platform_breakdown': {},
            'errors': []
        }
        
        start_time = time.time()
        
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            # Write header comment
            output_file.write(f"# Extracted credentials using {APP_NAME} v{APP_VERSION}\n")
            output_file.write(f"# Platform: {platform_type}\n")
            output_file.write(f"# Extraction time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output_file.write(f"# Format: URL|Username|Password\n")
            output_file.write("#\n")
            
            # Progress bars
            with tqdm(total=len(txt_files), desc="📁 Files", unit="file", position=0) as pbar_files:
                with tqdm(total=100, desc="📄 Current", unit="%", position=1, leave=False) as pbar_current:
                    
                    for file_path in txt_files:
                        total_stats['files_processed'] += 1
                        
                        # Process file
                        file_stats = enhanced_file_processor(
                            file_path=file_path,
                            parsers=parsers,
                            keywords=keywords,
                            output_file=output_file,
                            unique_lines=unique_lines,
                            progress_bar=pbar_current,
                            regex_patterns=keywords if platform_type == 'custom_regex' else None
                        )
                        
                        # Update total statistics
                        if file_stats['errors']:
                            total_stats['files_error'] += 1
                            total_stats['errors'].extend(file_stats['errors'])
                        else:
                            total_stats['files_success'] += 1
                        
                        total_stats['total_lines'] += file_stats['lines_processed']
                        total_stats['total_matches'] += file_stats['lines_matched']
                        total_stats['total_extracted'] += file_stats['credentials_extracted']
                        
                        # Merge platform breakdown
                        for platform, count in file_stats['platform_matches'].items():
                            total_stats['platform_breakdown'][platform] = \
                                total_stats['platform_breakdown'].get(platform, 0) + count
                        
                        # Update progress
                        pbar_files.update(1)
                        pbar_files.set_postfix_str(f"Total: {total_stats['total_extracted']}")
        
        # Final processing
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Sort and deduplicate output
        if total_stats['total_extracted'] > 0:
            print(f"\n📊 Finalizing output...")
            sorted_lines = sorted(list(unique_lines))
            
            with open(output_file_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write(f"# Extracted credentials using {APP_NAME} v{APP_VERSION}\n")
                f.write(f"# Platform: {platform_type}\n")
                f.write(f"# Total credentials: {len(sorted_lines)}\n")
                f.write(f"# Processing time: {processing_time:.2f} seconds\n")
                f.write(f"# Extraction date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Format: URL|Username|Password\n")
                f.write("#\n")
                
                # Write credentials
                for line in sorted_lines:
                    f.write(line + '\n')
        
        # Results summary
        print(f"\n" + "="*80)
        print(f"🎉 EXTRACTION COMPLETE!")
        print(f"="*80)
        print(f"📊 Processing Summary:")
        print(f"   Files processed: {total_stats['files_processed']}")
        print(f"   Files successful: {total_stats['files_success']}")
        print(f"   Files with errors: {total_stats['files_error']}")
        print(f"   Total lines processed: {total_stats['total_lines']:,}")
        print(f"   Lines matched criteria: {total_stats['total_matches']:,}")
        print(f"   Credentials extracted: {total_stats['total_extracted']:,}")
        print(f"   Unique credentials: {len(unique_lines):,}")
        print(f"   Processing time: {processing_time:.2f} seconds")
        print(f"   Average speed: {total_stats['total_lines']/processing_time:.0f} lines/sec")
        
        if total_stats['platform_breakdown']:
            print(f"\n🎯 Platform Breakdown:")
            for platform, count in sorted(total_stats['platform_breakdown'].items()):
                if count > 0:
                    emoji = get_platform_emoji(platform)
                    platform_name = PLATFORM_DEFINITIONS.get(platform, {}).get('name', platform)
                    print(f"   {emoji} {platform_name}: {count} credentials")
        
        if total_stats['errors']:
            print(f"\n⚠️ Errors encountered: {len(total_stats['errors'])}")
            for error in total_stats['errors'][:5]:  # Show first 5 errors
                print(f"   • {error}")
            if len(total_stats['errors']) > 5:
                print(f"   ... and {len(total_stats['errors']) - 5} more (check logs)")
        
        print(f"\n📁 Output saved to: {os.path.abspath(output_file_path)}")
        
        # Save detailed statistics
        stats_file = os.path.join(args.output, f"extraction_stats_{INSTANCE_ID}.json")
        with open(stats_file, 'w') as f:
            json.dump({
                'summary': total_stats,
                'configuration': {
                    'platform_type': platform_type,
                    'keywords': keywords,
                    'input_directory': input_dir,
                    'output_directory': args.output,
                    'parsers_used': len(parsers)
                },
                'execution': {
                    'start_time': start_time,
                    'end_time': end_time,
                    'duration_seconds': processing_time,
                    'instance_id': INSTANCE_ID,
                    'version': APP_VERSION
                }
            }, f, indent=2)
        
        print(f"📈 Detailed statistics: {os.path.abspath(stats_file)}")
        
        if total_stats['total_extracted'] > 0:
            print(f"\n✅ SUCCESS: {len(unique_lines)} unique credentials extracted!")
        else:
            print(f"\n⚠️ No credentials found matching the specified criteria.")
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️ Process interrupted by user")
        logging.warning("Process interrupted by user")
        return 1
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        print(f"\n❌ {error_msg}")
        logging.error(error_msg, exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())