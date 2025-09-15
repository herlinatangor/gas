#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Enhanced Ultra-Optimized Keyword Extractor v4.0.0
# Platform-specific credential extractor with advanced parsing and user-friendly interface
# Enhanced with dedicated platform parsers for maximum accuracy

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
from typing import Set, Dict, Any, List, Optional, Tuple
from datetime import datetime

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    from tqdm import tqdm
except ImportError:
    print("Installing required dependency: tqdm")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import tqdm

# --- CONFIGURATION ---
APP_NAME = "Enhanced Ultra-Optimized Keyword Extractor"
APP_VERSION = "4.0.0"
BASE_OUTPUT_DIR = './enhanced_output'
OUTPUT_FILE_TEMPLATE = 'extracted_lines_{instance_id}.txt'
PROCESSED_FILES_LOG_TEMPLATE = 'processed_files_{instance_id}.log'
ERROR_LOG_TEMPLATE = 'extractor_errors_{instance_id}.log'
DEFAULT_INPUT_DIR = r'./input'

# Instance identification
INSTANCE_ID = f"{socket.gethostname()}_{os.getpid()}_{uuid.uuid4().hex[:6]}"

# --- PLATFORM DEFINITIONS ---
PLATFORM_PATTERNS = {
    'wordpress': {
        'name': 'WordPress Admin',
        'keywords': ['wp-admin', 'wp-login', 'wp-content', 'wordpress'],
        'regex_patterns': [
            r'https?://[^/]+/wp-admin[/\w]*',
            r'https?://[^/]+/wp-login\.php',
            r'https?://[^/]+/wp-content[/\w]*'
        ],
        'port_indicators': [],
        'path_indicators': ['/wp-admin/', '/wp-login.php', '/wp-content/']
    },
    'joomla': {
        'name': 'Joomla Administrator',
        'keywords': ['administrator', 'joomla', 'com_admin'],
        'regex_patterns': [
            r'https?://[^/]+/administrator[/\w]*',
            r'https?://[^/]+/administrator/index\.php'
        ],
        'port_indicators': [],
        'path_indicators': ['/administrator/', '/administrator/index.php']
    },
    'moodle': {
        'name': 'Moodle Learning Management',
        'keywords': ['moodle', 'login/index.php'],
        'regex_patterns': [
            r'https?://[^/]+/moodle[/\w]*',
            r'https?://[^/]+/login/index\.php'
        ],
        'port_indicators': [],
        'path_indicators': ['/moodle/', '/login/index.php']
    },
    'cpanel': {
        'name': 'cPanel/WHM Control Panel',
        'keywords': ['cpanel', 'whm', ':2083', ':2087', ':2082'],
        'regex_patterns': [
            r'https?://[^/]+:208[23567][/\w]*',
            r'[^/]+:208[23567]'
        ],
        'port_indicators': [':2082', ':2083', ':2086', ':2087'],
        'path_indicators': ['/cpanel', '/whm']
    },
    'plesk': {
        'name': 'Plesk Control Panel',
        'keywords': ['plesk', ':8443', ':8880'],
        'regex_patterns': [
            r'https?://[^/]+:8443[/\w]*',
            r'https?://[^/]+:8880[/\w]*'
        ],
        'port_indicators': [':8443', ':8880'],
        'path_indicators': ['/login_up.php', '/admin/index.php']
    },
    'directadmin': {
        'name': 'DirectAdmin Panel',
        'keywords': ['directadmin', ':2222'],
        'regex_patterns': [
            r'https?://[^/]+:2222[/\w]*'
        ],
        'port_indicators': [':2222'],
        'path_indicators': ['/CMD_LOGIN', '/CMD_ADMIN_STATS']
    },
    'ssh': {
        'name': 'SSH Access',
        'keywords': ['ssh', ':22', 'ssh://'],
        'regex_patterns': [
            r'ssh://[^/\s]+',
            r'[^/\s]+:22\b'
        ],
        'port_indicators': [':22'],
        'path_indicators': []
    },
    'ftp': {
        'name': 'FTP Access',
        'keywords': ['ftp', ':21', 'ftp://'],
        'regex_patterns': [
            r'ftp://[^/\s]+',
            r'[^/\s]+:21\b'
        ],
        'port_indicators': [':21'],
        'path_indicators': []
    },
    'database': {
        'name': 'Database Access',
        'keywords': ['mysql', 'postgresql', 'phpmyadmin', ':3306', ':5432'],
        'regex_patterns': [
            r'https?://[^/]+/phpmyadmin[/\w]*',
            r'[^/\s]+:3306\b',
            r'[^/\s]+:5432\b'
        ],
        'port_indicators': [':3306', ':5432'],
        'path_indicators': ['/phpmyadmin']
    }
}

# --- ENHANCED LOGGING ---
class TqdmLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        self.stream = sys.stdout

    def emit(self, record):
        if 'tqdm' in sys.modules and hasattr(tqdm, 'write') and self.stream.isatty():
            try:
                msg = self.format(record)
                tqdm.write(msg, file=self.stream)
                self.flush()
            except Exception:
                self.stream.write(self.format(record) + '\n')
                self.stream.flush()
        else:
            self.stream.write(self.format(record) + '\n')
            self.stream.flush()

    def flush(self):
        if hasattr(self.stream, 'flush'):
            self.stream.flush()

def setup_logging(output_dir: str, error_log_file: str, level=logging.INFO):
    os.makedirs(output_dir, exist_ok=True)
    log_formatter = logging.Formatter(
        f'%(asctime)s [%(levelname)-8s] [Instance: {INSTANCE_ID[:8]}] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    if root_logger.hasHandlers():
        for handler in list(root_logger.handlers):
            try:
                handler.close()
            except:
                pass
            root_logger.removeHandler(handler)

    # Error file handler
    try:
        error_file_path = os.path.join(output_dir, error_log_file)
        error_handler = logging.FileHandler(error_file_path, mode='a', encoding='utf-8')
        error_handler.setFormatter(log_formatter)
        error_handler.setLevel(logging.ERROR)
        root_logger.addHandler(error_handler)
    except Exception as e:
        logging.error(f"Failed to create error log file handler: {e}")

    # Console handler
    if sys.stdout.isatty():
        console_handler = TqdmLoggingHandler()
        console_handler.setFormatter(log_formatter)
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(log_formatter)
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)

    logging.info(f"{APP_NAME} v{APP_VERSION} - Started")
    logging.info(f"Instance ID: {INSTANCE_ID}")

# --- PLATFORM-SPECIFIC PARSERS ---
class PlatformParser:
    def __init__(self, platform_config: Dict[str, Any]):
        self.config = platform_config
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                for pattern in platform_config['regex_patterns']]
    
    def matches_platform(self, line: str) -> bool:
        """Check if line matches this platform"""
        line_lower = line.lower()
        
        # Check keywords
        for keyword in self.config['keywords']:
            if keyword.lower() in line_lower:
                return True
        
        # Check regex patterns
        for pattern in self.compiled_patterns:
            if pattern.search(line):
                return True
        
        return False
    
    def extract_credentials(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Extract URL, username, password from line specific to this platform"""
        return self._enhanced_parse(line)
    
    def _enhanced_parse(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Enhanced parsing with platform-specific optimizations"""
        line_stripped = line.strip()
        if not line_stripped:
            return None
        
        # Strategy 1: Pipe separator (|)
        if '|' in line_stripped and line_stripped.count('|') >= 2:
            parts = line_stripped.split('|')
            if len(parts) >= 3:
                url_part = parts[0].strip()
                user_part = parts[1].strip()
                pass_part = parts[2].strip()
                return self._validate_and_clean(url_part, user_part, pass_part)
        
        # Strategy 2: Semicolon separator (;)
        if ';' in line_stripped and line_stripped.count(';') >= 2:
            parts = line_stripped.split(';')
            if len(parts) >= 3:
                url_part = parts[0].strip()
                user_part = parts[1].strip()
                pass_part = parts[2].strip()
                return self._validate_and_clean(url_part, user_part, pass_part)
        
        # Strategy 3: Colon separator (:) - enhanced for platform
        if ':' in line_stripped and line_stripped.count(':') >= 2:
            result = self._parse_colon_format(line_stripped)
            if result:
                return result
        
        # Strategy 4: Comma separator (,)
        if ',' in line_stripped and line_stripped.count(',') >= 2:
            parts = line_stripped.split(',')
            if len(parts) >= 3:
                url_part = parts[0].strip()
                user_part = parts[1].strip()
                pass_part = parts[2].strip()
                return self._validate_and_clean(url_part, user_part, pass_part)
        
        # Strategy 5: Space-separated format - platform aware
        if ' ' in line_stripped:
            result = self._parse_space_format(line_stripped)
            if result:
                return result
        
        return None
    
    def _parse_colon_format(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parse colon-separated format with platform awareness"""
        # Handle URLs with ports first
        if any(port in line for port in self.config.get('port_indicators', [])):
            # Find rightmost colons for user:pass
            last_colon = line.rfind(':')
            if last_colon != -1:
                pass_candidate = line[last_colon + 1:].strip()
                remaining = line[:last_colon]
                
                # Find second-to-last colon
                second_last_colon = remaining.rfind(':')
                if second_last_colon != -1:
                    # Check if this is a port number
                    potential_port = remaining[second_last_colon + 1:].strip()
                    if potential_port.isdigit():
                        # This is likely URL:PORT, need to find user before it
                        user_start = remaining.rfind(':', 0, second_last_colon)
                        if user_start != -1:
                            url_part = remaining[:user_start].strip()
                            user_part = remaining[user_start + 1:second_last_colon].strip()
                            return self._validate_and_clean(url_part + ':' + potential_port, user_part, pass_candidate)
                        else:
                            # Format: URL:PORT:USER:PASS
                            user_part = remaining[:second_last_colon].strip()
                            return self._validate_and_clean('', user_part, pass_candidate)
                    else:
                        # Regular URL:USER:PASS
                        url_part = remaining[:second_last_colon].strip()
                        user_part = remaining[second_last_colon + 1:].strip()
                        return self._validate_and_clean(url_part, user_part, pass_candidate)
        
        # Standard colon parsing
        parts = line.split(':')
        if len(parts) >= 3:
            # Try different combinations based on platform
            if len(parts) == 3:
                return self._validate_and_clean(parts[0].strip(), parts[1].strip(), parts[2].strip())
            elif len(parts) > 3:
                # Rejoin URL part if it contains protocol
                if parts[0].lower() in ['http', 'https', 'ftp', 'ssh']:
                    url_part = ':'.join(parts[:2])  # http:://domain or https://domain
                    if len(parts) >= 4:
                        return self._validate_and_clean(url_part, parts[2].strip(), parts[3].strip())
                else:
                    # Take last two as user:pass
                    url_part = ':'.join(parts[:-2])
                    return self._validate_and_clean(url_part, parts[-2].strip(), parts[-1].strip())
        
        return None
    
    def _parse_space_format(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parse space-separated format with platform intelligence"""
        parts = line.split()
        if len(parts) < 3:
            return None
        
        # Platform-specific parsing
        url_candidates = []
        user_candidates = []
        pass_candidates = []
        
        for part in parts:
            # URL detection
            if any(indicator in part.lower() for indicator in ['http', 'www.', '.com', '.org', '.net']):
                url_candidates.append(part)
            elif any(port in part for port in self.config.get('port_indicators', [])):
                url_candidates.append(part)
            elif any(path in part for path in self.config.get('path_indicators', [])):
                url_candidates.append(part)
            # Email-like usernames
            elif '@' in part and '.' in part:
                user_candidates.append(part)
            # Potential usernames (common patterns)
            elif any(keyword in part.lower() for keyword in ['admin', 'user', 'root']):
                user_candidates.append(part)
            else:
                pass_candidates.append(part)
        
        # Try to match intelligently
        if url_candidates and user_candidates and pass_candidates:
            return self._validate_and_clean(url_candidates[0], user_candidates[0], pass_candidates[0])
        elif len(parts) == 3:
            # Default assignment
            return self._validate_and_clean(parts[0], parts[1], parts[2])
        elif len(parts) > 3:
            # Take first as URL, last two as user:pass
            return self._validate_and_clean(parts[0], parts[-2], parts[-1])
        
        return None
    
    def _validate_and_clean(self, url: str, username: str, password: str) -> Optional[Tuple[str, str, str]]:
        """Validate and clean extracted components"""
        # Clean up components
        url = url.strip()
        username = username.strip()
        password = password.strip()
        
        # Basic validation
        if not username or not password:
            return None
        
        if len(username) < 3 or len(password) < 3:
            return None
        
        # Skip obvious placeholders
        invalid_passwords = ['password', 'pass', '123456', '12345', 'admin', '[unk]', '[n/a]']
        if password.lower() in invalid_passwords:
            return None
        
        # URL cleaning
        if url:
            # Remove extra protocols or malformed parts
            url = re.sub(r'^https?://', '', url)
            url = re.sub(r'^http://', '', url)
            if not url.startswith('http'):
                if any(port in url for port in [':80', ':443', ':8080', ':8443']):
                    url = 'https://' + url
                elif any(port in url for port in [':21', ':22']):
                    # Keep as is for FTP/SSH
                    pass
                else:
                    url = 'https://' + url
        
        return (url, username, password)

# --- ENHANCED USER INTERFACE ---
def show_platform_menu() -> str:
    """Display platform selection menu"""
    print("\n" + "="*60)
    print(f"🚀 {APP_NAME} v{APP_VERSION}")
    print("="*60)
    print("\n📋 PLATFORM SELECTION:")
    print("1. All Platforms (Auto-detect)")
    print("2. WordPress Admin Panels")
    print("3. Joomla Administrator")
    print("4. Moodle LMS")
    print("5. cPanel/WHM Control Panels")
    print("6. Plesk Control Panels")
    print("7. DirectAdmin Panels")
    print("8. SSH Access")
    print("9. FTP Access")
    print("10. Database Access (MySQL/PostgreSQL)")
    print("11. Custom Keywords")
    print("12. Custom Regex Patterns")
    
    while True:
        try:
            choice = input("\n🎯 Select platform (1-12): ").strip()
            if choice in [str(i) for i in range(1, 13)]:
                return choice
            else:
                print("❌ Invalid choice. Please enter 1-12.")
        except (EOFError, KeyboardInterrupt):
            print("\n\n⚠️ Operation cancelled.")
            sys.exit(0)

def get_platform_config(choice: str) -> Tuple[List[str], Optional[str]]:
    """Get platform configuration based on user choice"""
    platform_map = {
        '2': 'wordpress',
        '3': 'joomla',
        '4': 'moodle',
        '5': 'cpanel',
        '6': 'plesk',
        '7': 'directadmin',
        '8': 'ssh',
        '9': 'ftp',
        '10': 'database'
    }
    
    if choice == '1':
        # All platforms
        all_keywords = []
        for platform_config in PLATFORM_PATTERNS.values():
            all_keywords.extend(platform_config['keywords'])
        return list(set(all_keywords)), 'all'
    
    elif choice in platform_map:
        platform_key = platform_map[choice]
        return PLATFORM_PATTERNS[platform_key]['keywords'], platform_key
    
    elif choice == '11':
        # Custom keywords
        keywords_input = input("🔤 Enter custom keywords (comma-separated): ").strip()
        if keywords_input:
            return [k.strip() for k in keywords_input.split(',') if k.strip()], 'custom'
        else:
            print("❌ No keywords provided.")
            return [], None
    
    elif choice == '12':
        # Custom regex
        print("🔧 Custom regex mode selected.")
        regex_input = input("📝 Enter regex patterns (comma-separated): ").strip()
        if regex_input:
            return [p.strip() for p in regex_input.split(',') if p.strip()], 'regex'
        else:
            print("❌ No regex patterns provided.")
            return [], None
    
    return [], None

# --- ENHANCED PROCESSING FUNCTIONS ---
def enhanced_process_file(
    file_path: str,
    platform_parsers: List[PlatformParser],
    keywords: List[str],
    output_file,
    unique_lines: Set[str],
    progress_bar: Optional[tqdm] = None
) -> int:
    """Enhanced file processing with platform-specific parsers"""
    
    added_count = 0
    lines_processed = 0
    
    try:
        # Detect encoding
        encoding = detect_encoding(file_path)
        file_size = os.path.getsize(file_path)
        
        if progress_bar:
            progress_bar.reset(total=file_size)
            progress_bar.set_description(f"Processing {os.path.basename(file_path)}")
        
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            for line in f:
                lines_processed += 1
                if progress_bar and lines_processed % 1000 == 0:
                    progress_bar.update(len(line.encode(encoding, errors='replace')))
                
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith('#'):
                    continue
                
                # Keyword filtering (if specified)
                if keywords:
                    line_lower = line_stripped.lower()
                    if not any(keyword.lower() in line_lower for keyword in keywords):
                        continue
                
                # Try platform-specific parsers
                result = None
                for parser in platform_parsers:
                    if parser.matches_platform(line_stripped):
                        result = parser.extract_credentials(line_stripped)
                        if result:
                            break
                
                # If no platform parser worked, try generic parsing
                if not result and not platform_parsers:
                    result = generic_parse(line_stripped)
                
                if result:
                    url, username, password = result
                    output_line = f"{url}|{username}|{password}"
                    
                    if output_line not in unique_lines:
                        unique_lines.add(output_line)
                        output_file.write(output_line + '\n')
                        output_file.flush()
                        added_count += 1
        
        if progress_bar:
            progress_bar.update(progress_bar.total - progress_bar.n)
            progress_bar.set_postfix_str(f"Added: {added_count}")
            
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return -1
    
    return added_count

def detect_encoding(file_path: str) -> str:
    """Detect file encoding"""
    try:
        with open(file_path, 'rb') as f:
            raw = f.read(4096)
            
            # Check for BOMs
            if raw.startswith(b'\xef\xbb\xbf'):
                return 'utf-8-sig'
            if raw.startswith(b'\xff\xfe'):
                return 'utf-16-le'
            if raw.startswith(b'\xfe\xff'):
                return 'utf-16-be'
            
            # Try UTF-8
            try:
                raw.decode('utf-8')
                return 'utf-8'
            except UnicodeDecodeError:
                return 'latin-1'
    except Exception:
        return 'utf-8'

def generic_parse(line: str) -> Optional[Tuple[str, str, str]]:
    """Generic parsing fallback"""
    line = line.strip()
    
    # Try different separators
    for separator in ['|', ';', ':', ',']:
        if separator in line and line.count(separator) >= 2:
            parts = line.split(separator)
            if len(parts) >= 3:
                url = parts[0].strip()
                user = parts[1].strip()
                password = parts[2].strip()
                
                if len(user) >= 3 and len(password) >= 3:
                    return (url, user, password)
    
    # Try space-separated
    parts = line.split()
    if len(parts) >= 3:
        return (parts[0], parts[1], parts[2])
    
    return None

# --- MAIN ENHANCED FUNCTION ---
def main():
    """Enhanced main function with improved user interface"""
    
    # Setup
    output_dir = os.path.join(os.getcwd(), BASE_OUTPUT_DIR)
    error_log_file = ERROR_LOG_TEMPLATE.format(instance_id=INSTANCE_ID)
    setup_logging(output_dir, error_log_file, logging.INFO)
    
    # User interface
    platform_choice = show_platform_menu()
    keywords, platform_type = get_platform_config(platform_choice)
    
    if not keywords and platform_type != 'regex':
        print("❌ No valid configuration selected. Exiting.")
        return 1
    
    # Input directory
    input_dir = input(f"\n📁 Input directory (default: {DEFAULT_INPUT_DIR}): ").strip()
    if not input_dir:
        input_dir = DEFAULT_INPUT_DIR
    
    if not os.path.isdir(input_dir):
        print(f"❌ Directory not found: {input_dir}")
        return 1
    
    # Setup platform parsers
    platform_parsers = []
    if platform_type == 'all':
        for platform_config in PLATFORM_PATTERNS.values():
            platform_parsers.append(PlatformParser(platform_config))
    elif platform_type in PLATFORM_PATTERNS:
        platform_parsers.append(PlatformParser(PLATFORM_PATTERNS[platform_type]))
    
    # Display configuration
    print(f"\n🔍 Configuration:")
    print(f"   Platform: {platform_type}")
    print(f"   Keywords: {', '.join(keywords) if keywords else 'None'}")
    print(f"   Input: {os.path.abspath(input_dir)}")
    print(f"   Output: {os.path.abspath(output_dir)}")
    
    # Scan for files
    txt_files = []
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.lower().endswith('.txt'):
                txt_files.append(os.path.join(root, file))
    
    if not txt_files:
        print(f"\n❌ No .txt files found in {input_dir}")
        return 1
    
    print(f"\n📊 Found {len(txt_files)} .txt files to process")
    
    # Processing
    output_file_path = os.path.join(output_dir, OUTPUT_FILE_TEMPLATE.format(instance_id=INSTANCE_ID))
    os.makedirs(output_dir, exist_ok=True)
    
    unique_lines = set()
    total_added = 0
    
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        with tqdm(total=len(txt_files), desc="Processing files", unit="file") as pbar_files:
            with tqdm(total=100, desc="Current file", unit="line", position=1, leave=False) as pbar_current:
                
                for file_path in txt_files:
                    logging.info(f"Processing: {os.path.basename(file_path)}")
                    
                    added = enhanced_process_file(
                        file_path=file_path,
                        platform_parsers=platform_parsers,
                        keywords=keywords,
                        output_file=output_file,
                        unique_lines=unique_lines,
                        progress_bar=pbar_current
                    )
                    
                    if added > 0:
                        total_added += added
                        logging.info(f"Extracted {added} credentials from {os.path.basename(file_path)}")
                    
                    pbar_files.update(1)
                    pbar_files.set_postfix_str(f"Total extracted: {total_added}")
    
    # Results
    print(f"\n🎉 PROCESSING COMPLETE!")
    print(f"📊 Results:")
    print(f"   Files processed: {len(txt_files)}")
    print(f"   Total credentials extracted: {total_added}")
    print(f"   Unique credentials: {len(unique_lines)}")
    print(f"   Output saved to: {output_file_path}")
    
    # Sort and deduplicate final output
    if total_added > 0:
        sorted_lines = sorted(list(unique_lines))
        with open(output_file_path, 'w', encoding='utf-8') as f:
            for line in sorted_lines:
                f.write(line + '\n')
        print(f"✅ Output file sorted and deduplicated")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)