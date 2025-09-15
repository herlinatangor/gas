#!/usr/bin/env python3
"""
Optimized version of gas.py with performance improvements
Key optimizations:
1. Vectorized parsing with compiled regex patterns
2. Optimized memory management with generators
3. Batch processing for better I/O efficiency
4. Improved validation with pre-compiled patterns
5. Real-time streaming output with better buffering
"""

import os
import re
import time
import sys
import threading
import logging
import signal
import uuid
import socket
import argparse
import errno
import json
from typing import Set, Dict, Any, List, Optional, Generator, Tuple, Iterator
from collections import deque
import mmap
import io
from contextlib import contextmanager

# Keep original imports for compatibility
try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    from tqdm import tqdm
except ImportError:
    # Fallback if tqdm not available
    class tqdm:
        def __init__(self, *args, **kwargs):
            pass
        def update(self, n=1):
            pass
        def close(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

from datetime import datetime

# --- OPTIMIZED CONFIGURATION ---
APP_NAME = "UltraOptimizedKeywordExtractor"
APP_VERSION = "4.0.0-OPTIMIZED"

# Optimized buffer sizes for better performance
OPTIMAL_BUFFER_SIZE = 8192  # 8KB buffer for file reading
BATCH_WRITE_SIZE = 1000     # Write in batches of 1000 lines
MEMORY_LIMIT_MB = 100       # Memory limit for deduplication set

# Compiled regex patterns for better performance
CREDENTIAL_PATTERNS = {
    'pipe': re.compile(r'^([^|]+)\|([^|]+)\|([^|]+)$'),
    'colon': re.compile(r'^([^:]+):([^:]+):([^:]+)$'),
    'semicolon': re.compile(r'^([^;]+);([^;]+);([^;]+)$'),
    'space': re.compile(r'^(\S+)\s+(\S+)\s+(\S+)$'),
    'username_prefix': re.compile(r'^username:([^:]+):password:([^:]+):(.+)$', re.IGNORECASE),
    'url_detection': re.compile(r'(?:https?://|www\.|\.[a-z]{2,})', re.IGNORECASE),
    'email_detection': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
}

# Validation patterns - compiled for speed
VALIDATION_PATTERNS = {
    'valid_url': re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
    'valid_user': re.compile(r'^[a-zA-Z0-9@._-]{3,}$'),
    'valid_pass': re.compile(r'^(?!.*(?:unknown|n/a|123456)).{4,}$', re.IGNORECASE),
}

class OptimizedCredentialParser:
    """Optimized credential parser with vectorized operations"""
    
    def __init__(self):
        self.patterns = CREDENTIAL_PATTERNS
        self.validation = VALIDATION_PATTERNS
        self.stats = {
            'parsed': 0,
            'validated': 0,
            'rejected': 0,
            'duplicates': 0
        }
    
    def parse_line_vectorized(self, line: str) -> Optional[Tuple[str, str, str]]:
        """Parse a single line using optimized regex patterns"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        # Try pipe format first (most common)
        match = self.patterns['pipe'].match(line)
        if match:
            return self._extract_parts(match.groups())
        
        # Try colon format with smart parsing
        if line.count(':') >= 2:
            # Handle special username:email:password:url format
            username_match = self.patterns['username_prefix'].match(line)
            if username_match:
                user, password, url = username_match.groups()
                return self._extract_parts((url, user, password))
            
            # Standard colon parsing - find rightmost separators
            parts = line.rsplit(':', 2)
            if len(parts) == 3:
                return self._extract_parts(parts)
        
        # Try semicolon format
        match = self.patterns['semicolon'].match(line)
        if match:
            return self._extract_parts(match.groups())
        
        # Try space-separated format with smart detection
        if ' ' in line:
            parts = line.split()
            if len(parts) >= 3:
                return self._parse_space_separated(parts)
        
        self.stats['rejected'] += 1
        return None
    
    def _extract_parts(self, parts: Tuple[str, str, str]) -> Optional[Tuple[str, str, str]]:
        """Extract and validate URL, username, password from parts"""
        url_part, user_part, pass_part = [p.strip() for p in parts]
        
        # Smart detection of which part is which
        if self.patterns['email_detection'].match(user_part):
            # user_part looks like email, likely correct order
            pass
        elif self.patterns['email_detection'].match(pass_part):
            # pass_part looks like email, swap with user_part
            user_part, pass_part = pass_part, user_part
        elif self.patterns['url_detection'].search(user_part):
            # user_part looks like URL, likely need to reorder
            if self.patterns['url_detection'].search(pass_part):
                # Both look like URLs, keep original order
                pass
            else:
                # Swap URL and user
                url_part, user_part = user_part, url_part
        
        self.stats['parsed'] += 1
        
        # Validate components
        if self._validate_components(url_part, user_part, pass_part):
            self.stats['validated'] += 1
            return (url_part, user_part, pass_part)
        
        self.stats['rejected'] += 1
        return None
    
    def _parse_space_separated(self, parts: List[str]) -> Optional[Tuple[str, str, str]]:
        """Parse space-separated format with intelligent ordering"""
        url_candidates = []
        email_candidates = []
        other_parts = []
        
        for part in parts:
            if self.patterns['url_detection'].search(part):
                url_candidates.append(part)
            elif self.patterns['email_detection'].match(part):
                email_candidates.append(part)
            else:
                other_parts.append(part)
        
        # Try to assign based on patterns
        if url_candidates and email_candidates and other_parts:
            return self._extract_parts((url_candidates[0], email_candidates[0], other_parts[0]))
        elif len(parts) >= 3:
            # Default assignment for 3 parts
            return self._extract_parts((parts[0], parts[1], parts[2]))
        
        return None
    
    def _validate_components(self, url: str, user: str, password: str) -> bool:
        """Validate credential components with optimized regex"""
        # Allow empty URL but require user and password
        user_valid = self.validation['valid_user'].match(user) and len(user) >= 3
        pass_valid = self.validation['valid_pass'].match(password) and len(password) >= 4
        
        return user_valid and pass_valid

class OptimizedFileProcessor:
    """Optimized file processor with memory-efficient streaming"""
    
    def __init__(self, output_dir: str, instance_id: str):
        self.output_dir = output_dir
        self.instance_id = instance_id
        self.parser = OptimizedCredentialParser()
        self.unique_lines: Set[str] = set()
        self.write_buffer: deque = deque()
        self.stats = {
            'files_processed': 0,
            'lines_read': 0,
            'lines_written': 0,
            'bytes_processed': 0
        }
        
        # Setup output file
        os.makedirs(output_dir, exist_ok=True)
        self.output_file_path = os.path.join(output_dir, f'extracted_lines_{instance_id}.txt')
        self.output_file_handle = None
    
    @contextmanager
    def _open_output_file(self):
        """Context manager for output file handling"""
        try:
            self.output_file_handle = open(self.output_file_path, 'a', encoding='utf-8', newline='\n')
            yield self.output_file_handle
        finally:
            if self.output_file_handle and not self.output_file_handle.closed:
                self.output_file_handle.close()
                self.output_file_handle = None
    
    def _should_use_mmap(self, file_path: str) -> bool:
        """Determine if memory mapping should be used for large files"""
        try:
            file_size = os.path.getsize(file_path)
            # Use mmap for files larger than 10MB
            return file_size > 10 * 1024 * 1024
        except OSError:
            return False
    
    def _process_file_mmap(self, file_path: str, keywords: List[str]) -> int:
        """Process large files using memory mapping for efficiency"""
        added_count = 0
        
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Process in chunks
                    for line_bytes in iter(mm.readline, b''):
                        try:
                            line = line_bytes.decode('utf-8', errors='replace').strip()
                        except UnicodeDecodeError:
                            continue
                        
                        if self._should_process_line(line, keywords):
                            result = self.parser.parse_line_vectorized(line)
                            if result:
                                added_count += self._add_unique_line(result)
                        
                        self.stats['lines_read'] += 1
                        self.stats['bytes_processed'] += len(line_bytes)
                        
                        # Flush buffer periodically
                        if len(self.write_buffer) >= BATCH_WRITE_SIZE:
                            self._flush_buffer()
        
        except Exception as e:
            logging.error(f"Error processing file with mmap {file_path}: {e}")
            return -1
        
        return added_count
    
    def _process_file_standard(self, file_path: str, keywords: List[str]) -> int:
        """Process files using standard I/O with optimized buffering"""
        added_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace', buffering=OPTIMAL_BUFFER_SIZE) as f:
                # Process in batches for better performance
                batch_lines = []
                batch_size = 1000
                
                for line in f:
                    line = line.strip()
                    batch_lines.append(line)
                    
                    if len(batch_lines) >= batch_size:
                        added_count += self._process_line_batch(batch_lines, keywords)
                        batch_lines.clear()
                
                # Process remaining lines
                if batch_lines:
                    added_count += self._process_line_batch(batch_lines, keywords)
        
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")
            return -1
        
        return added_count
    
    def _process_line_batch(self, lines: List[str], keywords: List[str]) -> int:
        """Process a batch of lines for better performance"""
        added_count = 0
        
        for line in lines:
            self.stats['lines_read'] += 1
            self.stats['bytes_processed'] += len(line.encode('utf-8', errors='replace'))
            
            if self._should_process_line(line, keywords):
                result = self.parser.parse_line_vectorized(line)
                if result:
                    added_count += self._add_unique_line(result)
        
        # Flush buffer if needed
        if len(self.write_buffer) >= BATCH_WRITE_SIZE:
            self._flush_buffer()
        
        return added_count
    
    def _should_process_line(self, line: str, keywords: List[str]) -> bool:
        """Optimized keyword filtering"""
        if not line or line.startswith('#'):
            return False
        
        if not keywords:
            return True
        
        # Case-insensitive keyword matching
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in keywords)
    
    def _add_unique_line(self, result: Tuple[str, str, str]) -> int:
        """Add unique line to buffer with deduplication"""
        url, user, password = result
        output_line = f"{url}|{user}|{password}"
        
        if output_line not in self.unique_lines:
            self.unique_lines.add(output_line)
            self.write_buffer.append(output_line)
            return 1
        else:
            self.parser.stats['duplicates'] += 1
            return 0
    
    def _flush_buffer(self):
        """Flush write buffer to disk"""
        if not self.write_buffer:
            return
        
        try:
            with self._open_output_file() as f:
                while self.write_buffer:
                    line = self.write_buffer.popleft()
                    f.write(line + '\n')
                    self.stats['lines_written'] += 1
                f.flush()
        except Exception as e:
            logging.error(f"Error flushing buffer: {e}")
    
    def process_file(self, file_path: str, keywords: List[str]) -> int:
        """Main file processing method with automatic optimization selection"""
        logging.info(f"Processing file: {os.path.basename(file_path)}")
        
        # Choose processing method based on file size
        if self._should_use_mmap(file_path):
            logging.debug(f"Using mmap for large file: {file_path}")
            result = self._process_file_mmap(file_path, keywords)
        else:
            logging.debug(f"Using standard I/O for file: {file_path}")
            result = self._process_file_standard(file_path, keywords)
        
        # Flush any remaining buffer
        self._flush_buffer()
        
        if result != -1:
            self.stats['files_processed'] += 1
        
        return result
    
    def finalize(self):
        """Finalize processing and cleanup"""
        # Final buffer flush
        self._flush_buffer()
        
        # Sort and deduplicate output file
        if os.path.exists(self.output_file_path):
            self._sort_and_dedupe_output()
        
        # Print statistics
        logging.info(f"Processing complete:")
        logging.info(f"  Files processed: {self.stats['files_processed']}")
        logging.info(f"  Lines read: {self.stats['lines_read']:,}")
        logging.info(f"  Lines written: {self.stats['lines_written']:,}")
        logging.info(f"  Bytes processed: {self.stats['bytes_processed']:,}")
        logging.info(f"  Parser stats: {self.parser.stats}")
    
    def _sort_and_dedupe_output(self):
        """Sort and deduplicate output file efficiently"""
        if not os.path.exists(self.output_file_path):
            return
        
        logging.info("Sorting and deduplicating output...")
        
        # Read all unique lines
        unique_lines = set()
        with open(self.output_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    unique_lines.add(line)
        
        # Write back sorted
        sorted_lines = sorted(unique_lines)
        with open(self.output_file_path, 'w', encoding='utf-8') as f:
            for line in sorted_lines:
                f.write(line + '\n')
        
        logging.info(f"Output file finalized with {len(sorted_lines):,} unique lines")

def setup_optimized_logging(output_dir: str, instance_id: str, level=logging.INFO):
    """Setup optimized logging with better performance"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format=f'%(asctime)s [%(levelname)-8s] [Instance: {instance_id[:8]}] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(os.path.join(output_dir, f'extractor_errors_{instance_id}.log')),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logging.info(f"{APP_NAME} v{APP_VERSION} - Optimized extraction started")
    logging.info(f"Instance ID: {instance_id}")

def scan_input_files(input_dir: str) -> List[str]:
    """Optimized file scanning with better error handling"""
    txt_files = []
    
    try:
        for root, dirs, files in os.walk(input_dir):
            # Sort for consistent processing order
            files.sort()
            for file_name in files:
                if file_name.lower().endswith('.txt'):
                    full_path = os.path.join(root, file_name)
                    # Skip obviously internal files
                    if not any(file_name.lower().startswith(prefix) for prefix in 
                              ['processed_files_', 'extractor_errors_', 'extracted_lines_']):
                        txt_files.append(os.path.abspath(full_path))
    
    except Exception as e:
        logging.error(f"Error scanning input directory {input_dir}: {e}")
        return []
    
    txt_files.sort()
    return txt_files

def main_optimized():
    """Optimized main function with improved performance"""
    
    # Parse arguments (simplified for optimization focus)
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--input", "-i", default="./input", help="Input directory")
    parser.add_argument("--keywords", "-k", default="", help="Keywords (comma-separated)")
    parser.add_argument("--output-dir", "-o", default="./optimized_output", help="Output directory")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    # Setup
    instance_id = f"{socket.gethostname()}_{os.getpid()}_{uuid.uuid4().hex[:6]}"
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_optimized_logging(args.output_dir, instance_id, log_level)
    
    # Process keywords
    keywords = [k.strip().lower() for k in args.keywords.split(',') if k.strip()] if args.keywords else []
    
    print(f"--- {APP_NAME} v{APP_VERSION} ---")
    print(f"Instance ID: {instance_id}")
    print(f"Keywords: {keywords if keywords else 'ALL (no filter)'}")
    
    # Scan input files
    input_files = scan_input_files(args.input)
    if not input_files:
        print(f"No .txt files found in {args.input}")
        return 1
    
    print(f"Found {len(input_files)} files to process")
    
    # Process files
    processor = OptimizedFileProcessor(args.output_dir, instance_id)
    start_time = time.time()
    
    total_added = 0
    with tqdm(total=len(input_files), desc="Processing files") as pbar:
        for file_path in input_files:
            added = processor.process_file(file_path, keywords)
            if added != -1:
                total_added += added
                pbar.set_postfix_str(f"Added: {total_added:,}")
            pbar.update(1)
    
    # Finalize
    processor.finalize()
    elapsed_time = time.time() - start_time
    
    print(f"\n--- Optimized Processing Summary ---")
    print(f"✓ Files processed: {processor.stats['files_processed']}")
    print(f"✓ Lines read: {processor.stats['lines_read']:,}")
    print(f"✓ Unique lines extracted: {processor.stats['lines_written']:,}")
    print(f"✓ Processing time: {elapsed_time:.2f}s")
    print(f"✓ Speed: {processor.stats['lines_read']/elapsed_time:.0f} lines/sec")
    print(f"📄 Output saved to: {processor.output_file_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main_optimized())