#!/usr/bin/python3
import os
import sys
import time
import random
import string
import subprocess
import hashlib
from pathlib import Path

def create_test_file(filename, size_kb=100):
    """Create a test file with random content"""
    content = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
    with open(filename, 'w') as f:
        f.write(content)
    return filename

def get_file_hash(filename):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)
    return sha256.hexdigest()

def run_server(interface):
    """Run the server in background"""
    return subprocess.Popen(['./server', interface])

def run_client(interface, command, filename):
    """Run client command and return exit code"""
    proc = subprocess.run(['./client', interface, command, filename], 
                         capture_output=True, text=True)
    print(f"Client output: {proc.stdout}")
    print(f"Client error: {proc.stderr}")
    return proc.returncode

def cleanup():
    """Clean up test files and backup directory"""
    for f in Path('.').glob('test_*'):
        f.unlink()
    for f in Path('backup').glob('*'):
        f.unlink()

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    test_files = []
    
    # Clean up before tests
    cleanup()
    
    try:
        # Start server
        server = run_server(interface)
        time.sleep(1)  # Wait for server to start
        
        print("Running backup tests...")
        
        # Test 1: Backup and restore small file
        print("\nTest 1: Small file backup/restore")
        test_file = create_test_file('test_small.txt', size_kb=1)
        original_hash = get_file_hash(test_file)
        
        assert run_client(interface, 'backup', test_file) == 0
        os.rename(test_file, f"{test_file}.original")
        assert run_client(interface, 'restaura', test_file) == 0
        restored_hash = get_file_hash(test_file)
        
        assert original_hash == restored_hash, "File content mismatch!"
        print("Test 1 passed!")
        
        # Test 2: Verify file exists
        print("\nTest 2: File verification")
        assert run_client(interface, 'verifica', test_file) == 0
        print("Test 2 passed!")
        
        # Test 3: Verify non-existent file
        print("\nTest 3: Non-existent file verification")
        assert run_client(interface, 'verifica', 'nonexistent.txt') != 0
        print("Test 3 passed!")
        
        # Test 4: Large file backup/restore
        print("\nTest 4: Large file backup/restore")
        test_file = create_test_file('test_large.txt', size_kb=1024)
        original_hash = get_file_hash(test_file)
        
        assert run_client(interface, 'backup', test_file) == 0
        os.rename(test_file, f"{test_file}.original")
        assert run_client(interface, 'restaura', test_file) == 0
        restored_hash = get_file_hash(test_file)
        
        assert original_hash == restored_hash, "File content mismatch!"
        print("Test 4 passed!")
        
        print("\nAll tests passed!")
        
    except AssertionError as e:
        print(f"Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        server.terminate()
        server.wait()
        cleanup()

if __name__ == '__main__':
    main()