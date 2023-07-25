import ctypes
import os
import time
import requests
import hashlib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pefile
import sys
import subprocess
import psutil
import pymem


#API KEY VIRUSTOTAL
API_KEY = '9b0420a6d701b2c5d987a2117c3041527466ef0396a2b3517a3440ee6c04916a'
# Define the known malicious APIs
MALICIOUS_APIS = ['CreateProcess', 'WriteMemory', 'VirtualAlloc']

# Define the severity levels for different types of malware
SEVERITY_LEVELS = {
    0: 'Not Malware',
    1: 'Low Severity Malware',
    2: 'Medium Severity Malware',
    3: 'High Severity Malware'
}

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return None
        elif event.event_type == 'created':
            file_path = event.src_path
            print(f'New file added: {file_path}')
            is_malware, severity = check_virustotal(file_path)
            if is_malware:
                print(f'{file_path} is malware with severity {severity}! via virustotal')
                os.remove (file_path)
            else:
                print(f'{file_path} is clean! via virustotal')

            static_malware = static_malware_check(file_path)
            if static_malware:
                print(f'{file_path} is a malware! via static analysis')
                os.remove (file_path)
            else:
                print(f'{file_path} is clean! via static analysis')
            dynamic_malware = dynamic_malware_check(file_path)
            print(f'{file_path} checked it is {dynamic_malware}! via dynamic analysis')
            if dynamic_malware != "Not Malware":
                print(f'{file_path} is a malware! via dynamic analysis') 
                os.remove (file_path)


def check_virustotal(file_path):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            if positives > 0:
                severity = get_severity(json_response)
                return True, severity
    return False, None

def get_severity(json_response):
    engines = json_response['scans']
    detections = [engine for engine in engines if engines[engine]['detected']]
    num_detections = len(detections)
    if num_detections == 0:
        return 'Unknown'
    elif num_detections < 3:
        return 'Low'
    elif num_detections < 10:
        return 'Medium'
    else:
        return 'High'
    
def static_malware_check(file_path):
    # Load the PE file
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        # The file is not a valid PE file
        return False

    # Check if the file is marked as a DLL or an EXE
    if (pe.FILE_HEADER.Characteristics & 0x2000) or \
        (pe.FILE_HEADER.Characteristics & 0x0002):
        # Check if the file has a debug directory
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            return True
        # Check if the file imports any suspicious APIs
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if 'kernel32.dll' in entry.dll.lower():
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.lower()
                        if 'createprocess' in api_name or \
                           'writememory' in api_name or \
                           'virtualalloc' in api_name:
                            return True
        # Check if the file contains suspicious resources
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name:
                if 'string' in resource_type.name.lower():
                    return True
            for resource in resource_type.directory.entries:
                if resource.name:
                    if 'config' in resource.name.lower() or \
                       'setup' in resource.name.lower() or \
                       'install' in resource.name.lower():
                        return True
    return False

# Define a function to monitor API calls during execution
def check_api_calls(dbg, args):
    # Get the API name from the stack
    api_name = args[0]
    # Check if the API is known to be malicious
    if api_name in MALICIOUS_APIS:
        # If the API is malicious, increase the severity level
        global severity_level
        severity_level += 1

# Define the main function to perform dynamic analysis
def dynamic_malware_check(file_path):
    # Execute the file and monitor its behavior
    process = subprocess.Popen([file_path])
    pid = process.pid
    p = psutil.Process(pid)
    mem = pymem.Pymem(pid)

    # Monitor process memory and API calls
    num_suspicious_activities = 0
    for _ in range(100):
        try:
            # Check for suspicious API calls
            for call in p.connections(kind='inet'):
                if call.status == 'ESTABLISHED':
                    num_suspicious_activities += 1
                    break
            
            # Check for suspicious memory activity
            if p.status() == psutil.STATUS_RUNNING:
                mem_data = mem.read_bytes(mem.process_base.lpBaseOfDll, mem.process_base.SizeOfImage)
                if b'CreateProcess' in mem_data or \
                   b'WriteProcessMemory' in mem_data or \
                   b'VirtualAlloc' in mem_data:
                    num_suspicious_activities += 1

            # Check for suspicious memory activity
            mem_data = mem.read_bytes(mem.process_base.lpBaseOfDll, mem.process_base.SizeOfImage)
            if b'CreateProcess' in mem_data or \
               b'WriteProcessMemory' in mem_data or \
               b'VirtualAlloc' in mem_data:
                num_suspicious_activities += 1

            # If multiple suspicious activities are detected, assume the file is malware
            if num_suspicious_activities >= 2:
                return "High Severity Malware"
        except psutil.NoSuchProcess:
            # The process has terminated
            break

    # If no suspicious activities were detected, assume the file is not malware
    return "Not Malware"
    

def monitor_folder(folder):
    event_handler = NewFileHandler()
    observer = Observer()
    observer.schedule(event_handler, folder, recursive=False)
    observer.start()
    print(f'Monitoring folder {folder} for new file additions...')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Example usage
folder = '.' # current folder
monitor_folder(folder)
