from flask import Flask, request, render_template, send_from_directory, jsonify
import socket
import threading
from queue import Queue
import nmap
import subprocess
import logging

app = Flask(__name__, static_url_path='', static_folder='static')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common ports to scan (top 1000 ports).
COMMON_PORTS = range(1, 1001)

# Number of threads for concurrent scanning.
NUM_THREADS = 50

# Create a queue to hold ports to scan.
port_queue = Queue()

# Lock to synchronize access to the queue and avoid race conditions.
queue_lock = threading.Lock()

results = []
active_tab = 1

def scan_port(target_host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            with queue_lock:
                try:
                    service = socket.getservbyport(port)
                    results.append(f"Port {port} ({service}) is open.")
                except OSError:
                    service = "Unknown"
                logging.info(f"Port {port} ({service}) is open.")
                
                banner = retrieve_banner(sock)
                if banner:
                    logging.info(f"  Banner: {banner}")
                    detect_service_version(target_host, port, banner)
        sock.close()
    except Exception as e:
        logging.error(f"Error scanning port {port}: {e}")

def retrieve_banner(sock):
    try:
        banner = sock.recv(1024).decode("utf-8").strip()
        return banner
    except Exception as e:
        logging.error(f"Error retrieving banner: {e}")
        return None

def detect_service_version(target_host, port, banner):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_host, arguments=f"-p {port}", timeout=30)
        service_info = nm[target_host]["tcp"][port]
        if "product" in service_info and "version" in service_info:
            product = service_info["product"]
            version = service_info["version"]
            logging.info(f"  Service Version: {product} {version}")
    except Exception as e:
        logging.error(f"Error detecting service version: {e}")

def run_nmap_vuln_scan(target_host):
    try:
        result = subprocess.run(["nmap", "--script", "vulners", target_host], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(result.stdout)
            index = result.stdout.find('Host is up')
            result=result.stdout[index:]
            index= result.find('Nmap')
            return result[:index]
        else:
            return "Nmap scan failed."
    except Exception as e:
        logging.error(f"Error running vulnerability scan: {e}")
        return str(e)

def caesar_cipher(text, key, operation):
    result = ""
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            result += chr((ord(char) - shift + operation * key) % 26 + shift)
        else:
            result += char
    return result

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action")
        logging.info(f"Action received: {action}")
        if action == "scan_ports":
            target_host = request.form.get("target_host")
            start_port = int(request.form.get("start_port"))
            end_port = int(request.form.get("end_port"))
            
            threads = []
            for _ in range(NUM_THREADS):
                thread = threading.Thread(target=port_scan_worker, args=(target_host,))
                thread.start()
                threads.append(thread)
            
            for port in range(start_port, end_port + 1):
                port_queue.put(port)
            
            port_queue.join()
            
            for _ in range(NUM_THREADS):                
                port_queue.put(None)
            
            for thread in threads:                
                thread.join()
                
            return render_template("index.html", results=results, active_tab=1)
        elif action == "caesar_cipher":
            text = request.form.get("text")
            key = int(request.form.get("key"))
            operation = request.form.get("operation")
            
            if operation == "encrypt":
                result = caesar_cipher(text, key, 1)
            else:
                result = caesar_cipher(text, key, -1)
            
            return render_template("index.html", result=result, active_tab=2)
        elif action == "vuln_scan":
            target_host = request.form.get("target_host")
            vuln_scan_result = run_nmap_vuln_scan(target_host)
            return render_template("index.html", results=None, result=None, vuln_scan_result=vuln_scan_result, active_tab=3)

    return render_template("index.html", results=None, result=None, vuln_scan_result=None, active_tab=1)

def port_scan_worker(target_host):
    while True:
        port = port_queue.get()
        if port is None:
            break
        scan_port(target_host, port)
        port_queue.task_done()

@app.route('/update_tab', methods=['POST'])
def update_tab():
    data = request.get_json()
    active_tab = data['active_tab_id']    

    response_data = {
        'message': 'Received active tab ID',
        'active_tab_id': active_tab
    }

    return render_template("index.html", results=None, result=None, vuln_scan_result=None, active_tab=active_tab)

if __name__ == "__main__":
    app.run()
