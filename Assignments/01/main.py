import socket
import os
import sys
import time

MAX_PROCESSES = 100
active_children = 0
request_count = 0

def remove_childrens():
    global active_children
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
            print(f"REAPER: Child {pid} has been collected | Active: {active_children - 1}")
            active_children -= 1
        except ChildProcessError:
            break

def send_error(client: socket.socket, message, code):
    print(f"ERROR: Sending {code} {message} to client")
    res = f'HTTP/1.0 {code} {message}\r\n'
    res += "Content-Type: text/html\r\n\r\n"
    res += f"<html><body><h1>{code} {message}</h1></body></html>"

    client.sendall(res.encode())

def parse_request(req):
    try:
        lines = req.split('\r\n')
        req_line = lines[0]
        method, url, version = req_line.split()

        # print(f"Method: {method}, Url: {url}, Version: {version}")

        if version != 'HTTP/1.0' and version != 'HTTP/1.1':
            print(f"PARSE: Unsupported HTTP version: {version}")
            return None, None, None, "400"

        if method == 'CONNECT':
            return None, None, None, "CONNECT"

        if method != 'GET':
            print(f"PARSE: Unsupported method: {method} (only GET allowed)")
            return None, None, None, "501"
        
        if not url.startswith("http://"):
            return None, None, None, "400"
        
        url = url[7:]

        if "/" in url:
            host_part, path = url.split('/', 1)
            path = '/' + path
        else:
            host_part = url
            path = '/'
        
        if ":" in host_part:
            host, port = host_part.split(':')
            port = int(port)
        else:
            host = host_part
            port = 80
        
        return host, port, path, None
    except:
        return None, None, None, "400"
    
def handle_client(client: socket.socket):
    try:
        start_time = time.time()
        req = client.recv(4096).decode()

        if not req:
            print(f"CHILD: {os.getpid()} Empty request received, dropping")
            client.close()
            return

        print(f"CHILD: {os.getpid()} Received {len(req)} bytes from client")
        host, port, path, error_code = parse_request(req)

        if error_code == "CONNECT":
            client.close()
            return

        if error_code == "400":
            send_error(client, "Bad Request", "400")
            client.close()
            return
        
        if error_code == "501":
            send_error(client, "Not Implemented", "501")
            client.close()
            return
        
        print(f"CHILD {os.getpid()}: Connecting to {host}:{port}...")
        remote_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_server.connect((host, port))
        print(f"CHILD {os.getpid()}: Connected! Forwarding: GET {path}")

        new_req = f"GET {path} HTTP/1.0\r\n"
        new_req += f"Host: {host}\r\n"
        new_req += "\r\n"

        remote_server.sendall(new_req.encode())

        total_bytes = 0
        chunks = 0
        while True:
            data = remote_server.recv(4096)
            if not data:
                break
            total_bytes += len(data)
            chunks += 1
            client.sendall(data)
        
        elapsed = time.time() - start_time
        speed = total_bytes / elapsed if elapsed > 0 else 0
        print(f"CHILD {os.getpid()}: Done! {total_bytes} bytes in {chunks} chunks | {elapsed:.3f}s | {speed/1024:.1f} KB/s")
        
        remote_server.close()
        client.close()
    except Exception as e:
        print(f"CHILD {os.getpid()}: Error: {e}")
        client.close()


def main():
    global active_children, request_count

    if len(sys.argv) != 2:
        print("Usage: python proxy.py <port>")
        sys.exit(1)

    port = int(sys.argv[1])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", port))
    server.listen(5)

    print(f"Running on port {port}...")

    while True:
        remove_childrens()

        client, addr = server.accept()
        request_count += 1

        print(f"\n{'='*50}")
        print(f"REQUEST #{request_count}: New connection from {addr[0]}:{addr[1]}")

        if active_children >= MAX_PROCESSES:
            print(f"OVERLOAD: {active_children}/{MAX_PROCESSES} processes — rejecting!")
            send_error(client, "Service Unavailable", "503")
            client.close()
            return
        
        pid = os.fork()

        if pid == 0:
            server.close()
            handle_client(client)
            os._exit(0)
        else:
            client.close()
            active_children += 1
            print(f"FORK: Spawned child {pid} | Active: {active_children}/{MAX_PROCESSES}")

if __name__ == "__main__":
    main()