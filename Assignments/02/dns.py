import socket
import threading
from collections import OrderedDict
from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, MX, NS, QTYPE, RR

class DNSServer:
    def __init__(self, ip, port, name="Server"):
        self.ip = ip
        self.port = port
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))
        print(f"{self.name} running on {self.ip}:{self.port}")

    def start(self):
        while True:
            data, addr = self.sock.recvfrom(4096)

            try:
                request = DNSRecord.parse(data)
            except Exception:
                continue

            domain = str(request.q.qname).rstrip(".")
            qtype = QTYPE.get(request.q.qtype, "A")
            recursive = bool(request.header.rd)

            print(
                f"{self.name} received query for {domain} from {addr} "
                f"(recursive={recursive})"
            )
            response = self.handle_query(
                domain,
                qtype=qtype,
                recursive=recursive,
                request=request,
            )
            self.sock.sendto(response.pack(), addr)

    def handle_query(self, domain, qtype="A", recursive=False, request=None):
        return request.reply() if request else DNSRecord()
    
class AuthoritativeServer(DNSServer):
    DNS_RECORDS = {
        "google.com": { 
            "A": ["64.233.187.99", "72.14.207.99", "64.233.167.99"],
            "NS": ["ns1.google.com", "ns2.google.com"],
            "MX": ["smtp1.google.com", "smtp2.google.com"]
        },
        "example.com": {
            "A": ["93.184.216.34"],
            "NS": ["ns1.example.com"],
            "MX": ["mail.example.com"]
        }
    }

    def handle_query(self, domain, qtype="A", recursive=False, request=None):
        # recursive flag ignored here, authoritative server always answers from local data
        reply = request.reply()
        records = self.DNS_RECORDS.get(domain, {})

        if not records:
            reply.header.rcode = 3  # NXDOMAIN
            return reply

        domain_fqdn = f"{domain}."
        qtype = qtype.upper()

        def include_type(rtype):
            return qtype in ("ANY", rtype)

        if include_type("A"):
            for ip in records.get("A", []):
                reply.add_answer(RR(domain_fqdn, QTYPE.A, rdata=A(ip), ttl=60))

        if include_type("NS"):
            for ns in records.get("NS", []):
                reply.add_answer(RR(domain_fqdn, QTYPE.NS, rdata=NS(f"{ns}."), ttl=60))

        if include_type("MX"):
            for mx in records.get("MX", []):
                reply.add_answer(RR(domain_fqdn, QTYPE.MX, rdata=MX(f"{mx}."), ttl=60))

        return reply
    
class TLDServer(DNSServer):
    TLD_MAPPING = {
        ".com": {
            "host": "ns1.google.com.",
            "ip": "127.0.0.1",
            "port": 5303,
        }
    }

    def handle_query(self, domain, qtype="A", recursive=False, request=None):
        tld = "." + domain.split(".")[-1]
        next_server = self.TLD_MAPPING.get(tld, None)
        if recursive and next_server:
            # Query Authoritative server internally
            auth_ip, auth_port = next_server["ip"], next_server["port"]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(request.pack(), (auth_ip, auth_port))
            data, _ = sock.recvfrom(4096)
            return DNSRecord.parse(data)
        else:
            reply = request.reply()
            if not next_server:
                reply.header.rcode = 3
                return reply

            # Iterative mode: return referral (NS + glue A)
            referral_host = next_server["host"]
            zone = f"{tld.lstrip('.')}."
            reply.add_auth(RR(zone, QTYPE.NS, rdata=NS(referral_host), ttl=60))
            reply.add_ar(RR(referral_host, QTYPE.A, rdata=A(next_server["ip"]), ttl=60))
            return reply
        
class RootServer(DNSServer):
    ROOT_MAPPING = {
        ".com": {
            "host": "a.gtld-servers.local.",
            "ip": "127.0.0.1",
            "port": 5302,
        }
    }

    def handle_query(self, domain, qtype="A", recursive=False, request=None):
        tld = "." + domain.split(".")[-1]
        next_server = self.ROOT_MAPPING.get(tld, None)
        if recursive and next_server:
            # query TLD server by the root server
            tld_ip, tld_port = next_server["ip"], next_server["port"]
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(request.pack(), (tld_ip, tld_port))
            data, _ = sock.recvfrom(4096)
            return DNSRecord.parse(data)
        else:
            reply = request.reply()
            if not next_server:
                reply.header.rcode = 3
                return reply

            # Iterative mode: return referral (NS + glue A)
            referral_host = next_server["host"]
            zone = f"{tld.lstrip('.')}."
            reply.add_auth(RR(zone, QTYPE.NS, rdata=NS(referral_host), ttl=60))
            reply.add_ar(RR(referral_host, QTYPE.A, rdata=A(next_server["ip"]), ttl=60))
            return reply

class DNSClient:
    def __init__(self, root_addr=("127.0.0.1", 5301), max_cache_size=5):
        self.root_addr = root_addr
        self.cache = OrderedDict()
        self.max_cache_size = max_cache_size
        self.ns_port_map = {
            "a.gtld-servers.local": 5302,
            "ns1.google.com": 5303,
            "ns1.example.com": 5303,
        }

    def query_server(self, domain, server_addr, recursive=False, qtype="ANY"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = DNSRecord(
            DNSHeader(rd=1 if recursive else 0),
            q=DNSQuestion(domain, getattr(QTYPE, qtype, QTYPE.A)),
        )
        sock.sendto(request.pack(), server_addr)
        data, _ = sock.recvfrom(4096)
        return DNSRecord.parse(data)

    def _extract_records(self, response):
        records = {"A": [], "NS": [], "MX": []}
        for rr in response.rr:
            rtype = QTYPE.get(rr.rtype)
            if rtype == "A":
                records["A"].append(str(rr.rdata))
            elif rtype == "NS":
                records["NS"].append(str(rr.rdata).rstrip("."))
            elif rtype == "MX":
                # dnslib MX prints like "10 mail.example.com."
                exchange = str(rr.rdata).split()[-1].rstrip(".")
                records["MX"].append(exchange)
        return records

    def _next_server_from_referral(self, response):
        ns_name = None
        ns_ip = None

        for rr in response.auth:
            if QTYPE.get(rr.rtype) == "NS":
                ns_name = str(rr.rdata).rstrip(".")
                break

        if ns_name:
            for rr in response.ar:
                if QTYPE.get(rr.rtype) == "A" and str(rr.rname).rstrip(".") == ns_name:
                    ns_ip = str(rr.rdata)
                    break

        if ns_name and ns_ip:
            port = self.ns_port_map.get(ns_name)
            if port:
                return (ns_ip, port)
        return None

    def resolve(self, domain, iterative=True):
        # check inside cache
        if domain in self.cache:
            print("Cache HIT")
            # move this domain to the end to mark it as recently used
            self.cache.move_to_end(domain)
            return self.cache[domain]

        print("Cache MISS")

        # iterative resolution
        if iterative:
            root_resp = self.query_server(domain, self.root_addr, recursive=False)
            tld_addr = self._next_server_from_referral(root_resp)
            if not tld_addr:
                return {}

            tld_resp = self.query_server(domain, tld_addr, recursive=False)
            auth_addr = self._next_server_from_referral(tld_resp)
            if not auth_addr:
                return self._extract_records(tld_resp)

            final_resp = self.query_server(domain, auth_addr, recursive=False)
            records = self._extract_records(final_resp)
        else:
            # recursive resolution
            response = self.query_server(domain, self.root_addr, recursive=True)
            records = self._extract_records(response)

        # cache flushing when chace is full
        if len(self.cache) >= self.max_cache_size:
            oldest = next(iter(self.cache))
            print(f"Cache full. Flushing oldest entry: {oldest}")
            self.cache.popitem(last=False)  # remove the oldest item

        # store a new record in cache
        self.cache[domain] = records
        return records

root = RootServer("127.0.0.1", 5301, "Root Server")
tld = TLDServer("127.0.0.1", 5302, "TLD Server")
auth = AuthoritativeServer("127.0.0.1", 5303, "Authoritative Server")

threading.Thread(target=root.start, daemon=True).start()
threading.Thread(target=tld.start, daemon=True).start()
threading.Thread(target=auth.start, daemon=True).start()

client = DNSClient()
while True:
    domain = input("\nEnter domain to resolve: ")
    mode = input("Choose mode: iterative / recursive: ").strip().lower()
    iterative = True if mode == "iterative" else False
    result = client.resolve(domain, iterative=iterative)

    if not isinstance(result, dict):
        print("\nResolution failed. No DNS records were found.")
        continue

    print("\n-- DNS INFORMATION --")
    print("A:", ", ".join(result.get("A", [])))
    print("NS:", ", ".join(result.get("NS", [])))
    print("MX:", ", ".join(result.get("MX", [])))