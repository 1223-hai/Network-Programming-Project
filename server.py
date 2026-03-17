import socket
import struct
import time

# ==============================
# CẤU HÌNH SERVER
# ==============================
PORT = 8888
GOOGLE_DNS = "8.8.8.8"
DNS_PORT = 53
BUF_SIZE = 2048

# Cache dạng:
# (domain, type) -> { ip, expire, is_nx }
dns_cache = {}


# ==============================
# HIỂN THỊ GIAO DIỆN CLI
# ==============================
def print_banner():
    print("="*55)
    print("        DNS RESOLVER SERVER (UDP)")
    print("   Hỗ trợ: A (IPv4), AAAA (IPv6)")
    print("   Lệnh: /cache để xem cache")
    print("="*55)


# ==============================
# CHUYỂN DOMAIN → DNS FORMAT
# ==============================
def format_dns_name(domain):
    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    return qname + b'\x00'


# ==============================
# BỎ QUA NAME (xử lý pointer DNS)
# ==============================
def skip_name(response, offset):
    while True:
        length = response[offset]

        if length == 0:
            return offset + 1

        elif (length & 0xC0) == 0xC0:
            return offset + 2

        else:
            offset += length + 1


# ==============================
# HIỂN THỊ CACHE
# ==============================
def handle_cache_command():
    now = time.time()
    result = "\n--- CURRENT DNS CACHE ---\n"

    if not dns_cache:
        return result + "Cache is empty.\n"

    for key, entry in list(dns_cache.items()):
        domain, rtype = key
        ttl = int(entry['expire'] - now)

        if ttl > 0:
            status = "NXDOMAIN" if entry['is_nx'] else entry['ip']
            result += f"{domain} [{rtype}] -> {status} | TTL: {ttl}s\n"
        else:
            del dns_cache[key]  # xóa cache hết hạn

    return result + "-------------------------\n"


# ==============================
# HÀM RESOLVE DNS (CORE)
# ==============================
def resolve_dns(domain, rtype="A"):
    now = time.time()
    cache_key = (domain, rtype)

    # ===== 1. KIỂM TRA CACHE =====
    if cache_key in dns_cache:
        entry = dns_cache[cache_key]

        if now < entry['expire']:
            ttl = int(entry['expire'] - now)

            if entry['is_nx']:
                return f"Error: NXDOMAIN '{domain}'\nSource: cache\nTTL: {ttl}s\n"

            return f"{domain} ({rtype}) -> {entry['ip']}\nSource: cache\nTTL: {ttl}s\n"

    # ===== 2. GỬI DNS QUERY =====
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        # Header DNS (12 byte)
        header = struct.pack("!HHHHHH",
                             1234,   # ID
                             0x0100, # Query chuẩn
                             1,      # 1 câu hỏi
                             0, 0, 0)

        qname = format_dns_name(domain)

        # A = 1, AAAA = 28
        qtype = 28 if rtype == "AAAA" else 1
        qinfo = struct.pack("!HH", qtype, 1)

        query = header + qname + qinfo

        sock.sendto(query, (GOOGLE_DNS, DNS_PORT))
        response, _ = sock.recvfrom(BUF_SIZE)

        sock.close()

    except:
        return "Error: Không kết nối được DNS server\n"

    # ===== 3. PARSE RESPONSE =====
    _, flags, _, ans_count, _, _ = struct.unpack("!HHHHHH", response[:12])
    rcode = flags & 0x000F

    # ===== NXDOMAIN =====
    if rcode == 3:
        dns_cache[cache_key] = {
            'ip': '',
            'expire': now + 60,
            'is_nx': True
        }
        return f"Error: NXDOMAIN '{domain}'\n"

    # ===== CÓ ANSWER =====
    if ans_count > 0:
        offset = skip_name(response, 12) + 4

        for _ in range(ans_count):
            offset = skip_name(response, offset)

            atype, _, ttl, rdlength = struct.unpack(
                "!HHIH", response[offset:offset+10])

            offset += 10

            # ===== IPv4 =====
            if atype == 1 and rtype == "A":
                ip = socket.inet_ntoa(response[offset:offset+4])

                dns_cache[cache_key] = {
                    'ip': ip,
                    'expire': now + ttl,
                    'is_nx': False
                }

                return f"{domain} (A) -> {ip}\nSource: fresh\nTTL: {ttl}s\n"

            # ===== IPv6 =====
            elif atype == 28 and rtype == "AAAA":
                ip = socket.inet_ntop(socket.AF_INET6,
                                      response[offset:offset+16])

                dns_cache[cache_key] = {
                    'ip': ip,
                    'expire': now + ttl,
                    'is_nx': False
                }

                return f"{domain} (AAAA) -> {ip}\nSource: fresh\nTTL: {ttl}s\n"

            else:
                offset += rdlength

        return f"Error: Không có bản ghi {rtype}\n"

    return "Error: Response rỗng\n"


# ==============================
# MAIN SERVER
# ==============================
def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('0.0.0.0', PORT))

    print_banner()
    print(f"[INFO] Server chạy tại port {PORT}\n")

    while True:
        data, addr = server_sock.recvfrom(BUF_SIZE)
        req = data.decode().strip()

        if not req:
            continue

        print("\n" + "-"*55)
        print(f"[CLIENT] {addr}")
        print(f"[REQUEST] {req}")

        # ===== XỬ LÝ =====
        if req == "/cache":
            response = handle_cache_command()

        else:
            parts = req.split()
            domain = parts[0]
            rtype = parts[1].upper() if len(parts) > 1 else "A"

            if rtype not in ["A", "AAAA"]:
                response = "Error: chỉ hỗ trợ A hoặc AAAA\n"
            else:
                print(f"[ACTION] Resolve {domain} ({rtype})")
                response = resolve_dns(domain, rtype)

        print(f"[RESPONSE]\n{response.strip()}")
        print("-"*55)

        server_sock.sendto(response.encode(), addr)


# ==============================
# CHẠY SERVER
# ==============================
if __name__ == "__main__":
    main()