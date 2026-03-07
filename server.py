import socket
import struct
import time

# --- CẤU HÌNH ---
PORT = 8888
GOOGLE_DNS = "8.8.8.8"
DNS_PORT = 53
BUF_SIZE = 2048

# Bộ nhớ Cache dạng Dictionary: { 'domain': {'ip': '1.2.3.4', 'expire': 1234567, 'is_nx': False} }
dns_cache = {}

def format_dns_name(domain):
    """Chuyển 'google.com' thành định dạng byte \x06google\x03com\x00"""
    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode('utf-8')
    return qname + b'\x00'

def skip_name(response, offset):
    """Hàm thông minh để bỏ qua trường Name (Xử lý cả con trỏ nén và chuỗi thường)"""
    while True:
        length = response[offset]
        if length == 0:  # Kết thúc chuỗi
            return offset + 1
        elif (length & 0xC0) == 0xC0:  # Là con trỏ nén (2 byte)
            return offset + 2
        else:  # Là chuỗi ký tự thường
            offset += length + 1

def resolve_dns(domain):
    now = time.time()
    
    # 1. KIỂM TRA CACHE TRƯỚC
    if domain in dns_cache:
        entry = dns_cache[domain]
        if now < entry['expire']:
            rem_ttl = int(entry['expire'] - now)
            if entry['is_nx']:
                return f"Error: NXDOMAIN '{domain}' does not exist.\nSource: Cache\nTTL: {rem_ttl}s remaining\n"
            return f"Result: {domain} -> {entry['ip']}\nSource: Cache hit\nTTL: {rem_ttl}s remaining\n"

    # 2. TẠO GÓI TIN & HỎI GOOGLE DNS
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)

        # Header (12 byte): ID=1234, Flags=0x0100 (Standard query), QCOUNT=1
        header = struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0)
        qname = format_dns_name(domain)
        qinfo = struct.pack("!HH", 1, 1)  # Type A (1), Class IN (1)
        query = header + qname + qinfo

        sock.sendto(query, (GOOGLE_DNS, DNS_PORT))
        response, _ = sock.recvfrom(BUF_SIZE)
        sock.close()
    except socket.error:
        return "Error: Timeout reaching 8.8.8.8. Lỗi kết nối mạng!\n"

    # 3. BÓC TÁCH GÓI TIN TRẢ VỀ (Đã vá lỗi CNAME)
    # Cắt 12 byte đầu để lấy Header
    resp_header = struct.unpack("!HHHHHH", response[:12])
    flags = resp_header[1]
    ans_count = resp_header[3]
    rcode = flags & 0x000F

    if rcode == 3: # Xử lý lỗi NXDOMAIN + Negative Cache
        dns_cache[domain] = {'ip': '', 'expire': now + 300, 'is_nx': True}
        return f"Error: NXDOMAIN '{domain}' does not exist.\n"

    if ans_count > 0:
        # Bỏ qua phần Header (12) và phần Question để đi tới Answer section
        offset = skip_name(response, 12) + 4 

        # Vòng lặp duyệt qua tất cả các câu trả lời (Xử lý được cả CNAME)
        for _ in range(ans_count):
            offset = skip_name(response, offset)  # Bỏ qua Name
            
            # Đọc 10 byte tiếp theo (Type, Class, TTL, Data_Length)
            atype, aclass, ttl, rdlength = struct.unpack("!HHIH", response[offset:offset+10])
            offset += 10

            if atype == 1 and rdlength == 4: # Nếu là bản ghi A (IP)
                ip_str = socket.inet_ntoa(response[offset:offset+4])
                dns_cache[domain] = {'ip': ip_str, 'expire': now + ttl, 'is_nx': False}
                return f"Result: {domain} -> {ip_str}\nSource: DNS query (fresh)\nTTL: {ttl}s\n"
            else:
                # Nếu là CNAME (Type 5), nhảy qua phần Data để xét bản ghi tiếp theo
                offset += rdlength

        return "Error: Không tìm thấy bản ghi A (IPv4) hợp lệ.\n"
    
    return "Error: DNS trả về gói tin rỗng.\n"

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(('0.0.0.0', PORT)) # Lắng nghe mọi IP trên cổng 8888
    print(f"--- DNS Resolver Server đang chạy trên cổng {PORT} ---")

    while True:
        data, addr = server_sock.recvfrom(BUF_SIZE)
        domain = data.decode('utf-8').strip() # Xóa khoảng trắng và \n (Message framing)
        if not domain: continue

        print(f"[DEBUG] Đã nhận yêu cầu phân giải: '{domain}'")
        response_msg = resolve_dns(domain)
        server_sock.sendto(response_msg.encode('utf-8'), addr)

if __name__ == '__main__':
    main()
