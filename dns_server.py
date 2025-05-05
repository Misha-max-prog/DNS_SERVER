import binascii
import socket
import time
import pickle
import selectors
import signal

class Record:
    def __init__(self, data, rtype, expires):
        self.data = data
        self.rtype = rtype
        self.expires = expires

    def ttl(self):
        return max(self.expires - int(time.time()), 0)

    def format_for_dns(self):
        if self.rtype == 'A':
            return socket.inet_aton(self.data).hex()
        elif self.rtype == 'AAAA':
            return socket.inet_pton(socket.AF_INET6, self.data).hex()
        elif self.rtype in ['NS', 'PTR']:
            parts = self.data.split('.')
            encoded = ''
            for part in parts:
                encoded += f"{len(part):02x}"
                encoded += ''.join([f"{ord(c):02x}" for c in part])
            encoded += '00'
            return encoded
        else:
            return ''

def dump_cache(cache):
    with open('cache.pkl', 'wb') as f:
        pickle.dump(cache, f)


def load_cache():
    try:
        with open('cache.pkl', 'rb') as f:
            cache = pickle.load(f)
            print(f"[Cache] Initial loaded records: {sum(len(v) for v in cache.values())}")

            cleaned_cache = clear_cache(cache)
            valid_count = sum(len(v) for v in cleaned_cache.values())
            expired_count = sum(len(v) for v in cache.values()) - valid_count

            print(f"[Cache] Loaded {valid_count} valid records "
                  f"({expired_count} expired records removed)")
            return cleaned_cache

    except FileNotFoundError:
        print("[Cache] No cache file found. Starting with empty cache")
        return {}
    except Exception as e:
        print(f"[Cache] Error loading cache: {str(e)}. Starting fresh")
        return {}

def clear_cache(cache):
    current_time = int(time.time())
    new_cache = {}
    for key in cache:
        valid_records = [r for r in cache[key] if r.expires > current_time]
        if valid_records:
            new_cache[key] = valid_records
    return new_cache

def get_name(data_hex, offset):
    name = []
    initial_offset = offset
    jumps = 0
    max_jumps = 5

    while True:
        if offset >= len(data_hex) or jumps > max_jumps:
            break

        length_byte = int(data_hex[offset:offset+2], 16)
        offset += 2

        if length_byte == 0:
            break

        if (length_byte & 0xC0) == 0xC0:
            jumps += 1
            ptr = (length_byte & 0x3F) << 8 | int(data_hex[offset:offset+2], 16)
            offset += 2
            part_name, _ = get_name(data_hex, ptr*2)
            name.append(part_name)
            break
        else:
            part = data_hex[offset:offset + length_byte*2]
            offset += length_byte*2
            part_str = bytes.fromhex(part).decode('iso-8859-1')
            name.append(part_str)

    return '.'.join(name), offset - initial_offset

def parse_response(data_hex, cache):
    header = data_hex[:24]
    qdcount = int(header[8:12], 16)
    ancount = int(header[12:16], 16)
    nscount = int(header[16:20], 16)
    arcount = int(header[20:24], 16)

    offset = 24

    for _ in range(qdcount):
        _, offset_inc = get_name(data_hex, offset)
        offset += offset_inc + 4

    sections = [(ancount, 'answer'), (nscount, 'authority'), (arcount, 'additional')]
    current_time = int(time.time())

    for count, _ in sections:
        for _ in range(count):
            if offset >= len(data_hex):
                break

            name, offset_inc = get_name(data_hex, offset)
            offset += offset_inc

            rtype = data_hex[offset:offset+4]
            offset += 8
            ttl = int(data_hex[offset:offset+8], 16)
            offset += 8
            rdlength = int(data_hex[offset:offset+4], 16)
            offset += 4
            rdata_hex = data_hex[offset:offset + rdlength*2]
            offset += rdlength*2

            rtype_str = get_rr_type(rtype)
            expires = current_time + ttl

            if rtype_str == 'A':
                data = '.'.join(str(int(rdata_hex[i:i+2], 16) for i in range(0, 8, 2)))
            elif rtype_str == 'AAAA':
                data = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(rdata_hex))
            elif rtype_str in ['NS', 'PTR']:
                data, _ = get_name(rdata_hex, 0)
            else:
                data = rdata_hex

            key = (name, rtype_str)
            record = Record(data, rtype_str, expires)
            if key not in cache:
                cache[key] = []
            cache[key].append(record)

def get_rr_type(rtype_hex):
    types = {
        '0001': 'A',
        '001c': 'AAAA',
        '0002': 'NS',
        '000c': 'PTR'
    }
    return types.get(rtype_hex.lower(), 'UNKNOWN')

def build_error_response(query_data):
    header = bytearray(query_data[:12])
    header[2] = 0x80
    header[3] = 0x80 | 2
    return bytes(header) + query_data[12:]

def handle_query(data, addr, sock, cache):
    data_hex = binascii.hexlify(data).decode()
    transaction_id = data_hex[:4]
    try:
        name, offset = get_name(data_hex, 24)
        qtype_start = 24 + offset * 2
        qtype = data_hex[qtype_start:qtype_start+4]
    except:
        return

    key = (name, get_rr_type(qtype))
    cached = cache.get(key, [])
    valid = [r for r in cached if r.expires > time.time()]
    if valid:
        ttl = valid[0].ttl()
        response = (
            f"{transaction_id}81800001{len(valid):04x}00000000"
            f"{data_hex[24:24 + (len(name)*2 + 10)]}"
        )
        for r in valid:
            rdata = r.format_for_dns()
            response += (
                f"c00c{qtype}0001{ttl:08x}"
                f"{len(rdata)//2:04x}{rdata}"
            )
        sock.sendto(binascii.unhexlify(response), addr)
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(data, ('8.8.8.8', 53))
            response, _ = s.recvfrom(4096)
            parse_response(binascii.hexlify(response).decode(), cache)
            sock.sendto(response, addr)
    except:
        sock.sendto(build_error_response(data), addr)


def start_server():
    cache = load_cache()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 53))  

    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ)

    running = True
    last_cleanup = time.time()

    def signal_handler(sig, frame):
        nonlocal running
        print("\nReceived shutdown signal, shutting down gracefully...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("DNS server running on port 5300")

    try:
        while running:
            events = sel.select(timeout=1)
            for key, mask in events:
                if key.fileobj == sock:
                    data, addr = sock.recvfrom(512)
                    handle_query(data, addr, sock, cache)

            # Очистка кэша каждые 60 секунд
            current_time = time.time()
            if current_time - last_cleanup >= 60:
                cache = clear_cache(cache)
                last_cleanup = current_time
    finally:
        sel.unregister(sock)
        sock.close()
        dump_cache(cache)
        print("Server has shut down and cache saved.")

if __name__ == '__main__':
    start_server()
