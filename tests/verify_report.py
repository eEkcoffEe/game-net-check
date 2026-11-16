import csv, datetime, ipaddress, json, struct, tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import paired


def write_pcap(path, records):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, _, b in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack('<IIII', sec, usec, len(b), len(b)))
            f.write(b)


def eth(payload):
    return b'\xff' * 6 + b'\x00' * 6 + b'\x08\x00' + payload


def ipv4(src, dst, proto, payload, ident=1):
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, ident, 0, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    s = 0
    data = hdr
    if len(data) % 2:
        data += b'\0'
    for i in range(0, len(data), 2):
        s += int.from_bytes(data[i:i + 2], 'big')
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack('!H', (~s) & 0xffff) + hdr[12:]
    return hdr + payload


def tcp(srcp, dstp, seq, ack, flags, payload=b''):
    return struct.pack('!HHIIBBHHH', srcp, dstp, seq, ack, 5 << 4, flags, 8192, 0, 0) + payload


def udp(srcp, dstp, payload=b''):
    return struct.pack('!HHHH', srcp, dstp, 8 + len(payload), 0) + payload


def tls_clienthello():
    host = b'example.com'
    name_entry = b'\x00' + struct.pack('!H', len(host)) + host
    sni_list = struct.pack('!H', len(name_entry)) + name_entry
    sni_ext = b'\x00\x00' + struct.pack('!H', len(sni_list)) + sni_list
    ext = sni_ext
    ch = b'\x03\x03' + b'\x16' * 32 + b'\x00' + struct.pack('!H', 2) + b'\x13\x01' + b'\x01\x00' + struct.pack('!H', len(ext)) + ext
    hs = b'\x01' + struct.pack('!I', len(ch))[1:] + ch
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs


def write_procmon(path, rows):
    fields = ['Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail', 'Date & Time', 'Time of Day']
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def run_case(records, proc_rows, **kw):
    with tempfile.TemporaryDirectory() as d:
        pcap = Path(d) / 'cap.pcap'
        csvp = Path(d) / 'pm.csv'
        out = Path(d) / 'out'
        write_pcap(pcap, records)
        write_procmon(csvp, proc_rows)
        outdir, rows = paired.run(str(pcap), str(csvp), kw.pop('local_ip', '192.168.1.5'), kw.pop('process', 'app.exe'), str(out), False, **kw)
        meta = json.loads((outdir / 'session.json').read_text(encoding='utf-8'))
        html = (outdir / 'report.html').read_text(encoding='utf-8')
        return rows, meta, html


def pm_row(t, op, path, result='SUCCESS', detail='', pid='1', name='app.exe'):
    return {
        'Process Name': name, 'PID': pid, 'Operation': op, 'Path': path, 'Result': result, 'Detail': detail,
        'Date & Time': datetime.datetime.utcfromtimestamp(int(t)).strftime('%d.%m.%Y %H:%M:%S'),
        'Time of Day': datetime.datetime.utcfromtimestamp(t).strftime('%H:%M:%S.%f'),
    }


base = 1700000000.0
L = '192.168.1.5'
R = '93.184.216.34'
ok = True


def check(cond, msg):
    global ok
    print(('OK' if cond else 'FAIL') + ': ' + msg)
    if not cond:
        ok = False


# 1) several SYN without answer
recs = [(base + i * 0.6, 1, eth(ipv4(L, R, 6, tcp(40000, 443, 100 + i, 0, 0x02)))) for i in range(6)]
pm = [pm_row(base, 'TCP Connect', f'{L}:40000 -> {R}:443')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any('без ответа' in x.get('Finding', '') or 'SYN' in x.get('Finding', '') for x in rows), 'SYN without answer detected')
check(not any('заблок' in (x.get('Finding', '') + x.get('Status', '')).lower() for x in rows), 'SYN case not declared blocked')

# 2) TCP answered but exchange stalled after data
recs = [
    (base, 1, eth(ipv4(L, R, 6, tcp(40001, 443, 1, 0, 0x02)))),
    (base + 0.1, 1, eth(ipv4(R, L, 6, tcp(443, 40001, 10, 2, 0x12)))),
    (base + 0.2, 1, eth(ipv4(L, R, 6, tcp(40001, 443, 2, 11, 0x18, b'abc')))),
    (base + 0.4, 1, eth(ipv4(L, R, 6, tcp(40001, 443, 5, 11, 0x18, b'def')))),
]
pm = [pm_row(base + 0.2, 'TCP Send', f'{L}:40001 -> {R}:443', detail='Length: 3')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any('дальнейшего прогресса не видно' in x.get('Finding', '') for x in rows), 'stalled TCP after data detected')

# 3) successful exchange then RST
recs = [
    (base, 1, eth(ipv4(L, R, 6, tcp(40002, 443, 1, 0, 0x02)))),
    (base + 0.1, 1, eth(ipv4(R, L, 6, tcp(443, 40002, 10, 2, 0x12)))),
    (base + 0.2, 1, eth(ipv4(L, R, 6, tcp(40002, 443, 2, 11, 0x18, b'abc')))),
    (base + 0.3, 1, eth(ipv4(R, L, 6, tcp(443, 40002, 11, 5, 0x18, b'ok')))),
    (base + 0.4, 1, eth(ipv4(R, L, 6, tcp(443, 40002, 13, 5, 0x14)))),
]
pm = [pm_row(base + 0.2, 'TCP Send', f'{L}:40002 -> {R}:443', detail='Length: 3')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any('TCP RST' in x.get('Finding', '') for x in rows), 'RST observed')

# 4) Procmon error without packets in PCAP
recs = [(base, 1, eth(ipv4(L, '1.1.1.1', 17, udp(50000, 53, b'x'))))]
pm = [pm_row(base, 'TCP Connect', f'{L}:40003 -> {R}:443', result='TIMEOUT')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any(x.get('Type') == 'Ошибка Procmon' and x.get('Result') == 'TIMEOUT' for x in rows), 'Procmon error without PCAP packets preserved')
check(any('Пакетов этого 5-tuple' in x.get('Evidence', '') for x in rows if x.get('Type') == 'Ошибка Procmon'), 'no packets at all distinguished')
# packets exist but not in match window
recs = [(base + 120, 1, eth(ipv4(L, R, 6, tcp(40013, 443, 1, 0, 0x02))))]
pm = [pm_row(base, 'TCP Connect', f'{L}:40013 -> {R}:443', result='TIMEOUT')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any(x.get('Type') == 'Ошибка Procmon' and 'не попали в окно' in x.get('Evidence', '') for x in rows), 'packets exist but outside match window distinguished')

# 5) ordinary UDP without required reply
recs = [(base, 1, eth(ipv4(L, R, 17, udp(40004, 9999, b'hi'))))]
pm = [pm_row(base, 'UDP Send', f'{L}:40004 -> {R}:9999', detail='Length: 2')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(not any('заблок' in (x.get('Finding', '') + x.get('Status', '')).lower() for x in rows), 'UDP without reply not declared blocked')
check(any('не означает сбой' in x.get('Finding', '') or 'не доказывает' in x.get('Finding', '') for x in rows), 'UDP no-reply treated as non-failure observation')

# 6) ambiguous match
recs = [(base + i * 0.6, 1, eth(ipv4(L, R, 6, tcp(40005, 443, 1 + i, 0, 0x02)))) for i in range(6)]
pm = [
    pm_row(base, 'TCP Connect', f'{L}:40005 -> {R}:443', pid='1', name='app.exe'),
    pm_row(base + 0.1, 'TCP Connect', f'{L}:40005 -> {R}:443', pid='2', name='other.exe'),
]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any(x.get('Ambiguous') for x in rows), 'ambiguous match flagged')
check(not any(x.get('Candidate') for x in rows), 'ambiguous match not a candidate')

# 7) CSV/PCAP time mismatch
recs = [(base, 1, eth(ipv4(L, R, 17, udp(40006, 9999, b'hi'))))]
pm = [pm_row(base + 7200, 'UDP Send', f'{L}:40006 -> {R}:9999', detail='Length: 2')]
rows, meta, _ = run_case(recs, pm, utc_offset=0)
check(bool(meta and any('ВРЕМЯ CSV И PCAP' in k for k in meta.get('warnings', {}))), 'CSV/PCAP time mismatch warned')

# Extra: TLS ClientHello without observed server reply
recs = [(base, 1, eth(ipv4(L, R, 6, tcp(40007, 443, 1, 0, 0x18, tls_clienthello()))))]
pm = [pm_row(base, 'TCP Send', f'{L}:40007 -> {R}:443', detail='Length: 10')]
rows, _, _ = run_case(recs, pm, utc_offset=0)
check(any('TLS ClientHello' in x.get('Finding', '') for x in rows), 'ClientHello without reply observed')

# HTML with problems
check('Что требует внимания' in _ and 'Все соединения' in _ and 'DNS' in _ and 'Несопоставленные события' in _ and 'Технические подробности' in _, 'HTML has required sections when problems exist')

# HTML without obvious issues
recs = [
    (base, 1, eth(ipv4(L, R, 6, tcp(40008, 443, 1, 0, 0x02)))),
    (base + 0.1, 1, eth(ipv4(R, L, 6, tcp(443, 40008, 10, 2, 0x12)))),
    (base + 0.2, 1, eth(ipv4(L, R, 6, tcp(40008, 443, 2, 11, 0x18, b'abc')))),
    (base + 0.3, 1, eth(ipv4(R, L, 6, tcp(443, 40008, 11, 5, 0x18, b'ok')))),
]
pm = [pm_row(base + 0.2, 'TCP Send', f'{L}:40008 -> {R}:443', detail='Length: 3')]
rows, meta, html = run_case(recs, pm, utc_offset=0)
check(not any(x.get('NeedsAttention') for x in rows), 'normal exchange not marked as needing attention')
check('Явных признаков сбоя не найдено. Это не подтверждает доступность всех ресурсов' in html, 'clean HTML shows explicit no-findings message')

print('ALL_OK' if ok else 'ALL_FAIL')
sys.exit(0 if ok else 1)
