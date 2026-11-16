#!/usr/bin/env python3
"""Offline IPv4 TCP/UDP triage. Python 3.10+, standard library only."""
import argparse, collections, csv, datetime, html, ipaddress, json, pathlib, struct, sys, webbrowser


def packets(path, warnings):
    """PCAP/PCAPNG reader, Ethernet/raw IP/Linux cooked link types."""
    with open(path, 'rb') as f:
        magic = f.read(4); f.seek(0)
        if magic != b'\x0a\x0d\x0d\x0a':
            formats = {b'\xd4\xc3\xb2\xa1':('<',1e-6), b'\xa1\xb2\xc3\xd4':('>',1e-6), b'\x4d\x3c\xb2\xa1':('<',1e-9), b'\xa1\xb2\x3c\x4d':('>',1e-9)}
            if magic not in formats: raise ValueError('Неизвестный формат захвата')
            endian, scale = formats[magic]; hdr=f.read(24)
            if len(hdr)!=24: raise ValueError('Обрезанный заголовок PCAP')
            link=struct.unpack_from(endian+'I',hdr,20)[0]&0xffff
            while True:
                h=f.read(16)
                if not h: break
                if len(h)!=16: raise ValueError('Обрезанная запись PCAP')
                sec, sub, cap, orig=struct.unpack(endian+'IIII',h)
                if cap>64*1024*1024: raise ValueError('Слишком большая запись PCAP')
                b=f.read(cap)
                if len(b)!=cap: raise ValueError('Обрезанные пакеты PCAP')
                if cap<orig: warnings['Обрезанные пакеты']+=1
                yield sec+sub*scale,link,b
            return
        endian='<'; interfaces=[]
        while True:
            h=f.read(8)
            if not h: break
            if len(h)!=8: raise ValueError('Обрезанный блок PCAPNG')
            prefix=b''
            if h[:4]==b'\x0a\x0d\x0d\x0a':
                prefix=f.read(4)
                if prefix==b'\x4d\x3c\x2b\x1a': endian='<'
                elif prefix==b'\x1a\x2b\x3c\x4d': endian='>'
                else: raise ValueError('Неверный byte-order magic')
                interfaces=[]
            typ,size=struct.unpack(endian+'II',h)
            if size<12 or size%4 or size>64*1024*1024: raise ValueError('Некорректный блок PCAPNG')
            tail=f.read(size-8-len(prefix)); body=prefix+tail
            if len(body)!=size-8 or struct.unpack(endian+'I',body[-4:])[0]!=size: raise ValueError('Обрезанный блок PCAPNG')
            d=body[:-4]
            if typ==1:
                link=struct.unpack_from(endian+'H',d)[0];scale=1e-6;offset=0;pos=8
                while pos+4<=len(d):
                    code,n=struct.unpack_from(endian+'HH',d,pos);pos+=4;v=d[pos:pos+n];pos+=(n+3)//4*4
                    if code==0:break
                    if code==9 and v: scale=(2.0**-(v[0]&127)) if v[0]&128 else (10.0**-v[0])
                    if code==14 and len(v)==8: offset=struct.unpack(endian+'q',v)[0]
                interfaces.append((link,scale,offset))
            elif typ==6:
                iid,hi,lo,cap,orig=struct.unpack_from(endian+'IIIII',d)
                if iid>=len(interfaces) or 20+cap>len(d): raise ValueError('Некорректная запись EPB')
                link,scale,offset=interfaces[iid]
                if cap<orig:warnings['Обрезанные пакеты']+=1
                yield ((hi<<32)+lo)*scale+offset,link,d[20:20+cap]
            elif typ in (2,3): warnings['Неподдерживаемые устаревшие блоки пакетов']+=1


def decode(link,b,warnings):
    if link==1:
        if len(b)<14:return
        eth=struct.unpack_from('!H',b,12)[0];pos=14
        while eth in (0x8100,0x88a8):
            if len(b)<pos+4:return
            eth=struct.unpack_from('!H',b,pos+2)[0];pos+=4
        if eth==0x86dd:warnings['IPv6: анализ не поддерживается']+=1;return
        if eth!=0x800:return
        b=b[pos:]
    elif link==113:b=b[16:]
    elif link==276:b=b[20:]
    elif link not in (101,228):warnings['Неподдерживаемый тип интерфейса '+str(link)]+=1;return
    if not b:return
    if b[0]>>4==6:warnings['IPv6: анализ не поддерживается']+=1;return
    if len(b)<20 or b[0]>>4!=4:return
    ihl=(b[0]&15)*4;total=struct.unpack_from('!H',b,2)[0]
    if ihl<20 or ihl>len(b):return
    if struct.unpack_from('!H',b,6)[0]&0x3fff:
        warnings['Фрагменты IPv4: пропущены']+=1;return
    src=str(ipaddress.ip_address(b[12:16]));dst=str(ipaddress.ip_address(b[16:20]));proto=b[9];q=b[ihl:total]
    if proto not in (6,17):return
    if len(q)<(20 if proto==6 else 8):return
    sp,dp=struct.unpack_from('!HH',q);flags=q[13] if proto==6 else 0
    plen=max(0,len(q)-((q[12]>>4)*4 if proto==6 else 8))
    return (proto,src,sp,dst,dp),plen,flags


def load_csv(path,process):
    if not path:return set(),0
    raw=pathlib.Path(path).read_bytes()
    try:text=raw.decode('utf-8-sig')
    except UnicodeDecodeError:text=raw.decode('cp1251')
    delim=';' if text.splitlines()[0].count(';')>text.splitlines()[0].count(',') else ','
    rows=list(csv.DictReader(text.splitlines(),delimiter=delim));ips=set();count=0
    for r in rows:
        app=r.get('Приложение',r.get('Application',''));addr=r.get('IP-адрес',r.get('IP address',r.get('IP Address','')))
        if process.lower() not in app.lower():continue
        try:ipaddress.ip_address(addr)
        except ValueError:continue
        ips.add(addr);count+=1
    if not ips:raise ValueError('В CSV нет IP выбранного процесса. Проверьте имя процесса и экспорт NetLimiter.')
    return ips,count


def analyze(capture,local_ip,netcsv=None,process='discovery-d.exe',out=None,online=False):
    local_ip=str(ipaddress.IPv4Address(local_ip));known,count=load_csv(netcsv,process)
    warnings=collections.Counter();flows={};start=None;end=None;num=0
    for t,link,b in packets(capture,warnings):
        num+=1;start=t if start is None else min(t,start);end=t if end is None else max(t,end)
        parsed=decode(link,b,warnings)
        if not parsed:continue
        key,plen,flags=parsed
        if local_ip not in (key[1],key[3]):continue
        z=flows.setdefault(key,{'n':0,'bytes':0,'first':t,'last':t,'syn':0,'rst':0})
        z['n']+=1;z['bytes']+=plen;z['last']=max(t,z['last']);z['first']=min(t,z['first'])
        z['syn']+=int(bool(flags&2) and not flags&16);z['rst']+=int(bool(flags&4))
    if not num:raise ValueError('В файле нет поддерживаемых записей пакетов')
    if not flows:raise ValueError('Нет TCP/UDP для указанного IP ПК. Проверьте адрес и интерфейс захвата.')
    result=[]
    for (proto,s,sp,d,dp),v in flows.items():
        addr=ipaddress.ip_address(d)
        if s!=local_ip or not addr.is_global or addr.is_multicast:continue
        rv=flows.get((proto,d,dp,s,sp),{'n':0,'bytes':0,'rst':0})
        span=v['last']-v['first']; repeated=v['n']>=5 and span>=3
        status='Есть ответы'
        if rv['n']==0:status='Повторяется без ответов' if repeated else 'Нет ответа: мало данных'
        elif proto==6 and rv['rst']:status='TCP RST: соединение сброшено'
        elif proto==6 and rv['bytes']==0:status='TCP ответы есть, данных сервера нет'
        result.append({'Status':status,'Protocol':'UDP' if proto==17 else 'TCP','IP':d,'Port':dp,'LocalPort':sp,'Sent':v['n'],'Received':rv['n'],'SentPayloadBytes':v['bytes'],'ReceivedPayloadBytes':rv['bytes'],'SpanSeconds':round(span,2),'SynAttempts':v['syn'],'CSVMatch':d in known,'Subnet24':str(ipaddress.ip_network(d+'/24',strict=False)),'Candidate':rv['n']==0 and repeated})
    result.sort(key=lambda r:(not r['Candidate'],not r['CSVMatch'],-r['Sent']))
    out=pathlib.Path(out or pathlib.Path(capture).parent/('GameNetCheck_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')))
    out.mkdir(parents=True,exist_ok=False)
    if result:
        with (out/'connections.csv').open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(result[0]));w.writeheader();w.writerows(result)
    candidates=sorted({r['IP'] for r in result if r['Candidate']},key=ipaddress.ip_address)
    rules=['// Кандидаты, НЕ доказанные блокировки. Проверяйте маршрут и повторный тест.','// /32 ограничивает тест одним IP. Не добавляйте все строки без проверки.']+[x+'/32' for x in candidates]
    (out/'podkop-candidates.txt').write_text('\n'.join(rules)+'\n',encoding='utf-8-sig')
    network_info=[]
    if online:
        from netinfo import lookup
        for addr in candidates[:20]:
            print('RDAP/BGP:',addr,flush=True)
            network_info.append(lookup(addr))
        if len(candidates)>20:warnings['Онлайн-проверка ограничена первыми 20 IP']+=len(candidates)-20
        (out/'networks.json').write_text(json.dumps(network_info,ensure_ascii=False,indent=2),encoding='utf-8')
    groups=collections.defaultdict(set)
    for r in result:
        if r['Candidate']:groups[r['Subnet24']].add(r['IP'])
    esc=html.escape
    def table(headers,rows):return '<table><thead><tr>'+''.join('<th>'+esc(str(h))+'</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+esc(str(c))+'</td>' for c in row)+'</tr>' for row in rows)+'</tbody></table>'
    htmltext='''<!doctype html><meta charset="utf-8"><title>GameNetCheck</title><style>body{font:16px system-ui;max-width:1400px;margin:32px auto;padding:20px;color:#182b40;background:#f4f7fa}table{border-collapse:collapse;width:100%;background:white;font-size:14px}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}th{background:#12334b;color:white}section{margin:24px 0;padding:20px;background:white;border-radius:12px}h1{color:#12334b}code{background:#e8eef4;padding:3px}</style><h1>GameNetCheck — диагностика соединений</h1>'''
    htmltext+='<p>Файл: '+esc(str(capture))+' · IP ПК: '+esc(local_ip)+' · '+str(num)+' пакетов · '+str(round(end-start,1))+' с</p>'
    htmltext+='<section><b>Как читать результат</b><p>«Повторяется без ответов»: минимум 5 исходящих пакетов на протяжении минимум 3 секунд, обратных пакетов в записи нет. Это эвристика, а не доказательство блокировки. UDP может не требовать ответа. TCP с ответами тоже может завершиться ошибкой приложения.</p><p>CSVMatch=True означает только совпадение IP с историей выбранного процесса '+esc(process)+'. Захват не содержит PID: общий IP может использоваться другими программами. CSVMatch=False НЕ исключает игру — экспорт мог не успеть обновиться.</p><p>Сначала сравните неудачную и успешную попытки. Проверяйте точечный /32 в нужной секции Podkop и выбранный outbound. Если ответов всё ещё нет, проверьте журнал Podkop и UDP, а не расширяйте подсеть бесконечно.</p></section>'
    htmltext+='<h2>Кандидаты по /24 — только группировка, не готовые правила</h2>'+table(['Подсеть','Наблюдавшиеся IP'],[(g,', '.join(sorted(v))) for g,v in sorted(groups.items())])
    if online:
        htmltext+='<h2>Интернет-реестры: диапазон регистрации и BGP-маршрут</h2><p>Запрашиваются только IP повторяющихся потоков без ответов, до 20 адресов. Кэш — 24 часа. Страна реестра не означает местонахождение сервера. Эти сети НЕ добавляются в правила автоматически.</p>'
        htmltext+=table(['IP','Имя сети / регистрант','Диапазон RDAP','CIDR RDAP','Адресов','BGP-префикс / ASN','Проверено UTC / ошибки'],[(n['ip'],n.get('network_name','')+' / '+n.get('registrant',''),n.get('range_start','')+' — '+n.get('range_end',''),', '.join(n.get('cidrs',[])),n.get('address_count',''),n.get('bgp_prefix','')+' / '+', '.join(n.get('asns',[])),n.get('checked_utc','')+' '+ '; '.join(n.get('errors',[]))) for n in network_info])
        htmltext+='<p>RDAP показывает зарегистрированную сеть; BGP — маршрут, наблюдаемый RIPE RIS. Они могут различаться, включать много чужих сервисов и не являются пулом именно этой игры. Начинайте проверку с /32; расширение диапазона — отдельное решение.</p><ul>'
        for n in network_info:
            for key in ('rdap_source','bgp_source'):
                url=n.get(key,'')
                if url.startswith('https://'):htmltext+='<li>'+esc(n['ip'])+' <a href="'+esc(url,quote=True)+'">'+esc(key)+'</a></li>'
        htmltext+='</ul>'
    else:
        htmltext+='<p>Интернет-проверка отключена (--offline).</p>'
    htmltext+='<h2>Соединения с публичными IPv4</h2>'+table(['Статус','Протокол','IP','Порт','Лок. порт','Отправлено','Ответов','Длительность, с','IP есть в CSV'],[(r['Status'],r['Protocol'],r['IP'],r['Port'],r['LocalPort'],r['Sent'],r['Received'],r['SpanSeconds'],r['CSVMatch']) for r in result])
    htmltext+='<section><h2>Ограничения</h2><p>IPv4 TCP/UDP. IPv6, фрагменты, ICMP и расшифровка TLS не анализируются. Внутренние и Fake-IP адреса не включены в таблицу: для 198.18.x.x нужен журнал Podkop. Домены не определяются; обратный DNS не заменяет исходный домен. Проверяются точные пары IP/портов, захват не показывает фактический выход через КЗ. Часть соединений может начаться до записи.</p><pre>'+esc(json.dumps(dict(warnings),ensure_ascii=False,indent=2))+'</pre></section>'
    (out/'report.html').write_text(htmltext,encoding='utf-8')
    return out,result


def main():
    ap=argparse.ArgumentParser(description='GameNetCheck 1.5: Wireshark + Process Monitor / NetLimiter')
    ap.add_argument('--pcap');ap.add_argument('--input',help='Alias for --pcap')
    ap.add_argument('--csv');ap.add_argument('--local-ip');ap.add_argument('--process',default='')
    ap.add_argument('--mode',choices=['procmon','netlimiter']);ap.add_argument('--procmon-date',help='Date of first network CSV event: YYYY-MM-DD')
    ap.add_argument('--utc-offset',type=float,help='Capture PC UTC offset in hours, e.g. 5')
    ap.add_argument('--tolerance',type=float,default=2.0);ap.add_argument('--clock-shift',type=float,default=0.0,help='Seconds added to Procmon timestamps')
    ap.add_argument('--out');ap.add_argument('--no-open',action='store_true');ap.add_argument('--offline',action='store_true');ap.add_argument('--lookup-ip');a=ap.parse_args()
    gui=not (a.pcap or a.input or a.csv or a.lookup_ip)
    try:
        if a.lookup_ip:
            if a.offline:ap.error('--lookup-ip requires Internet access; remove --offline')
            from netinfo import lookup
            print(json.dumps(lookup(a.lookup_ip),ensure_ascii=False,indent=2));return
        from csv_modes import detect,appname,infer_local,selected
        from paired import run
        a.pcap=a.pcap or a.input
        if gui:
            import tkinter as tk
            from tkinter import filedialog,simpledialog,messagebox
            root=tk.Tk();root.withdraw()
            picker=tk.Toplevel(root);picker.title('GameNetCheck 1.5');picker.geometry('480x210');picker.resizable(False,False)
            tk.Label(picker,text='Выберите режим работы',font=('Segoe UI',13)).pack(pady=16)
            choice=[]
            def choose(mode):choice.append(mode);picker.destroy()
            tk.Button(picker,text='Process Monitor + Wireshark',command=lambda:choose('procmon'),width=48,height=2).pack(pady=4)
            tk.Button(picker,text='NetLimiter + Wireshark',command=lambda:choose('netlimiter'),width=48,height=2).pack(pady=4)
            root.wait_window(picker)
            if not choice:return
            a.mode=choice[0]
            a.pcap=filedialog.askopenfilename(title='1. Запись Wireshark той же попытки',filetypes=[('Capture','*.pcapng *.pcap')])
            if not a.pcap:return
            a.csv=filedialog.askopenfilename(title='2. CSV '+('Process Monitor' if a.mode=='procmon' else 'NetLimiter'),filetypes=[('CSV','*.csv *.CSV')])
            if not a.csv:return
        if not a.pcap or not a.csv:raise ValueError('Нужны оба файла: --pcap capture.pcapng --csv history.csv')
        mode,raw=detect(a.csv)
        if a.mode and a.mode!=mode:raise ValueError('CSV не соответствует выбранному режиму: '+mode)
        if gui:
            apps=sorted({appname(r) for r in raw if appname(r)})
            answer=simpledialog.askstring('Процесс','Точное имя EXE (пусто = все):\n'+', '.join(apps[:20]),initialvalue=apps[0] if len(apps)==1 else '')
            if answer is None:return
            a.process=answer.strip()
            guess=infer_local(selected(raw,a.process)) if mode=='procmon' else ''
            answer=simpledialog.askstring('IP компьютера','Локальный IPv4 ПК из ipconfig:',initialvalue=guess)
            if not answer:return
            a.local_ip=answer.strip()
            if mode=='procmon':
                # Current exports include Date & Time: no date/time prompt required.
                has_dates=any(r.get('Date & Time','').strip() for r in raw if r.get('Operation','').startswith(('TCP ','UDP ')))
                if not has_dates:
                    first=next(packets(a.pcap,collections.Counter()))[0]
                    date=datetime.datetime.fromtimestamp(first).date().isoformat()
                    answer=simpledialog.askstring('Старый CSV без даты','В CSV нет Date & Time. Дата первого сетевого события, YYYY-MM-DD:',initialvalue=date)
                    if not answer:return
                    a.procmon_date=answer.strip()
        if not a.local_ip:raise ValueError('Укажите --local-ip')
        out,rows=run(a.pcap,a.csv,a.local_ip,a.process,a.out,not a.offline,a.procmon_date,a.utc_offset,a.tolerance,a.clock_shift,a.mode)
        print('Отчёт:',out/'report.html')
        print('Сопоставлено потоков:',sum(r['Matched'] for r in rows),'Кандидатов:',sum(r['Candidate'] for r in rows))
        if not a.no_open:webbrowser.open((out/'report.html').resolve().as_uri())
    except Exception as e:
        if gui:
            from tkinter import messagebox
            messagebox.showerror('GameNetCheck',str(e))
        else:print('Ошибка:',e,file=sys.stderr)
        sys.exit(1)

if __name__=='__main__':main()
