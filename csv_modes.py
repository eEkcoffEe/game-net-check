"""CSV adapters for Process Monitor and NetLimiter; no packet-count inference."""
import collections,csv,datetime,html,io,ipaddress,json,pathlib,re


def read_rows(path):
    raw=pathlib.Path(path).read_bytes()
    enc='utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
    try:text=raw.decode(enc)
    except UnicodeDecodeError:text=raw.decode('cp1251')
    if not text.strip():raise ValueError('Пустой CSV')
    delim=';' if text.splitlines()[0].count(';')>text.splitlines()[0].count(',') else ','
    reader=csv.DictReader(io.StringIO(text),delimiter=delim);rows=list(reader)
    return set(reader.fieldnames or []),rows


def detect(path):
    fields,rows=read_rows(path)
    if {'Process Name','Operation','Path','Result'}.issubset(fields):return 'procmon',rows
    if ('Приложение' in fields and 'IP-адрес' in fields) or ('Application' in fields and ('IP Address' in fields or 'IP address' in fields)):return 'netlimiter',rows
    raise ValueError('Неизвестный CSV. Нужен экспорт Process Monitor или истории NetLimiter.')


def appname(row):return row.get('Process Name',row.get('Приложение',row.get('Application','')))
def selected(rows,process):return [r for r in rows if not process or appname(r).lower()==process.lower()]
def field(row,*names):return next((row[n] for n in names if row.get(n) is not None),'')
def number(text):
    text=re.sub(r'[\s\u00a0\u202f]','',str(text))
    if not re.fullmatch(r'\d+',text):raise ValueError('Ожидалось целое число байт: '+text)
    return int(text)
def endpoint(text):
    host,port=text.strip().rsplit(':',1);host=host.strip('[]')
    addr=ipaddress.ip_address(host)
    if port in ('https','http','domain'):port={'https':'443','http':'80','domain':'53'}[port]
    port=int(port)
    if not 0<=port<=65535:raise ValueError('Invalid port')
    return str(addr),port

def scope(addr):
    ip=ipaddress.ip_address(addr)
    if ip.version==4 and ip in ipaddress.ip_network('198.18.0.0/15'):return 'Fake-IP: нужен журнал Podkop'
    if ip.is_multicast:return 'Multicast: локальное обнаружение'
    if not ip.is_global:return 'Локальный/служебный адрес'
    if ip.version==6:return 'IPv6: интернет-проверка не поддерживается'
    return 'Публичный IPv4'

def infer_local(rows):
    c=collections.Counter()
    for r in rows:
        try:
            left,right=map(endpoint,r.get('Path','').split(' -> '))
            for host,port in (left,right):
                ip=ipaddress.ip_address(host)
                if ip.version==4 and any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):c[host]+=1
        except (ValueError,TypeError):pass
    return c.most_common(1)[0][0] if c else ''


def procmon(rows,local_ip,process):
    local_ip=str(ipaddress.ip_address(local_ip));groups={};warnings=collections.Counter();prev=None;offset=0;used=0
    for r in selected(rows,process):
        op=r.get('Operation','')
        if not op.startswith(('TCP ','UDP ')):continue
        try:
            t=r['Time of Day'].replace(',','.');parts=t.split(':')
            sec=int(parts[0])*3600+int(parts[1])*60+float(parts[2])
            if prev is not None and sec<prev-43200:offset+=86400
            prev=sec;t=sec+offset
        except (ValueError,KeyError,IndexError):warnings['Не распознано время события']+=1;continue
        try:left,right=map(endpoint,r['Path'].split(' -> '))
        except (ValueError,KeyError):warnings['Не разобран адрес: отключите Resolve Network Addresses']+=1;continue
        if left[0]==local_ip:local,remote=left,right
        elif right[0]==local_ip:local,remote=right,left
        else:warnings['События другого локального адреса / интерфейса']+=1;continue
        key=(appname(r),r.get('PID',''),op.split()[0],local[1],remote[0],remote[1])
        z=groups.setdefault(key,{'ops':collections.Counter(),'errors':collections.Counter(),'first':t,'last':t,'send_times':[],'sentbytes':0,'receivedbytes':0})
        used+=1;z['ops'][op]+=1;z['last']=max(z['last'],t);z['first']=min(z['first'],t)
        if r.get('Result','')!='SUCCESS':z['errors'][r.get('Result','unknown')]+=1
        m=re.search(r'Length:\s*([\d\s\u00a0\u202f]+)',r.get('Detail',''));size=int(re.sub(r'\s','',m[1])) if m else 0
        if op.endswith(' Send') and r.get('Result')=='SUCCESS':z['send_times'].append(t);z['sentbytes']+=size
        if op.endswith(' Receive') and r.get('Result')=='SUCCESS':z['receivedbytes']+=size
    if not groups:raise ValueError('Нет подходящих сетевых событий. Проверьте процесс, IP ПК и числовые адреса в CSV.')
    result=[]
    for (app,pid,proto,lp,ip,rp),z in groups.items():
        ops=z['ops'];sent=ops[proto+' Send'];recv=ops[proto+' Receive'];retry=ops['TCP Retransmit'];reconnect=ops['TCP Reconnect']
        st=z['send_times'];span=max(st)-min(st) if st else 0;repeated=len(st)>=5 and span>=3 and recv==0
        reasons=[]
        if repeated:reasons.append('Повторные отправки без Receive')
        elif sent and not recv:reasons.append('Нет Receive: мало данных')
        if retry:reasons.append('TCP Retransmit: '+str(retry))
        if reconnect:reasons.append('TCP Reconnect: '+str(reconnect))
        if z['errors']:reasons.append('Ошибки операций: '+str(dict(z['errors'])))
        category=scope(ip);candidate=category=='Публичный IPv4' and (repeated or retry>=2 or reconnect>=2 or bool(z['errors']))
        result.append({'Process':app,'PID':pid,'Protocol':proto,'IP':ip,'Port':rp,'LocalPort':lp,'Scope':category,'Status':'; '.join(reasons) or ('Есть Receive' if recv else 'Недостаточно данных'),'SendEvents':sent,'ReceiveEvents':recv,'RetransmitEvents':retry,'ReconnectEvents':reconnect,'SentBytes':z['sentbytes'],'ReceivedBytes':z['receivedbytes'],'SpanSeconds':round(z['last']-z['first'],3),'Candidate':candidate})
    return result,warnings,used


def netlimiter(rows,process):
    result=[];warnings=collections.Counter()
    for r in selected(rows,process):
        try:
            ip=str(ipaddress.ip_address(field(r,'IP-адрес','IP Address','IP address')))
            sent=number(field(r,'Исходящих данных','Data Out','Outgoing data','Outgoing Data'))
            recv=number(field(r,'Входящих данных','Data In','Incoming data','Incoming Data'))
        except ValueError:warnings['Строки с нераспознанным IP или числом байт']+=1;continue
        category=scope(ip)
        result.append({'Process':appname(r),'IP':ip,'Port':field(r,'Порт','Port'),'Protocol':'Не указан в экспорте','Scope':category,'SentBytes':sent,'ReceivedBytes':recv,'FirstTransfer':field(r,'Время первой передачи','First transfer time','First Transfer Time'),'LastTransfer':field(r,'Время последней передачи','Last transfer time','Last Transfer Time'),'Status':'Есть входящие байты' if recv else ('Исходящие байты без входящих — проверить' if sent else 'Нет обмена'),'Candidate':category=='Публичный IPv4' and sent>0 and recv==0})
    if not result:raise ValueError('Нет строк выбранного приложения с числовыми IP и байтами. Экспортируйте историю NetLimiter в CSV.')
    return result,warnings,len(result)


def analyze_csv(path,process='',local_ip=None,out=None,online=False):
    mode,rows=detect(path)
    if mode=='procmon':result,warnings,used=procmon(rows,local_ip or infer_local(selected(rows,process)),process)
    else:result,warnings,used=netlimiter(rows,process)
    result.sort(key=lambda r:(not r['Candidate'],r['Process'],r['IP']))
    out=pathlib.Path(out or pathlib.Path(path).parent/('GameNetCheck_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')));out.mkdir(parents=True,exist_ok=False)
    with (out/'connections.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(result[0]));w.writeheader();w.writerows(result)
    candidates=sorted({r['IP'] for r in result if r['Candidate']},key=ipaddress.ip_address)
    (out/'podkop-candidates.txt').write_text('// Кандидаты для проверки, не доказанные блокировки. Не применять весь список автоматически.\n'+'\n'.join(ip+'/32' for ip in candidates)+'\n',encoding='utf-8-sig')
    networks=[]
    if online:
        from netinfo import lookup
        for ip in candidates[:20]:print('RDAP/BGP:',ip,flush=True);networks.append(lookup(ip))
        if len(candidates)>20:warnings['Онлайн-проверка ограничена первыми 20 адресами']+=len(candidates)-20
        (out/'networks.json').write_text(json.dumps(networks,ensure_ascii=False,indent=2),encoding='utf-8')
    def table(headers,data):return '<table><tr>'+''.join('<th>'+html.escape(str(x))+'</th>' for x in headers)+'</tr>'+''.join('<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in row)+'</tr>' for row in data)+'</table>'
    explanation=('Это события Process Monitor, а не пакеты. Send SUCCESS не доказывает получение сервером. Группировка: процесс + PID + протокол + локальный порт + удалённый IP/порт. Направление Receive определяется по локальному IP, а не по стрелке. Кандидаты: ≥5 успешных Send за ≥3 с без Receive, ≥2 Retransmit, ≥2 Reconnect либо ошибка операции. Ошибка может быть локальной. Если есть Receive, повторные передачи всё равно могут требовать проверки.' if mode=='procmon' else 'Это агрегированные байты NetLimiter, не пакеты и не последовательность событий. Кандидат: исходящие байты >0, входящие =0. Порты могут отсутствовать; протокол нельзя определить по названию порта. История может содержать старые попытки; отсутствие входящих байтов не доказывает блокировку. Для точного анализа используйте запись Wireshark.')
    h='''<!doctype html><meta charset="utf-8"><title>GameNetCheck 1.2</title><style>body{font:16px system-ui;margin:30px;color:#163047;background:#f5f8fb}table{border-collapse:collapse;background:white;margin-bottom:25px}td,th{padding:9px;border:1px solid #dde3e8;text-align:left}th{background:#163047;color:white}section{background:white;padding:18px;border-radius:10px}pre{white-space:pre-wrap}</style><h1>GameNetCheck 1.2</h1>'''
    h+='<p>Режим: '+mode+' · Файл: '+html.escape(str(path))+' · Учтено строк: '+str(used)+'</p><section>'+html.escape(explanation)+'</section>'
    labels={'Process':'Процесс','PID':'PID','Protocol':'Протокол','IP':'Удалённый IP','Port':'Порт','LocalPort':'Локальный порт','Scope':'Тип адреса','Status':'Результат','SendEvents':'Send (события)','ReceiveEvents':'Receive (события)','RetransmitEvents':'Retransmit','ReconnectEvents':'Reconnect','SentBytes':'Отправлено, байт','ReceivedBytes':'Получено, байт','SpanSeconds':'Интервал, с','Candidate':'Проверить','FirstTransfer':'Первая передача','LastTransfer':'Последняя передача'}
    keys=list(result[0]);h+='<h2>Соединения</h2>'+table([labels.get(k,k) for k in keys],[[r[k] for k in keys] for r in result])
    groups=collections.defaultdict(set)
    for ip in candidates:groups[str(ipaddress.ip_network(ip+'/24',strict=False))].add(ip)
    h+='<h2>Группировка /24 — не готовые правила</h2>'+table(['/24','Наблюдавшиеся IP'],[(k,', '.join(sorted(v))) for k,v in groups.items()])
    if online:
        h+='<h2>Диапазоны из RDAP и BGP</h2>'+table(['IP','Имя сети','Диапазон RDAP','CIDR','BGP / ASN','UTC / ошибки'],[(n['ip'],n.get('network_name',''),n.get('range_start','')+' — '+n.get('range_end',''),', '.join(n.get('cidrs',[])),n.get('bgp_prefix','')+' / '+', '.join(n.get('asns',[])),n.get('checked_utc','')+'; '+ '; '.join(n.get('errors',[]))) for n in networks])
        h+='<p>Зарегистрированная сеть и BGP-маршрут могут включать сторонние сервисы. Не направляйте всю сеть автоматически. Полные сведения и источники: networks.json.</p>'
        for n in networks:
            for k in ('rdap_source','bgp_source'):
                u=n.get(k,'')
                if u.startswith('https://'):h+='<p>'+html.escape(n['ip'])+' <a href="'+html.escape(u,quote=True)+'">'+k+'</a></p>'
    h+='<h2>Ограничения и пропуски</h2><p>Fake-IP, локальные, multicast и IPv6 показаны, но не попадают в правила /32 и интернет-запросы. Для Fake-IP нужен журнал Podkop. Сайты внутри одного процесса не разделяются. Закрывайте посторонние вкладки. CSV с именами хостов вместо числовых адресов необходимо экспортировать с отключённым Resolve Network Addresses. PML не поддерживается.</p><pre>'+html.escape(json.dumps(dict(warnings),ensure_ascii=False,indent=2))+'</pre>'
    (out/'report.html').write_text(h,encoding='utf-8');return out,result
