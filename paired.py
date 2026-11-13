"""Pair packet captures with Procmon events or NetLimiter address history."""
import bisect,collections,csv,datetime,html,ipaddress,json,pathlib,math
from csv_modes import detect,appname,field,endpoint,scope


def parse_date_time(value):
    value=value.strip().replace(',', '.')
    for fmt in ('%d.%m.%Y %H:%M:%S', '%d.%m.%Y %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f'):
        try:return datetime.datetime.strptime(value,fmt)
        except ValueError:pass
    raise ValueError('Date & Time: ожидается DD.MM.YYYY HH:MM:SS или YYYY-MM-DD HH:MM:SS')


def seconds_of_day(value):
    parts=value.strip().replace(',', '.').split(':')
    hh,mm,ss=int(parts[0]),int(parts[1]),float(parts[2])
    if len(parts)!=3 or not (0<=hh<24 and 0<=mm<60 and 0<=ss<60):raise ValueError('Time of Day')
    return hh*3600+mm*60+ss


def build_procmon(rows,local_ip,date,utc_offset,shift,warnings):
    # With no override, use the analysis computer's local timezone for each date.
    # This handles historic offsets better than copying today's fixed UTC offset.
    tz=datetime.timezone(datetime.timedelta(hours=utc_offset)) if utc_offset is not None else None
    fallback=datetime.date.fromisoformat(date) if date else None
    result=collections.defaultdict(list);previous=None;day=0
    for row in rows:
        op=row.get('Operation','')
        if not op.startswith(('TCP ','UDP ')):continue
        try:
            full=row.get('Date & Time','').strip()
            tod=row.get('Time of Day','').strip()
            if full:
                dt=parse_date_time(full)
                sec=seconds_of_day(tod) if tod else dt.hour*3600+dt.minute*60+dt.second+dt.microsecond/1e6
                if tod and int(sec)!=dt.hour*3600+dt.minute*60+dt.second:
                    warnings['Procmon: Date & Time и Time of Day противоречат друг другу']+=1;continue
                midnight=datetime.datetime.combine(dt.date(),datetime.time())
                # Convert full wall-clock datetime, then restore subsecond precision.
                wall=midnight+datetime.timedelta(seconds=int(sec))
                t=(wall.replace(tzinfo=tz).timestamp() if tz else wall.timestamp())+(sec-int(sec))+shift
                if not tod:warnings['Procmon: без Time of Day точность ограничена Date & Time']+=1
            else:
                if fallback is None:raise ValueError('Нет даты')
                sec=seconds_of_day(tod)
                if previous is not None and sec<previous-43200:day+=1
                wall=datetime.datetime.combine(fallback+datetime.timedelta(days=day),datetime.time())+datetime.timedelta(seconds=int(sec))
                t=(wall.replace(tzinfo=tz).timestamp() if tz else wall.timestamp())+(sec-int(sec))+shift
                previous=sec
        except (KeyError,ValueError,IndexError,OverflowError):warnings['Procmon: не распознана дата/время события']+=1;continue
        try:a,b=map(endpoint,row['Path'].split(' -> '))
        except (KeyError,ValueError):warnings['Procmon: имена хостов или нераспознанный Path']+=1;continue
        if a[0]==local_ip:local,remote=a,b
        elif b[0]==local_ip:local,remote=b,a
        else:warnings['Procmon: другой локальный IP']+=1;continue
        if ':' in remote[0]:warnings['Procmon: IPv6 не сопоставляется с PCAP']+=1;continue
        key=(6 if op.startswith('TCP') else 17,local[1],remote[0],remote[1])
        result[key].append((t,appname(row),row.get('PID',''),op,row.get('Result','')))
    for v in result.values():v.sort()
    if not result:raise ValueError('Нет подходящих событий Procmon. Проверьте Date & Time, Time of Day, IP ПК и числовые адреса.')
    return result


def packet_index(capture,local_ip,warnings):
    from GameNetCheck import packets,decode
    from names import Collector
    names=Collector(local_ip,warnings)
    flows=collections.defaultdict(list);start=None;end=None;num=0
    for t,link,buf in packets(capture,warnings):
        num+=1;start=t if start is None else min(start,t);end=t if end is None else max(end,t)
        names.feed(t,link,buf)
        p=decode(link,buf,warnings)
        if not p:continue
        (proto,src,sp,dst,dp),size,flags=p
        if src==local_ip:key=(proto,sp,dst,dp);outgoing=True
        elif dst==local_ip:key=(proto,dp,src,sp);outgoing=False
        else:continue
        if ipaddress.ip_address(key[2]).is_multicast:continue
        flows[key].append((t,outgoing,size,flags))
    for v in flows.values():v.sort()
    if not num or not flows:raise ValueError('В захвате нет IPv4 TCP/UDP для указанного IP ПК.')
    names.finish()
    return flows,start,end,num,names


def metrics(packets):
    sent=[p for p in packets if p[1]];received=[p for p in packets if not p[1]]
    span=sent[-1][0]-sent[0][0] if sent else 0
    repeat=len(sent)>=5 and span>=3 and not received
    rst=sum(bool(p[3]&4) for p in received)
    status='Повторяется без ответов' if repeat else ('Нет ответа: мало данных' if sent and not received else ('Есть ответы' if received else 'Нет пакетов в окне'))
    if rst:status='Получен TCP RST'
    return {'Sent':len(sent),'Received':len(received),'SentPayloadBytes':sum(p[2] for p in sent),'ReceivedPayloadBytes':sum(p[2] for p in received),'SpanSeconds':round(span,3),'RST':rst,'Status':status,'Suspicious':repeat or bool(rst)}


def match_procmon(key,packets,index,process,tolerance):
    events=index.get(key,[]);times=[x[0] for x in packets];owners={};allowners=set()
    for event in events:
        t,app,pid,op,res=event
        lo=bisect.bisect_left(times,t-tolerance);hi=bisect.bisect_right(times,t+tolerance)
        if lo==hi:continue
        owner=(app,pid);allowners.add(owner)
        owners.setdefault(owner,{'indices':set(),'ops':collections.Counter(),'errors':0})
        z=owners[owner];z['indices'].update(range(lo,hi));z['ops'][op]+=1;z['errors']+=int(res!='SUCCESS')
    target={o:z for o,z in owners.items() if not process or o[0].lower()==process.lower()}
    if not target:
        return 'Нет совпадения выбранного процесса' if owners else 'Нет совпадения по времени и 5-tuple',[],[],[],0,0,False
    # Conservatively do not assign a tuple reused by different PIDs to one process.
    ambiguous=len(allowners)>1
    indices=sorted(set().union(*(z['indices'] for z in target.values())))
    ops=collections.Counter()
    for z in target.values():ops.update(z['ops'])
    return ('Неоднозначно: несколько процессов/PID' if ambiguous else '5-tuple + время'),[packets[i] for i in indices],sorted({o[0] for o in target}),sorted({o[1] for o in target}),ops['TCP Retransmit'],ops['TCP Reconnect'],ambiguous


def run(capture,source,local_ip,process='',out=None,online=False,procmon_date=None,utc_offset=None,tolerance=2.0,clock_shift=0.0,expected_mode=None):
    local_ip=str(ipaddress.IPv4Address(local_ip))
    if not math.isfinite(clock_shift):raise ValueError('Сдвиг часов должен быть конечным числом')
    if not 0<=tolerance<=30:raise ValueError('Допуск времени должен быть от 0 до 30 секунд')
    mode,raw=detect(source)
    if expected_mode and mode!=expected_mode:raise ValueError('Выбранный режим не соответствует CSV: '+mode)
    if process and not any(appname(r).lower()==process.lower() for r in raw):raise ValueError('Процесс не найден в CSV: '+process)
    warnings=collections.Counter();flows,start,end,num,names=packet_index(capture,local_ip,warnings)
    owners=collections.defaultdict(set);lognames=collections.defaultdict(set);index={};date_info=''
    if mode=='procmon':
        has_dates=any(r.get('Date & Time','').strip() for r in raw if r.get('Operation','').startswith(('TCP ','UDP ')))
        if not has_dates and procmon_date is None:raise ValueError('CSV не содержит Date & Time. Укажите --procmon-date YYYY-MM-DD или экспортируйте колонку Date & Time.')
        if utc_offset is not None and not -14<=utc_offset<=14:raise ValueError('UTC-смещение должно быть от -14 до +14 часов')
        index=build_procmon(raw,local_ip,procmon_date,utc_offset,clock_shift,warnings)
        timestamps=[e[0] for v in index.values() for e in v]
        if max(timestamps)<start-tolerance or min(timestamps)>end+tolerance:warnings['ВРЕМЯ CSV И PCAP НЕ ПЕРЕСЕКАЕТСЯ: проверьте пару файлов, дату и часовой пояс']=1
        zone=f'UTC{utc_offset:+g}' if utc_offset is not None else 'локальный часовой пояс компьютера анализа (автоматически)'
        dates='колонка Date & Time' if has_dates else str(procmon_date)
        date_info=f'Дата: {dates}; пояс: {zone}; сдвиг {clock_shift:+g} с; допуск ±{tolerance:g} с.'
        if utc_offset is None:warnings['Часовой пояс взят с компьютера анализа. Если CSV экспортирован в другом поясе, задайте --utc-offset']=1
    else:
        for row in raw:
            try:ip=str(ipaddress.IPv4Address(field(row,'IP-адрес','IP Address','IP address')))
            except ValueError:continue
            owners[ip].add(appname(row))
            if not process or appname(row).lower()==process.lower():
                from names import hostname
                name=hostname(field(row,'Имя хоста','Host Name','Host name','Hostname'))
                if name:lognames[ip].add(name)
        warnings['NetLimiter: время, локальный порт, PID и протокол для сопоставления не используются']=1
    result=[]
    for key,ps in flows.items():
        proto,lp,ip,rp=key;category=scope(ip);ambiguous=False;retries=reconnects=0
        if mode=='procmon':
            match,window,apps,pids,retries,reconnects,ambiguous=match_procmon(key,ps,index,process,tolerance)
            matched=bool(window)
        else:
            allapps=owners.get(ip,set());apps=sorted(a for a in allapps if not process or a.lower()==process.lower());pids=[]
            matched=bool(apps);window=ps if matched else [];ambiguous=len(allapps)>1
            match=('Только IP; адрес нескольких приложений' if ambiguous else 'Только IP; слабая привязка') if matched else 'IP отсутствует у выбранного приложения'
        # Statistics in a Procmon match use only packets close to its events.
        m=metrics(window if matched else ps)
        possible=m['Suspicious'] or retries>=2 or reconnects>=2
        candidate=category=='Публичный IPv4' and matched and not ambiguous and possible
        domain,name_source=names.find(key,ps[0][0],ps[-1][0])
        if not domain and lognames.get(ip):domain='; '.join(sorted(lognames[ip]));name_source='Имя хоста NetLimiter (может быть PTR, не домен запроса)'
        result.append({'Domain':domain,'DomainSource':name_source,'NameLookupStatus':'Из записи' if domain else 'Не найдено в записи','Process':'; '.join(apps),'PID':'; '.join(pids),'Match':match,'Matched':matched,'Ambiguous':ambiguous,'Protocol':'TCP' if proto==6 else 'UDP','LocalIP':local_ip,'LocalPort':lp,'IP':ip,'Port':rp,'Scope':category,'Status':m['Status'],'Sent':m['Sent'],'Received':m['Received'],'SentPayloadBytes':m['SentPayloadBytes'],'ReceivedPayloadBytes':m['ReceivedPayloadBytes'],'SpanSeconds':m['SpanSeconds'],'CapturePackets':len(ps),'MatchedPackets':len(window),'ProcmonRetransmit':retries,'ProcmonReconnect':reconnects,'UnassignedSuspicious':bool(possible and not candidate),'Candidate':bool(candidate)})
    result.sort(key=lambda r:(not r['Candidate'],not r['Matched'],not r['UnassignedSuspicious'],-r['Sent']))
    if not any(r['Matched'] for r in result):warnings['НЕТ СОПОСТАВЛЕННЫХ СОЕДИНЕНИЙ: отсутствие кандидатов не означает исправность']=1
    pending=sum(r['UnassignedSuspicious'] for r in result)
    if pending:warnings['Подозрительные потоки без однозначной привязки: проверьте несопоставленные и неоднозначные строки']=pending
    out=pathlib.Path(out or pathlib.Path(capture).parent/('GameNetCheck_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')));out.mkdir(parents=True,exist_ok=False)
    candidates=sorted({r['IP'] for r in result if r['Candidate']},key=ipaddress.ip_address)
    netinfo=[];ptr_results=[]
    if online:
        from netinfo import lookup
        for ip in candidates[:20]:print('RDAP/BGP:',ip,flush=True);netinfo.append(lookup(ip))
        if len(candidates)>20:warnings['Интернет-проверка ограничена первыми 20 IP']+=len(candidates)-20
        (out/'networks.json').write_text(json.dumps(netinfo,ensure_ascii=False,indent=2),encoding='utf-8')
        from names import ptr_lookup
        for ip in candidates[:20]:
            targets=[r for r in result if r['IP']==ip and not r['Domain']]
            if not targets:continue
            print('PTR:',ip,flush=True)
            ptr=ptr_lookup(ip);ptr_results.append(ptr)
            for r in targets:
                r['NameLookupStatus']=ptr['status']+(': '+ptr['error'] if ptr['error'] else '')
                if ptr['names']:r['Domain']='; '.join(ptr['names']);r['DomainSource']='PTR через Google Public DNS (имя сервера, не домен приложения)'
        (out/'name-lookups.json').write_text(json.dumps(ptr_results,ensure_ascii=False,indent=2),encoding='utf-8')

    for r in result:
        if not r['Domain'] and r['NameLookupStatus']=='Не найдено в записи':
            r['NameLookupStatus']+='; PTR '+('не проверялся (не кандидат или лимит 20 IP)' if online else 'отключён (--offline)')
    for filename,items in [('connections.csv',result),('candidates.csv',[r for r in result if r['Candidate']])]:
        with (out/filename).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(result[0]));writer.writeheader();writer.writerows(items)
    rules=['// Кандидаты для ручной проверки. Не доказанные блокировки.', '// PTR и имена реестров НЕ превращаются в доменные правила.']
    for ip in candidates:
        domains=sorted({r['Domain'] for r in result if r['IP']==ip and r['Domain']})
        if domains:rules.append('// Имя: '+'; '.join(domains))
        rules.append(ip+'/32')
    (out/'podkop-candidates.txt').write_text('\n'.join(rules)+'\n',encoding='utf-8-sig')
    metadata={'version':'1.5' ,'mode':mode,'capture':str(capture),'csv':str(source),'local_ip':local_ip,'process':process,'capture_start_utc':datetime.datetime.fromtimestamp(start,datetime.timezone.utc).isoformat(),'capture_end_utc':datetime.datetime.fromtimestamp(end,datetime.timezone.utc).isoformat(),'procmon_date':procmon_date,'utc_offset':utc_offset,'clock_shift':clock_shift,'tolerance':tolerance,'warnings':dict(warnings)}
    (out/'session.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf-8')
    render(out,result,metadata,num,date_info,netinfo,online)
    return out,result


def render(out,rows,meta,num,date_info,netinfo,online):
    esc=html.escape
    def table(headers,data):return '<div class="scroll"><table><tr>'+''.join('<th>'+esc(str(h))+'</th>' for h in headers)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(str(c))+'</td>' for c in row)+'</tr>' for row in data)+'</table></div>'
    page='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GameNetCheck 1.5</title><style>body{font:15px system-ui;background:#f1f5f9;color:#193348;margin:28px}h1{font-size:30px}section{background:white;padding:18px;border-radius:12px;margin:18px 0}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;padding:10px;border-bottom:1px solid #dbe4eb;vertical-align:top}th{background:#17374d;color:white;white-space:nowrap}.warn{border-left:5px solid #e6a029}pre{white-space:pre-wrap}.tag{color:#29615a;font-weight:600}</style><h1>GameNetCheck 1.5</h1>'''
    page+='<p class="tag">Wireshark + '+('Process Monitor' if meta['mode']=='procmon' else 'NetLimiter')+'</p><p>'+esc(meta['capture'])+'<br>'+esc(meta['csv'])+'</p><p>ПК: '+esc(meta['local_ip'])+' · Процесс: '+esc(meta['process'] or 'все')+' · Пакетов в записи: '+str(num)+'</p>'
    page+='<p>Интервал PCAP (UTC): '+esc(meta['capture_start_utc'])+' — '+esc(meta['capture_end_utc'])+'</p><p>'+esc(date_info)+'</p>'
    if meta['warnings']:page+='<section class="warn"><b>Проверьте ограничения</b><pre>'+esc(json.dumps(meta['warnings'],ensure_ascii=False,indent=2))+'</pre></section>'
    if meta['mode']=='procmon':
        text='Сопоставляются протокол, оба IP и оба порта (5-tuple), а также время ± заданный допуск. Счётчики сопоставленных строк включают только пакеты в этих временных окнах. Это корреляция потока, не доказанная привязка каждого пакета к PID: Procmon и захват работают на разных уровнях. Если один tuple встречается у нескольких процессов/PID, строка неоднозначна и исключена из правил. PID мог повторно использоваться в длинной записи.'
    else:text='Сопоставление только по IP из истории приложения. NetLimiter не доказывает принадлежность отдельных пакетов: один IP может использоваться несколькими программами. Счётчики включают весь поток из захвата; время, PID и протокол CSV не используются. Экспортируйте историю за тот же сеанс. IP, встречающийся у нескольких приложений в CSV, исключён из правил как неоднозначный.'
    page+='<section>'+esc(text)+'<p>Кандидаты: повторные отправки без ответа (≥5 пакетов за ≥3 с), полученный TCP RST либо повторные Retransmit/Reconnect Procmon. Это признаки для проверки, а не установленная блокировка. Отсутствие кандидатов не доказывает исправность.</p></section>'
    headers=['Проверить','Сопоставление','Процесс / PID','Тип адреса','Протокол','Удалённый IP:порт','Домен / имя','Источник имени','Проверка имени','Лок. порт','Результат','Отправлено / получено, пакетов','В окне / всего пакетов','Retransmit / Reconnect (события)']
    def row(r):return [r['Candidate'],r['Match'],r['Process']+' / '+r['PID'],r['Scope'],r['Protocol'],r['IP']+':'+str(r['Port']),r['Domain'] or 'Не найден',r['DomainSource'] or '—',r['NameLookupStatus'],r['LocalPort'],r['Status'],str(r['Sent'])+' / '+str(r['Received']),str(r['MatchedPackets'])+' / '+str(r['CapturePackets']),str(r['ProcmonRetransmit'])+' / '+str(r['ProcmonReconnect'])]
    page+='<section><b>Домен / имя</b>: TLS SNI относится к этому TCP-потоку; при ECH видимое имя может быть внешним. DNS-ответ связывает имя с IP, но не с процессом. Имя NetLimiter может быть результатом обратного DNS. PTR — имя сервера, а не доказанный домен приложения. Один IP может обслуживать много доменов. Если имя отсутствует, оно не выдумывается.</section>'
    page+='<h2>Кандидаты для проверки</h2>'+table(headers,[row(r) for r in rows if r['Candidate']])
    page+='<h2>Сопоставленные соединения</h2>'+table(headers,[row(r) for r in rows if r['Matched']])
    page+='<h2>Не сопоставлены с выбранным процессом</h2><p>Эти строки не попадают в правила и интернет-проверку. Они могут относиться к другим приложениям, отсутствовать в CSV или не совпасть по времени.</p>'+table(headers,[row(r) for r in rows if not r['Matched']])
    groups=collections.defaultdict(set)
    for r in rows:
        if r['Candidate']:groups[str(ipaddress.ip_network(r['IP']+'/24',strict=False))].add(r['IP'])
    page+='<h2>Кандидаты по /24 — только группировка</h2>'+table(['/24','Наблюдавшиеся IP'],[(k,', '.join(sorted(v))) for k,v in groups.items()])
    if online:
        page+='<h2>Сети RDAP / BGP</h2>'+table(['IP','Имя сети','Диапазон RDAP','CIDR','BGP / ASN','Проверено UTC / ошибки'],[(n['ip'],n.get('network_name',''),n.get('range_start','')+' — '+n.get('range_end',''),', '.join(n.get('cidrs',[])),n.get('bgp_prefix','')+' / '+', '.join(n.get('asns',[])),n.get('checked_utc','')+'; '+ '; '.join(n.get('errors',[]))) for n in netinfo])
        for n in netinfo:
            for k in ('rdap_source','bgp_source'):
                u=n.get(k,'')
                if u.startswith('https://'):page+='<p>'+esc(n['ip'])+' <a href="'+esc(u,quote=True)+'">'+esc(k)+'</a></p>'
    page+='<section>Fake-IP 198.18.x.x видны в отчёте, но требуют журнала Podkop для определения назначения. Локальные адреса и Fake-IP исключены из интернет-проверки и правил. Анализ PCAP ограничен IPv4 TCP/UDP; IPv6, фрагменты, ICMP и расшифровка TLS не поддерживаются. Multicast исключён. Нельзя определить реальный выход через КЗ по одному захвату на ПК. Сети реестров могут включать сторонние сервисы; диапазоны не добавляются автоматически.</section></html>'
    (out/'report.html').write_text(page,encoding='utf-8')
