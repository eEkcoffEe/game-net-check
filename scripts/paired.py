"""Pair packet captures with Procmon events or NetLimiter address history."""
import bisect,collections,csv,datetime,html,ipaddress,json,math,pathlib
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
    tz=datetime.timezone(datetime.timedelta(hours=utc_offset)) if utc_offset is not None else None
    fallback=datetime.date.fromisoformat(date) if date else None
    result=collections.defaultdict(list);previous=None;day=0
    for row in rows:
        op=row.get('Operation','')
        if not op.startswith(('TCP ','UDP ')):continue
        try:
            full=row.get('Date & Time','').strip();tod=row.get('Time of Day','').strip()
            if full:
                dt=parse_date_time(full)
                sec=seconds_of_day(tod) if tod else dt.hour*3600+dt.minute*60+dt.second+dt.microsecond/1e6
                if tod and int(sec)!=dt.hour*3600+dt.minute*60+dt.second:
                    warnings['Procmon: Date & Time и Time of Day противоречат друг другу']+=1;continue
                midnight=datetime.datetime.combine(dt.date(),datetime.time())
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


def clienthello_times(key,start,end,names):
    result=[]
    for t,_ in getattr(names,'sni',{}).get(key,[]):
        if start-2<=t<=end+2:result.append(t)
    return sorted(set(result))


def metrics(proto,packets,observed='',ch_times=None):
    sent=[p for p in packets if p[1]];received=[p for p in packets if not p[1]]
    if not packets and not observed:return None
    span=(max(p[0] for p in packets)-min(p[0] for p in packets)) if packets else 0.0
    rst=sum(bool(p[3]&4) for p in received)
    syn=sum(bool(p[3]&2) and not bool(p[3]&16) for p in sent)
    synack=sum(bool(p[3]&2) and bool(p[3]&16) for p in received)
    recv_data=sum(p[2] for p in received)
    sent_data=sum(p[2] for p in sent)
    late_reply=bool(sent and received and (received[0][0]-sent[0][0])>=3)
    ch_times=sorted(ch_times or []);ch_no_reply=0
    if proto==6 and ch_times:
        times=[p[0] for p in packets]
        for t in ch_times:
            after=[i for i,x in enumerate(times) if x>t]
            if not after or all(packets[i][1] for i in after):ch_no_reply+=1
    issues=[];problem=False
    if proto==6:
        if sent and not received:
            issues.append('Наблюдение: попытки TCP-подключения без ответа в захвате');problem=True
        elif syn and not synack and not rst and not received:
            issues.append('Наблюдение: TCP SYN без наблюдаемого SYN/ACK/RST');problem=True
        elif sent_data>0 and recv_data==0 and (received or synack):
            issues.append('Наблюдение: TCP установлен, но после отправки данных дальнейшего прогресса не видно');problem=True
        if ch_no_reply:
            issues.append('Наблюдение: отправлен TLS ClientHello, ответ сервера после него не наблюдался');problem=True
        if rst:issues.append('Наблюдение: получен TCP RST')
        if late_reply and received:issues.append('Наблюдение: ответ от сервера пришёл с задержкой')
        if sent and received and not rst and not (sent_data>0 and recv_data==0 and (received or synack)) and not (syn and not synack and not received):
            issues.append('Наблюдение: есть двусторонний обмен; успешность операции приложения неизвестна')
    else:
        if sent and received:
            issues.append('Наблюдение: есть двусторонний UDP-обмен; успешность операции приложения неизвестна')
        elif sent and not received:
            issues.append('Наблюдение: исходящие UDP-пакеты без ответа в захвате (это не означает сбой)')
    if observed:issues.append('Procmon: '+observed)
    if not issues:issues.append('Недостаточно данных')
    benign_only=all(x.startswith('Наблюдение: есть двусторонний') for x in issues) and not observed and not rst
    attention=bool(issues) and not benign_only
    # conservative proxy signal: no single RST alone, no UDP no-reply, no retransmit-only
    proxy_issue=problem or bool(observed)
    if proto==17 and not observed:proxy_issue=False
    if proto==6 and rst and not problem and not observed:proxy_issue=False
    return {
        'Sent':len(sent),'Received':len(received),'SentPayloadBytes':sent_data,'ReceivedPayloadBytes':recv_data,
        'SpanSeconds':round(span,3),'RST':rst,'Status':' · '.join(dict.fromkeys(issues)),
        'NeedsAttention':attention,'ProxyIssue':proxy_issue,'LateReply':late_reply,'HadReply':bool(received),
        'Problem':problem,'ClientHelloNoReply':ch_no_reply,
    }


def match_procmon(key,packets,index,process,tolerance):
    events=index.get(key,[]);times=[x[0] for x in packets];owners={};allowners=set()
    for event in events:
        t,app,pid,op,res=event
        lo=bisect.bisect_left(times,t-tolerance);hi=bisect.bisect_right(times,t+tolerance)
        owner=(app,pid);allowners.add(owner)
        if lo==hi:continue
        owners.setdefault(owner,{'indices':set(),'events':[],'ops':collections.Counter()})
        z=owners[owner];z['indices'].update(range(lo,hi));z['events'].append((t,op,res,lo,hi));z['ops'][op]+=1
    target={o:z for o,z in owners.items() if not process or o[0].lower()==process.lower()}
    if not target:
        return 'Нет совпадения выбранного процесса' if owners else 'Нет совпадения по времени и 5-tuple',[],[],[],0,0,False,owners
    ambiguous=len(allowners)>1
    indices=sorted(set().union(*(z['indices'] for z in target.values())))
    ops=collections.Counter()
    for z in target.values():ops.update(z['ops'])
    match='Неоднозначно: несколько процессов/PID' if ambiguous else '5-tuple + время'
    return match,[packets[i] for i in indices],sorted({o[0] for o in target}),sorted({o[1] for o in target}),ops['TCP Retransmit'],ops['TCP Reconnect'],ambiguous,target


def fmt_time(ts):
    if ts is None:return ''
    return datetime.datetime.fromtimestamp(ts,datetime.timezone.utc).isoformat(timespec='milliseconds')


def split_attempts(owner_data,packets):
    # Do not split a TCP flow only because of a pause; late replies are part of same attempt.
    # Separate only clearly independent attempts indicated by Procmon events.
    events=sorted(owner_data.get('events',[]),key=lambda x:x[0])
    if not events:return []
    groups=[[events[0]]]
    for event in events[1:]:
        prev=groups[-1][-1];gap=event[0]-prev[0]
        is_new=event[1].endswith('Connect') and gap>2
        is_send_after_end=event[1].endswith('Send') and prev[1].endswith(('Disconnect','Reconnect')) and gap>1
        if is_new or is_send_after_end:groups.append([event])
        else:groups[-1].append(event)
    attempts=[]
    for group in groups:
        idx=sorted(set().union(*(set(range(e[3],e[4])) for e in group)))
        ap=[packets[i] for i in idx] if idx else []
        start=group[0][0];finish=group[-1][0]
        if ap:start=min(start,ap[0][0]);finish=max(finish,ap[-1][0])
        attempts.append({'events':group,'packets':ap,'start':start,'end':finish})
    return attempts


def procmon_event_rows(index,flows,process,tolerance):
    rows=[];times_cache={}
    for key,events in index.items():
        proto,lp,ip,rp=key
        times=times_cache.setdefault(key,[p[0] for p in flows.get(key,[])])
        for t,app,pid,op,res in events:
            if process and app.lower()!=process.lower():continue
            if res=='SUCCESS':continue
            lo=bisect.bisect_left(times,t-tolerance);hi=bisect.bisect_right(times,t+tolerance)
            if lo!=hi:continue
            evidence='Пакетов этого 5-tuple в PCAP не найдено' if not flows.get(key) else 'Пакеты 5-tuple есть, но не попали в окно сопоставления ±допуск'
            rows.append({
                'Type':'Ошибка Procmon','Source':'Procmon','Process':app,'PID':pid,'Match':'Событие Procmon (пакетов в окне ±допуск нет)' if flows.get(key) else 'Событие Procmon (пакетов 5-tuple в PCAP нет)',
                'Matched':False,'Ambiguous':False,'Protocol':'TCP' if proto==6 else 'UDP','IP':ip,'Port':rp,'LocalPort':lp,
                'Scope':scope(ip),'Domain':'','DomainSource':'','NameLookupStatus':'Не применимо',
                'Finding':'Наблюдение: Procmon сообщил об ошибке операции; '+evidence.lower(),
                'Check':'Проверьте время, интерфейс и полноту захвата. Отсутствие пакетов может означать локальный отказ, другой интерфейс, неполный захват или несовпадение записей.',
                'Status':'Procmon: '+res,'TimeUTC':fmt_time(t),'Operation':op,'Result':res,
                'Sent':0,'Received':0,'SentPayloadBytes':0,'ReceivedPayloadBytes':0,'SpanSeconds':0,
                'CapturePackets':len(flows.get(key,[])),'MatchedPackets':0,'ProcmonRetransmit':0,'ProcmonReconnect':0,
                'Candidate':False,'NeedsAttention':True,'Evidence':evidence,
                'ProxyIssue':True,'LateReply':False,'HadReply':False,
            })
    return rows


def category_fake(ip):
    try:return ipaddress.IPv4Address(ip) in ipaddress.ip_network('198.18.0.0/15')
    except Exception:return False


def exportable_domains(domain,source):
    if not domain or not source:return []
    src=source or ''
    # domains from SNI or justified DNS association only; exclude PTR/RDAP/ambiguous/NetLimiter hostnames
    if 'PTR' in src or 'RDAP' in src or 'NetLimiter' in src:return []
    if not ('TLS SNI' in src or 'DNS' in src):return []
    out=[]
    for name in domain.split(';'):
        name=name.strip().lower().rstrip('.')
        if not name:continue
        try:ipaddress.ip_address(name);continue
        except ValueError:pass
        out.append(name)
    return sorted(set(out))


def flow_row(mode,key,category,domain,name_source,m,all_packets,matched_packets,apps,pids,match,matched,ambiguous,retries,reconnects,check='',tstart='',tend=''):
    proto,lp,ip,rp=key
    finding=m['Status'] if m else 'Недостаточно данных'
    check=check or ''
    if mode=='netlimiter' and matched:check=(check+'; ' if check else '')+'Сопоставление только по IP.'
    if category_fake(ip):check=(check+'; ' if check else '')+'Fake-IP: для проверки нужен журнал прокси/Podkop.'
    needs=m['NeedsAttention'] if m else False
    # never substitute selected app when process not established
    proc='; '.join(apps) if (matched and not ambiguous and apps) else ''
    pidtxt='; '.join(pids) if (matched and not ambiguous and pids) else ''
    proxy_issue=bool(m and m.get('ProxyIssue') and matched and not ambiguous and category=='Публичный IPv4' and not category_fake(ip))
    return {
        'Type':'Поток PCAP','Source':'Поток PCAP','Process':proc,'PID':pidtxt,'Match':match,'Matched':matched,'Ambiguous':ambiguous,
        'Protocol':'TCP' if proto==6 else 'UDP','LocalPort':lp,'IP':ip,'Port':rp,'Scope':category,
        'Domain':domain,'DomainSource':name_source,'NameLookupStatus':'Из записи' if domain else 'Не найдено в записи',
        'Finding':finding,'Check':check or ('Проверьте повторением/журналами' if needs else 'Требуются дополнительные данные'),
        'Status':finding,'TimeUTC':(tstart+(' — '+tend if tend and tend!=tstart else '')) if tstart else '',
        'Operation':'','Result':'','Evidence':'Пакеты в захвате'+(' и сопоставленные события Procmon' if mode=='procmon' and matched and not ambiguous else ''),
        'Sent':m['Sent'] if m else 0,'Received':m['Received'] if m else 0,
        'SentPayloadBytes':m['SentPayloadBytes'] if m else 0,'ReceivedPayloadBytes':m['ReceivedPayloadBytes'] if m else 0,
        'SpanSeconds':m['SpanSeconds'] if m else 0,'CapturePackets':len(all_packets),'MatchedPackets':len(matched_packets),
        'ProcmonRetransmit':retries,'ProcmonReconnect':reconnects,'RST':m['RST'] if m else 0,
        'ClientHelloNoReply':m.get('ClientHelloNoReply',0) if m else 0,
        'Candidate':proxy_issue,'NeedsAttention':needs,'ProxyIssue':bool(m and m.get('ProxyIssue')),
        'LateReply':bool(m and m.get('LateReply')),'HadReply':bool(m and m.get('HadReply')),'Problem':bool(m and m.get('Problem')),
    }


def build_proxy_table(rows):
    groups={}
    for r in rows:
        if r.get('Source')!='Поток PCAP':continue
        if not r.get('Matched') or r.get('Ambiguous'):continue
        ip=r.get('IP','');cat=r.get('Scope','')
        if category_fake(ip):continue
        domains=exportable_domains(r.get('Domain',''),r.get('DomainSource',''))
        targets=domains if domains else ([ip] if cat=='Публичный IPv4' else [])
        for t in targets:
            key=('domain',t) if domains else ('ip',t)
            g=groups.setdefault(key,{'target':t,'kind':key[0],'issues':set(),'replies':False,'late':False,'count':0,'proxy':False})
            g['count']+=1
            if r.get('HadReply') or r.get('Received',0)>0:g['replies']=True
            if r.get('LateReply'):g['late']=True
            if r.get('ProxyIssue'):g['proxy']=True
            f=r.get('Finding','')
            if 'без ответа в захвате' in f and 'UDP' not in f:g['issues'].add('нет ответа в захвате')
            if 'SYN без наблюдаемого' in f:g['issues'].add('SYN без ответа')
            if 'дальнейшего прогресса не видно' in f:g['issues'].add('нет прогресса после отправки данных')
            if 'ClientHello' in f and 'не наблюдался' in f:g['issues'].add('TLS ClientHello без ответа')
            if 'Procmon сообщил об ошибке' in f:g['issues'].add('ошибка Procmon')
            if r.get('LateReply'):g['issues'].add('ответ приходил с задержкой')
    out=[];doms=[];ips=[]
    for g in groups.values():
        if not g['proxy']:continue
        reasons=sorted(g['issues']) or ['наблюдались проблемы соединения']
        if g['replies'] or g['late']:
            action='Сравнить напрямую и через прокси'
            if g['replies']:reasons.append('были и ответы')
        else:
            action='Проверить через прокси'
        reason='; '.join(dict.fromkeys(reasons))
        if g['count']>1:reason+=f' (попыток: {g["count"]})'
        label=g['target'] if g['kind']=='domain' else g['target']+'/32'
        out.append({'Домен/IP':label,'Краткая причина':reason,'Действие':action})
        if g['kind']=='domain':doms.append(g['target'])
        else:ips.append(g['target']+'/32')
    doms=sorted(set(doms));ips=sorted(set(ips),key=lambda x:ipaddress.ip_address(x.split('/')[0]))
    out.sort(key=lambda r:(r['Действие'],r['Домен/IP']))
    return out,doms,ips


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
        if timestamps and (max(timestamps)<start-tolerance or min(timestamps)>end+tolerance):warnings['ВРЕМЯ CSV И PCAP НЕ ПЕРЕСЕКАЕТСЯ: проверьте пару файлов, дату и часовой пояс']=1
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
        warnings['NetLimiter: сопоставление только по IP; принадлежность одному приложению не доказана']=1

    result=[]
    for key,ps in flows.items():
        proto,lp,ip,rp=key;category=scope(ip)
        domain,name_source=names.find(key,ps[0][0],ps[-1][0])
        if not domain and lognames.get(ip):domain='; '.join(sorted(lognames[ip]));name_source='Имя хоста NetLimiter (может быть PTR, не домен запроса)'
        if mode=='procmon':
            match,window,apps,pids,retries,reconnects,ambiguous,target=match_procmon(key,ps,index,process,tolerance)
            if target:
                if ambiguous:
                    m=metrics(proto,ps,'неоднозначное сопоставление: один 5-tuple у нескольких процессов/PID',clienthello_times(key,ps[0][0],ps[-1][0],names) if proto==6 else [])
                    result.append(flow_row(mode,key,category,domain,name_source,m,ps,ps,sorted({o[0] for o in target}),sorted({o[1] for o in target}),match,True,True,retries,reconnects,'Сопоставление неоднозначно; строка показана отдельно.'))
                else:
                    for owner,data in sorted(target.items()):
                        attempts=split_attempts(data,ps)
                        if not attempts:attempts=[{'events':data.get('events',[]),'packets':[ps[i] for i in sorted(data['indices'])],'start':ps[0][0],'end':ps[-1][0]}]
                        for attempt in attempts:
                            ap=attempt['packets'];ev=attempt.get('events',[])
                            observed='; '.join(op+'='+res for _,op,res,_,_ in ev if res!='SUCCESS')
                            ops=collections.Counter(e[1] for e in ev)
                            ch=clienthello_times(key,attempt['start'],attempt['end'],names) if proto==6 else []
                            m=metrics(proto,ap,observed,ch)
                            if not m:continue
                            result.append(flow_row(mode,key,category,domain,name_source,m,ps,ap,[owner[0]],[owner[1]],match,True,False,ops['TCP Retransmit'],ops['TCP Reconnect'],'',fmt_time(attempt['start']),fmt_time(attempt['end'])))
            else:
                m=metrics(proto,ps,'',clienthello_times(key,ps[0][0],ps[-1][0],names) if proto==6 else [])
                result.append(flow_row(mode,key,category,domain,name_source,m,ps,[],[],[],match,False,False,0,0,'Не сопоставлено с выбранным процессом.'))
        else:
            allapps=owners.get(ip,set());apps=sorted(a for a in allapps if not process or a.lower()==process.lower())
            matched=bool(apps);ambiguous=len(allapps)>1
            match=('Только IP; адрес встречается у нескольких приложений в CSV' if ambiguous else 'Только IP; слабая привязка NetLimiter') if matched else 'IP отсутствует у выбранного приложения в CSV'
            window=ps if matched else []
            m=metrics(proto,window if matched else ps,('неоднозначное сопоставление по IP' if ambiguous else ''),clienthello_times(key,ps[0][0],ps[-1][0],names) if proto==6 else [])
            row_apps=apps if (matched and not ambiguous) else []
            result.append(flow_row(mode,key,category,domain,name_source,m,ps,window,row_apps,[],match,matched,ambiguous,0,0,('Сопоставление только по IP.' if matched else '')))

    if mode=='procmon':
        result.extend(procmon_event_rows(index,flows,process,tolerance))

    result.sort(key=lambda r:(not r.get('NeedsAttention',False),not r.get('Matched',False),r.get('IP',''),str(r.get('Port',''))))
    if not any(r.get('Matched') and not r.get('Ambiguous') and r.get('Source')=='Поток PCAP' for r in result):
        warnings['НЕТ ОДНОЗНАЧНО СОПОСТАВЛЕННЫХ СОЕДИНЕНИЙ: отсутствие кандидатов не означает исправность']=1

    from names import check_dns_failures
    skipped_dns_checks=check_dns_failures(names.dns_failures,names.dns_unanswered,online)
    if skipped_dns_checks:warnings['DNS-перепроверка ограничена 20 уникальными запросами']+=skipped_dns_checks

    proxy_rows,proxy_domains,proxy_ips=build_proxy_table(result)

    out=pathlib.Path(out or pathlib.Path(capture).parent/('GameNetCheck_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')));out.mkdir(parents=True,exist_ok=False)
    netinfo=[];ptr_results=[]
    if online:
        from netinfo import lookup
        cand_ips=sorted({r['IP'] for r in result if r.get('Candidate')},key=ipaddress.ip_address)
        for ip in cand_ips[:20]:print('RDAP/BGP:',ip,flush=True);netinfo.append(lookup(ip))
        if len(cand_ips)>20:warnings['Интернет-проверка ограничена первыми 20 IP']+=len(cand_ips)-20
        (out/'networks.json').write_text(json.dumps(netinfo,ensure_ascii=False,indent=2),encoding='utf-8')
        from names import ptr_lookup
        for ip in cand_ips[:20]:
            targets=[r for r in result if r.get('IP')==ip and not r.get('Domain') and r.get('Source')=='Поток PCAP']
            if not targets:continue
            print('PTR:',ip,flush=True)
            ptr=ptr_lookup(ip);ptr_results.append(ptr)
            for r in targets:
                r['NameLookupStatus']=ptr['status']+(': '+ptr['error'] if ptr['error'] else '')
                if ptr['names']:r['Domain']='; '.join(ptr['names']);r['DomainSource']='PTR через Google Public DNS (имя сервера, не домен приложения)'
        (out/'name-lookups.json').write_text(json.dumps(ptr_results,ensure_ascii=False,indent=2),encoding='utf-8')

    fieldnames=sorted({k for r in result for k in r.keys()}) if result else ['Type']
    for filename,items in [('connections.csv',result),('candidates.csv',[r for r in result if r.get('Candidate')])]:
        with (out/filename).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=fieldnames);writer.writeheader();writer.writerows(items)
    rules=['// Кандидаты для ручной проверки. Не доказанные блокировки.']
    for r in proxy_rows:
        rules.append('// '+r['Домен/IP']+' — '+r['Действие'])
        if r['Домен/IP'].endswith('/32'):rules.append(r['Домен/IP'])
    (out/'podkop-candidates.txt').write_text('\n'.join(rules)+'\n',encoding='utf-8-sig')
    metadata={'version':'1.5','mode':mode,'capture':str(capture),'csv':str(source),'local_ip':local_ip,'process':process,'capture_start_utc':datetime.datetime.fromtimestamp(start,datetime.timezone.utc).isoformat(),'capture_end_utc':datetime.datetime.fromtimestamp(end,datetime.timezone.utc).isoformat(),'procmon_date':procmon_date,'utc_offset':utc_offset,'clock_shift':clock_shift,'tolerance':tolerance,'warnings':dict(warnings),'dns_failures':names.dns_failures,'dns_unanswered':names.dns_unanswered}
    (out/'session.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf-8')
    render(out,result,metadata,num,date_info,netinfo,online,proxy_rows)
    return out,result


def render(out,rows,meta,num,date_info,netinfo,online,proxy_rows):
    esc=html.escape
    def table(headers,data):
        return '<div class="scroll"><table><tr>'+''.join('<th>'+esc(str(h))+'</th>' for h in headers)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(str(c))+'</td>' for c in row)+'</tr>' for row in data)+'</table></div>'
    process=meta['process'] or 'все приложения'
    critical_keys=[k for k in ('ВРЕМЯ CSV И PCAP НЕ ПЕРЕСЕКАЕТСЯ: проверьте пару файлов, дату и часовой пояс','НЕТ ОДНОЗНАЧНО СОПОСТАВЛЕННЫХ СОЕДИНЕНИЙ: отсутствие кандидатов не означает исправность') if meta['warnings'].get(k)]
    page='<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetScope 1.5 — диагностика сетевых подключений</title><style>body{font:15px system-ui;background:#f1f5f9;color:#193348;margin:28px}h1{font-size:30px;margin-bottom:6px}section{background:white;padding:18px;border-radius:12px;margin:18px 0}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;padding:10px;border-bottom:1px solid #dbe4eb;vertical-align:top}th{background:#17374d;color:white;white-space:nowrap}.warn{border-left:5px solid #e6a029}.summary{font-size:17px}.muted{color:#4b6072}details>summary{cursor:pointer;font-weight:600;padding:6px 0}pre{white-space:pre-wrap}</style><h1>NetScope 1.5 — диагностика сетевых подключений</h1>'
    page+='<p class="muted">Приложение: <b>'+esc(process)+'</b> · Интервал записи: '+esc(meta['capture_start_utc'])+' — '+esc(meta['capture_end_utc'])+' (UTC) · Режим: Wireshark + '+('Process Monitor' if meta['mode']=='procmon' else 'NetLimiter')+'</p>'
    page+='<section class="summary"><b>Краткий итог:</b> проанализировано записей — '+str(len(rows))+'; кандидатов для проверки через прокси — '+str(len(proxy_rows))+'.</section>'
    if critical_keys:
        crit={k:meta['warnings'][k] for k in critical_keys}
        page+='<section class="warn"><b>Критичные ошибки сопоставления</b><pre>'+esc(json.dumps(crit,ensure_ascii=False,indent=2))+'</pre></section>'
    if meta['mode']=='netlimiter':
        page+='<section class="warn"><b>Сопоставление только по IP (NetLimiter):</b> порт, протокол, PID, время и отдельные попытки не подтверждаются; принадлежность одному приложению по IP не доказывается.</section>'

    page+='<section><h2>Что проверить через прокси</h2>'
    if proxy_rows:
        page+='<p class="muted">Кандидаты для ручной проверки, не доказанные блокировки. Повторные попытки объединены; учитываются поздние ответы.</p>'
        page+=table(['Домен или IP','Краткая причина','Действие'],[(r['Домен/IP'],r['Краткая причина'],r['Действие']) for r in proxy_rows])
    else:
        page+='<p><b>Обоснованных кандидатов для проверки через прокси не найдено. Это не подтверждает доступность всех ресурсов.</b></p>'
    page+='</section>'

    flow_rows=[r for r in rows if r.get('Source')=='Поток PCAP']
    page+='<details><summary>Все соединения</summary>'
    conn=[]
    for r in sorted(flow_rows,key=lambda x:(not x.get('NeedsAttention'),not x.get('Matched'),x.get('IP',''),str(x.get('Port','')))):
        conn.append((r.get('Process','')+' / '+r.get('PID',''),r.get('Match',''),r.get('Protocol',''),(r.get('Domain') or r.get('IP',''))+(':'+str(r.get('Port','')) if r.get('Port') else ''),r.get('Finding',''),str(r.get('Sent',0))+'/'+str(r.get('Received',0)),str(r.get('MatchedPackets',0))+'/'+str(r.get('CapturePackets',0)),r.get('TimeUTC',''),r.get('Check','')))
    page+=table(['Процесс / PID','Сопоставление','Протокол','Домен / IP:порт','Что обнаружено','Отпр./получ. пакетов','В окне / всего','Время (UTC)','Что проверить'],conn or [('Нет данных','','','','','','','','')])
    page+='</details>'

    dns_events=[]
    def check_text(item,key):
        check=item.get('checks',{}).get(key,{})
        reachable=check.get('reachable')
        if reachable is True:parts=['Доступен']
        elif reachable is False:parts=['Не доступен']
        else:parts=[check.get('status','Не запускалась')]
        if check.get('rcode'):parts.append(check['rcode'])
        elif reachable is True and check.get('status')!='Ответ получен':parts.append(check['status'])
        elif reachable is False:parts.append(check.get('status','Ошибка'))
        if check.get('elapsed_ms') is not None:parts.append('%.0f мс'%check['elapsed_ms'])
        if check.get('error'):parts.append(check['error'])
        if check.get('warning'):parts.append(check['warning'])
        return ' · '.join(parts)
    for item in meta.get('dns_failures',[]):dns_events.append((item.get('time',0),item.get('name',''),item.get('type',''),item.get('server',''),item.get('protocol',''),item['status']+(' (запрос есть в записи)' if item.get('query_captured') else ' (запрос не найден в записи)'),item))
    for item in meta.get('dns_unanswered',[]):dns_events.append((item.get('time',0),item.get('name',''),item.get('type',''),item.get('server',''),item.get('protocol',''),'Ответ не найден в записи',item))
    page+='<details><summary>DNS</summary><p class="muted">DNS-запросы не привязываются к процессу. HTTPS REFUSED, PTR NXDOMAIN и отсутствие ответа в записи сами по себе не означают необходимость прокси.</p>'
    if dns_events:
        dns_events.sort(key=lambda item:item[0])
        page+=table(['Время UTC','Имя запроса','Тип','DNS-сервер','Протокол','Результат в PCAP','DNS-сервер :53 (UDP / TCP)','Google DoH','Cloudflare DoH'],[(datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat(timespec='milliseconds') if t else '',name,typ,server,proto,status,'UDP: '+check_text(item,'dns53_udp')+'; TCP: '+check_text(item,'dns53_tcp'),check_text(item,'google_doh'),check_text(item,'cloudflare_doh')) for t,name,typ,server,proto,status,item in dns_events])
    else:page+='<p>Ошибочных DNS-ответов и запросов без ответа в записи не найдено.</p>'
    page+='</details>'

    page+='<details><summary>Несопоставленные события</summary>'
    unmatched=[r for r in rows if r.get('Type')=='Ошибка Procmon' or (r.get('Source')=='Поток PCAP' and (not r.get('Matched') or r.get('Ambiguous')))]
    un=[]
    for r in unmatched:un.append((r.get('Type',''),r.get('Process','')+' / '+r.get('PID',''),r.get('Match',''),r.get('Protocol',''),(r.get('Domain') or r.get('IP',''))+(':'+str(r.get('Port','')) if r.get('Port') else ''),r.get('Finding',''),r.get('Evidence',''),r.get('TimeUTC',''),r.get('Check','')))
    page+='<p class="muted">Чужие, несопоставленные и неоднозначные потоки показаны отдельно и не подставляются выбранному приложению.</p>'
    page+=table(['Тип','Процесс / PID','Сопоставление','Протокол','Домен / IP:порт','Наблюдение','Основание','Время (UTC)','Что проверить'],un or [('Нет','','','','','','','','')])
    page+='</details>'

    page+='<details><summary>Технические подробности</summary>'
    page+='<p class="muted">ПК: '+esc(meta['local_ip'])+' · Процесс: '+esc(meta['process'] or 'все')+' · Пакетов в записи: '+str(num)+'.</p>'
    page+='<p>'+esc(meta['capture'])+'<br>'+esc(meta['csv'])+'</p><p>'+esc(date_info)+'</p>'
    if meta['warnings']:page+='<section class="warn"><b>Ограничения и предупреждения</b><pre>'+esc(json.dumps(meta['warnings'],ensure_ascii=False,indent=2))+'</pre></section>'
    tech=[]
    for r in rows:tech.append((r.get('Type',''),r.get('Process',''),r.get('PID',''),r.get('Match',''),r.get('Protocol',''),r.get('IP',''),r.get('Port',''),r.get('Domain',''),r.get('DomainSource',''),r.get('NameLookupStatus',''),r.get('Status',''),r.get('Sent',0),r.get('Received',0),r.get('CapturePackets',0),r.get('MatchedPackets',0),r.get('ProcmonRetransmit',0),r.get('ProcmonReconnect',0),r.get('Operation',''),r.get('Result',''),r.get('TimeUTC','')))
    page+=table(['Тип','Процесс','PID','Сопоставление','Протокол','IP','Порт','Домен/имя','Источник имени','Проверка имени','Статус','Отпр.','Получ.','Всего','В окне','Retransmit','Reconnect','Операция','Результат','Время'],tech)
    if online and netinfo:
        page+='<h3>RDAP / BGP</h3>'+table(['IP','Имя сети','Диапазон RDAP','CIDR','BGP / ASN','Проверено UTC / ошибки'],[(n['ip'],n.get('network_name',''),n.get('range_start','')+' — '+n.get('range_end',''),', '.join(n.get('cidrs',[])),n.get('bgp_prefix','')+' / '+', '.join(n.get('asns',[])),n.get('checked_utc','')+'; '+ '; '.join(n.get('errors',[]))) for n in netinfo])
    page+='<p class="muted">Один RST, отсутствие UDP-ответа и отдельные DNS-ошибки сами по себе не означают необходимость прокси. PTR/RDAP не являются доменом приложения. Fake-IP и подсети не экспортируются автоматически. Полные данные: connections.csv, candidates.csv, session.json, networks.json, name-lookups.json.</p>'
    page+='</details></html>'
    (out/'report.html').write_text(page,encoding='utf-8')
