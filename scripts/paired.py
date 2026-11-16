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


def clienthello_times(key,start,end,names):
    # Observed outbound TLS ClientHello times for the same TCP 5-tuple.
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
    ch_times=sorted(ch_times or [])
    ch_no_reply=0
    if proto==6 and ch_times:
        times=[p[0] for p in packets]
        for t in ch_times:
            after=[i for i,x in enumerate(times) if x>t]
            # No later observed server packet after ClientHello is only an observed symptom.
            if not after or all(packets[i][1] for i in after):ch_no_reply+=1
    issues=[]
    if proto==6:
        if sent and not received:
            issues.append('Наблюдение: попытки TCP-подключения без ответа в захвате')
        elif syn and not synack and not rst and not received:
            issues.append('Наблюдение: TCP SYN без наблюдаемого SYN/ACK/RST')
        elif sent_data>0 and recv_data==0 and (received or synack):
            issues.append('Наблюдение: TCP установлен, но после отправки данных дальнейшего прогресса не видно')
        if rst:issues.append('Наблюдение: получен TCP RST')
        if ch_no_reply:issues.append('Наблюдение: отправлен TLS ClientHello, ответ сервера после него не наблюдался')
        if sent and received and not rst and not (sent_data>0 and recv_data==0 and (received or synack)) and not (syn and not synack and not received):
            issues.append('Наблюдение: есть двусторонний обмен; успешность операции приложения неизвестна')
    else:
        # UDP is datagram-based: absence of reply is not by itself a failure.
        if sent and received:
            issues.append('Наблюдение: есть двусторонний UDP-обмен; успешность операции приложения неизвестна')
        elif sent and not received:
            issues.append('Наблюдение: исходящие UDP-пакеты без ответа в захвате (это не означает сбой)')
    if observed:issues.append('Procmon: '+observed)
    if not issues:issues.append('Недостаточно данных')
    attention=bool(issues) and issues!=['Наблюдение: есть двусторонний UDP-обмен; успешность операции приложения неизвестна'] and issues!=['Наблюдение: есть двусторонний обмен; успешность операции приложения неизвестна']
    # Candidate heuristics are intentionally narrower than "needs attention".
    candidate=False
    if proto==6:
        repeat=len(sent)>=5 and span>=3 and not received
        candidate=repeat or bool(rst) or ch_no_reply>0
    return {
        'Sent':len(sent),'Received':len(received),'SentPayloadBytes':sent_data,'ReceivedPayloadBytes':recv_data,
        'SpanSeconds':round(span,3),'RST':rst,'Status':' · '.join(dict.fromkeys(issues)),
        'Suspicious':candidate,'NeedsAttention':attention,'ClientHelloNoReply':ch_no_reply,
    }


def match_procmon(key,packets,index,process,tolerance):
    events=index.get(key,[]);times=[x[0] for x in packets];owners={};allowners=set();unmatched=[]
    for event in events:
        t,app,pid,op,res=event
        lo=bisect.bisect_left(times,t-tolerance);hi=bisect.bisect_right(times,t+tolerance)
        owner=(app,pid);allowners.add(owner)
        if lo==hi:
            unmatched.append((t,app,pid,op,res,owner))
            continue
        owners.setdefault(owner,{'indices':set(),'events':[],'ops':collections.Counter(),'errors':0})
        z=owners[owner];z['indices'].update(range(lo,hi));z['events'].append((t,op,res,lo,hi));z['ops'][op]+=1;z['errors']+=int(res!='SUCCESS')
    target={o:z for o,z in owners.items() if not process or o[0].lower()==process.lower()}
    if not target:
        return 'Нет совпадения выбранного процесса' if owners else 'Нет совпадения по времени и 5-tuple',[],[],[],0,0,False,owners,unmatched
    ambiguous=len(allowners)>1
    indices=sorted(set().union(*(z['indices'] for z in target.values())))
    ops=collections.Counter()
    for z in target.values():ops.update(z['ops'])
    match='Неоднозначно: несколько процессов/PID' if ambiguous else '5-tuple + время'
    return match,[packets[i] for i in indices],sorted({o[0] for o in target}),sorted({o[1] for o in target}),ops['TCP Retransmit'],ops['TCP Reconnect'],ambiguous,target,unmatched


def fmt_time(ts):
    if ts is None:return ''
    return datetime.datetime.fromtimestamp(ts,datetime.timezone.utc).isoformat(timespec='milliseconds')


def split_attempts(owner_data,packets):
    # Separate independent connect attempts when possible; packet-level rows are split by gaps.
    events=sorted(owner_data.get('events',[]),key=lambda x:x[0])
    if not events:return []
    event_groups=[[events[0]]]
    for event in events[1:]:
        prev=event_groups[-1][-1]
        gap=event[0]-prev[0]
        is_send=event[1].endswith(('Connect','Send'))
        if is_send and gap>3 and (prev[1].endswith(('Receive','Disconnect','Retransmit','Reconnect')) or gap>10):
            event_groups.append([event])
        else:event_groups[-1].append(event)
    attempts=[]
    for group in event_groups:
        idx=sorted(set().union(*(set(range(e[3],e[4])) for e in group)))
        attempt_packets=[packets[i] for i in idx] if idx else []
        start=group[0][0];finish=group[-1][0]
        if attempt_packets:
            start=min(start,attempt_packets[0][0]);finish=max(finish,attempt_packets[-1][0])
        attempts.append({'events':group,'packets':attempt_packets,'start':start,'end':finish})
    split=[]
    for attempt in attempts:
        pk=sorted(attempt['packets'],key=lambda x:x[0])
        if not pk:
            split.append(attempt);continue
        bursts=[[pk[0]]]
        for packet in pk[1:]:
            if packet[0]-bursts[-1][-1][0]>3:bursts.append([packet])
            else:bursts[-1].append(packet)
        for burst in bursts:
            ev=[e for e in attempt['events'] if not (e[0]<burst[0][0]-2 or e[0]>burst[-1][0]+2)] or attempt['events']
            split.append({'events':ev,'packets':burst,'start':min(burst[0][0],min(e[0] for e in ev)),'end':max(burst[-1][0],max(e[0] for e in ev))})
    return split


def procmon_event_rows(index,flows,process,tolerance):
    rows=[];times_cache={}
    for key,events in index.items():
        proto,lp,ip,rp=key
        times=times_cache.setdefault(key,[p[0] for p in flows.get(key,[])])
        for t,app,pid,op,res in events:
            if process and app.lower()!=process.lower():continue
            if res=='SUCCESS':continue
            lo=bisect.bisect_left(times,t-tolerance);hi=bisect.bisect_right(times,t+tolerance)
            if lo!=hi:continue # represented in paired flow rows; keep only events without packets in window
            evidence='Пакетов этого 5-tuple в PCAP не найдено' if not flows.get(key) else 'Пакеты 5-tuple есть, но не попали в окно сопоставления ±допуск'
            rows.append({
                'Type':'Ошибка Procmon','Source':'Procmon','Process':app,'PID':pid,'Match':'Событие Procmon (пакетов в окне ±допуск нет)' if flows.get(key) else 'Событие Procmon (пакетов 5-tuple в PCAP нет)',
                'Matched':False,'Ambiguous':False,'Protocol':'TCP' if proto==6 else 'UDP','IP':ip,'Port':rp,'LocalPort':lp,
                'Scope':scope(ip),'Domain':'','DomainSource':'','NameLookupStatus':'Не применимо',
                'Observed':'операция '+op+' завершилась с результатом '+res,
                'Finding':'Наблюдение: Procmon сообщил об ошибке операции; '+evidence.lower(),
                'Check':'Проверьте время, локальный интерфейс и полноту захвата. Отсутствие пакетов может означать локальный отказ, другой интерфейс, неполный захват или несовпадение записей.',
                'Status':'Procmon: '+res,'TimeUTC':fmt_time(t),'Operation':op,'Result':res,
                'Sent':0,'Received':0,'SentPayloadBytes':0,'ReceivedPayloadBytes':0,'SpanSeconds':0,
                'CapturePackets':len(flows.get(key,[])),'MatchedPackets':0,'ProcmonRetransmit':0,'ProcmonReconnect':0,
                'Candidate':False,'NeedsAttention':True,'Evidence':evidence,
            })
    return rows


def category_fake(ip):
    try:return ipaddress.IPv4Address(ip) in ipaddress.ip_network('198.18.0.0/15')
    except Exception:return False


def flow_row(mode,key,category,domain,name_source,m,all_packets,matched_packets,apps,pids,match,matched,ambiguous,retries,reconnects,check='',tstart='',tend='',observed_note=''):
    proto,lp,ip,rp=key
    finding=m['Status'] if m else 'Недостаточно данных'
    check=check or ''
    if observed_note:check=(check+'; ' if check else '')+observed_note
    if mode=='netlimiter' and matched:check=(check+'; ' if check else '')+'Проверка ориентировочная: NetLimiter связан с PCAP только по IP.'
    if category_fake(ip):check=(check+'; ' if check else '')+'Fake-IP: для проверки дальнейшего подключения нужен журнал прокси/Podkop.'
    needs=m['NeedsAttention'] if m else False
    return {
        'Type':'Поток PCAP','Source':'Поток PCAP','Process':'; '.join(apps),'PID':'; '.join(pids),'Match':match,'Matched':matched,'Ambiguous':ambiguous,
        'Protocol':'TCP' if proto==6 else 'UDP','LocalPort':lp,'IP':ip,'Port':rp,'Scope':category,
        'Domain':domain,'DomainSource':name_source,'NameLookupStatus':'Из записи' if domain else 'Не найдено в записи',
        'Finding':finding,'Observed':finding,'Check':check or ('Проверьте повторением, журналом прокси/сервера и другой попыткой' if needs else 'Требуются дополнительные данные'),
        'Status':finding,'TimeUTC':(tstart+(' — '+tend if tend and tend!=tstart else '')) if tstart else '',
        'Operation':'','Result':'','Evidence':'Пакеты в захвате'+(' и сопоставленные события Procmon' if mode=='procmon' and matched and not ambiguous else ''),
        'Sent':m['Sent'] if m else 0,'Received':m['Received'] if m else 0,
        'SentPayloadBytes':m['SentPayloadBytes'] if m else 0,'ReceivedPayloadBytes':m['ReceivedPayloadBytes'] if m else 0,
        'SpanSeconds':m['SpanSeconds'] if m else 0,'CapturePackets':len(all_packets),'MatchedPackets':len(matched_packets),
        'ProcmonRetransmit':retries,'ProcmonReconnect':reconnects,'RST':m['RST'] if m else 0,
        'ClientHelloNoReply':m.get('ClientHelloNoReply',0) if m else 0,
        'Candidate':bool(m and m['Suspicious'] and matched and not ambiguous and category=='Публичный IPv4'),
        'NeedsAttention':needs,
    }


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
        warnings['NetLimiter: привязка слабая (только по IP); принадлежность одному приложению не доказана']=1

    result=[]
    for key,ps in flows.items():
        proto,lp,ip,rp=key;category=scope(ip)
        domain,name_source=names.find(key,ps[0][0],ps[-1][0])
        if not domain and lognames.get(ip):domain='; '.join(sorted(lognames[ip]));name_source='Имя хоста NetLimiter (может быть PTR, не домен запроса)'
        if mode=='procmon':
            match,window,apps,pids,retries,reconnects,ambiguous,target,unmatched=match_procmon(key,ps,index,process,tolerance)
            if target:
                if ambiguous:
                    m=metrics(proto,ps,'неоднозначное сопоставление: один 5-tuple у нескольких процессов/PID',clienthello_times(key,ps[0][0],ps[-1][0],names) if proto==6 else [])
                    result.append(flow_row(mode,key,category,domain,name_source,m,ps,ps,sorted({o[0] for o in target}),sorted({o[1] for o in target}),match,True,True,retries,reconnects,'Сопоставление неоднозначно; строка не доказывает принадлежность процессу.'))
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
                result.append(flow_row(mode,key,category,domain,name_source,m,ps,[],[],[],match,False,False,0,0,'Нет однозначной привязки к событию выбранного процесса.'))
        else:
            allapps=owners.get(ip,set());apps=sorted(a for a in allapps if not process or a.lower()==process.lower())
            matched=bool(apps);ambiguous=len(allapps)>1
            match=('Только IP; адрес встречается у нескольких приложений в CSV' if ambiguous else 'Только IP; слабая привязка NetLimiter') if matched else 'IP отсутствует у выбранного приложения в CSV'
            window=ps if matched else []
            m=metrics(proto,window if matched else ps,('неоднозначное сопоставление по IP' if ambiguous else ''),clienthello_times(key,ps[0][0],ps[-1][0],names) if proto==6 else [])
            result.append(flow_row(mode,key,category,domain,name_source,m,ps,window,apps,[],match,matched,ambiguous,0,0,'Сопоставление NetLimiter выполнено только по IP.' if matched else ''))

    if mode=='procmon':
        result.extend(procmon_event_rows(index,flows,process,tolerance))

    result.sort(key=lambda r:(not r.get('NeedsAttention',False),not r.get('Candidate',False),not r.get('Matched',False),-r.get('Sent',0),r.get('IP',''),str(r.get('Port',''))))
    if not any(r.get('Matched') for r in result):warnings['НЕТ СОПОСТАВЛЕННЫХ СОЕДИНЕНИЙ: отсутствие кандидатов не означает исправность']=1
    pending=sum(1 for r in result if r.get('NeedsAttention') and r.get('Source')=='Поток PCAP' and (not r.get('Matched') or r.get('Ambiguous')))
    if pending:warnings['Подозрительные потоки без однозначной привязки: проверьте несопоставленные и неоднозначные строки']=pending

    from names import check_dns_failures
    skipped_dns_checks=check_dns_failures(names.dns_failures,names.dns_unanswered,online)
    if skipped_dns_checks:warnings['DNS-перепроверка ограничена 20 уникальными запросами']+=skipped_dns_checks

    out=pathlib.Path(out or pathlib.Path(capture).parent/('GameNetCheck_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')));out.mkdir(parents=True,exist_ok=False)
    candidates=sorted({r['IP'] for r in result if r.get('Candidate') and r.get('Source')=='Поток PCAP'},key=ipaddress.ip_address)
    netinfo=[];ptr_results=[]
    if online:
        from netinfo import lookup
        for ip in candidates[:20]:print('RDAP/BGP:',ip,flush=True);netinfo.append(lookup(ip))
        if len(candidates)>20:warnings['Интернет-проверка ограничена первыми 20 IP']+=len(candidates)-20
        (out/'networks.json').write_text(json.dumps(netinfo,ensure_ascii=False,indent=2),encoding='utf-8')
        from names import ptr_lookup
        for ip in candidates[:20]:
            targets=[r for r in result if r.get('IP')==ip and not r.get('Domain') and r.get('Source')=='Поток PCAP']
            if not targets:continue
            print('PTR:',ip,flush=True)
            ptr=ptr_lookup(ip);ptr_results.append(ptr)
            for r in targets:
                r['NameLookupStatus']=ptr['status']+(': '+ptr['error'] if ptr['error'] else '')
                if ptr['names']:r['Domain']='; '.join(ptr['names']);r['DomainSource']='PTR через Google Public DNS (имя сервера, не домен приложения)'
        (out/'name-lookups.json').write_text(json.dumps(ptr_results,ensure_ascii=False,indent=2),encoding='utf-8')

    for r in result:
        if r.get('Source')!='Поток PCAP':continue
        if not r.get('Domain') and r.get('NameLookupStatus','Не найдено в записи').startswith('Не найдено в записи'):
            r['NameLookupStatus']+='; PTR '+('не проверялся (не кандидат или лимит 20 IP)' if online else 'отключён (--offline)')
        if category_fake(r.get('IP')):r['Check']=(r.get('Check')+'; ' if r.get('Check') else '')+'Fake-IP: для проверки дальнейшего подключения нужен журнал прокси/Podkop'

    fieldnames=sorted({k for r in result for k in r.keys()}) if result else ['Type']
    for filename,items in [('connections.csv',result),('candidates.csv',[r for r in result if r.get('Candidate') and r.get('Source')=='Поток PCAP'])]:
        with (out/filename).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=fieldnames);writer.writeheader();writer.writerows(items)
    rules=['// Кандидаты для ручной проверки. Не доказанные блокировки.', '// PTR и имена реестров НЕ превращаются в доменные правила.']
    for ip in candidates:
        domains=sorted({r['Domain'] for r in result if r.get('IP')==ip and r.get('Domain') and r.get('Source')=='Поток PCAP'})
        if domains:rules.append('// Имя: '+'; '.join(domains))
        rules.append(ip+'/32')
    (out/'podkop-candidates.txt').write_text('\n'.join(rules)+'\n',encoding='utf-8-sig')
    metadata={'version':'1.5','mode':mode,'capture':str(capture),'csv':str(source),'local_ip':local_ip,'process':process,'capture_start_utc':datetime.datetime.fromtimestamp(start,datetime.timezone.utc).isoformat(),'capture_end_utc':datetime.datetime.fromtimestamp(end,datetime.timezone.utc).isoformat(),'procmon_date':procmon_date,'utc_offset':utc_offset,'clock_shift':clock_shift,'tolerance':tolerance,'warnings':dict(warnings),'dns_failures':names.dns_failures,'dns_unanswered':names.dns_unanswered}
    (out/'session.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf-8')
    render(out,result,metadata,num,date_info,netinfo,online)
    return out,result


def render(out,rows,meta,num,date_info,netinfo,online):
    esc=html.escape
    def table(headers,data):
        return '<div class="scroll"><table><tr>'+''.join('<th>'+esc(str(h))+'</th>' for h in headers)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(str(c))+'</td>' for c in row)+'</tr>' for row in data)+'</table></div>'
    process=meta['process'] or 'все приложения'
    attention=[r for r in rows if r.get('NeedsAttention')]
    flow_rows=[r for r in rows if r.get('Source')=='Поток PCAP']
    critical_keys=[k for k in ('ВРЕМЯ CSV И PCAP НЕ ПЕРЕСЕКАЕТСЯ: проверьте пару файлов, дату и часовой пояс','НЕТ СОПОСТАВЛЕННЫХ СОЕДИНЕНИЙ: отсутствие кандидатов не означает исправность') if meta['warnings'].get(k)]
    page='''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GameNetCheck 1.5</title><style>body{font:15px system-ui;background:#f1f5f9;color:#193348;margin:28px}h1{font-size:30px;margin-bottom:6px}section{background:white;padding:18px;border-radius:12px;margin:18px 0}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;padding:10px;border-bottom:1px solid #dbe4eb;vertical-align:top}th{background:#17374d;color:white;white-space:nowrap}.warn{border-left:5px solid #e6a029}.ok{border-left:5px solid #4d8b63}.summary{font-size:17px}.muted{color:#4b6072}details>summary{cursor:pointer;font-weight:600;padding:6px 0}pre{white-space:pre-wrap}</style><h1>GameNetCheck 1.5</h1>'''
    page+='<p class="muted">Приложение: <b>'+esc(process)+'</b> · Интервал записи: '+esc(meta['capture_start_utc'])+' — '+esc(meta['capture_end_utc'])+' (UTC)</p>'
    page+='<section class="summary"><b>Краткая сводка:</b> проанализировано соединений/событий — '+str(len(rows))+'; требуют внимания — '+str(len(attention))+'. Режим: Wireshark + '+('Process Monitor' if meta['mode']=='procmon' else 'NetLimiter')+'.</section>'
    if critical_keys:
        crit={k:meta['warnings'][k] for k in critical_keys}
        page+='<section class="warn"><b>Критичные предупреждения о качестве данных</b><pre>'+esc(json.dumps(crit,ensure_ascii=False,indent=2))+'</pre></section>'
    if not attention:
        page+='<section class="ok"><b>Явных признаков сбоя не найдено. Это не подтверждает доступность всех ресурсов.</b></section>'
    if meta['mode']=='netlimiter':
        page+='<section class="warn"><b>Привязка NetLimiter слабая:</b> сопоставление выполняется только по IP. Порт, протокол, PID, время и отдельные попытки из NetLimiter не подтверждаются; принадлежность одному приложению по IP не доказывается.</section>'

    grouped=collections.defaultdict(lambda:{'apps':set(),'dests':set(),'observed':set(),'checks':set(),'count':0})
    for r in attention:
        app=r.get('Process') or process
        if r.get('PID'):app=app+' / '+r['PID']
        dest=r.get('Domain') or r.get('IP') or '—'
        if r.get('IP') and r.get('Port'):dest=str(dest)+':'+str(r['Port'])
        observed=r.get('Finding') or r.get('Status','')
        key=(app,dest,observed,r.get('Check') or '')
        g=grouped[key];g['apps'].add(app);g['dests'].add(dest);g['observed'].add(observed);g['checks'].add(r.get('Check') or 'Требуются дополнительные данные');g['count']+=1
    main=[]
    for g in sorted(grouped.values(),key=lambda x:(-x['count'],str(sorted(x['dests'])))):
        observed='; '.join(sorted(g['observed']))
        if g['count']>1:observed+=' (повторов: '+str(g['count'])+')'
        main.append(('; '.join(sorted(g['apps'])),'; '.join(sorted(g['dests'])),observed,'; '.join(sorted(g['checks']))))
    page+='<h2>Что требует внимания</h2>'
    if main:
        page+='<p class="muted">Таблица показывает наблюдаемые факты и что стоит проверить. Это не утверждение о блокировке.</p>'
        page+=table(['Приложение','Домен / IP','Что обнаружено','Что проверить'],main)
    else:
        page+='<p>Подозрительных ситуаций для основной таблицы нет.</p>'

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
    for item in meta.get('dns_failures',[]):
        status=item['status']+(' (запрос есть в записи)' if item.get('query_captured') else ' (запрос не найден в записи)')
        dns_events.append((item.get('time',0),item.get('name',''),item.get('type',''),item.get('server',''),item.get('protocol',''),status,item))
    for item in meta.get('dns_unanswered',[]):
        dns_events.append((item.get('time',0),item.get('name',''),item.get('type',''),item.get('server',''),item.get('protocol',''),'Ответ не найден в записи',item))
    page+='<details><summary>DNS</summary><p class="muted">DNS-запросы не привязываются к выбранному процессу. Отсутствие ответа в записи не доказывает блокировку.</p>'
    if dns_events:
        dns_events.sort(key=lambda item:item[0])
        page+=table(['Время UTC','Имя запроса','Тип','DNS-сервер','Протокол','Результат в PCAP','DNS-сервер :53 (UDP / TCP)','Google DoH','Cloudflare DoH'],[
            (datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat(timespec='milliseconds') if t else '',name,typ,server,proto,status,
             'UDP: '+check_text(item,'dns53_udp')+'; TCP: '+check_text(item,'dns53_tcp'),
             check_text(item,'google_doh'),check_text(item,'cloudflare_doh'))
            for t,name,typ,server,proto,status,item in dns_events
        ])
    else:page+='<p>Ошибочных DNS-ответов и запросов без ответа в записи не найдено.</p>'
    page+='</details>'

    page+='<details><summary>Несопоставленные события</summary>'
    unmatched=[r for r in rows if r.get('Type')=='Ошибка Procmon' or (r.get('Source')=='Поток PCAP' and not r.get('Matched')) or r.get('Ambiguous')]
    un=[]
    for r in unmatched:
        un.append((r.get('Type',''),r.get('Process','')+' / '+r.get('PID',''),r.get('Match',''),r.get('Protocol',''),(r.get('Domain') or r.get('IP',''))+(':'+str(r.get('Port','')) if r.get('Port') else ''),r.get('Finding') or r.get('Observed',''),r.get('Evidence',''),r.get('TimeUTC',''),r.get('Check','')))
    page+='<p class="muted">Сюда попадают ошибки Procmon без подходящих пакетов в окне, потоки без совпадения по выбранному процессу и неоднозначные сопоставления. Отсутствие пакетов может означать локальный отказ, другой интерфейс, неполный захват или несовпадение записей.</p>'
    page+=table(['Тип','Процесс / PID','Сопоставление','Протокол','Домен / IP:порт','Наблюдение','Основание','Время (UTC)','Что проверить'],un or [('Нет','','','','','','','','')])
    page+='</details>'

    page+='<details><summary>Технические подробности</summary>'
    page+='<p class="muted">ПК: '+esc(meta['local_ip'])+' · Процесс: '+esc(meta['process'] or 'все')+' · Пакетов в записи: '+str(num)+'.</p>'
    page+='<p>'+esc(meta['capture'])+'<br>'+esc(meta['csv'])+'</p><p>'+esc(date_info)+'</p>'
    if meta['warnings']:page+='<section class="warn"><b>Ограничения и предупреждения</b><pre>'+esc(json.dumps(meta['warnings'],ensure_ascii=False,indent=2))+'</pre></section>'
    tech=[]
    for r in rows:
        tech.append((r.get('Type',''),r.get('Source',''),r.get('Process',''),r.get('PID',''),r.get('Match',''),r.get('Protocol',''),r.get('IP',''),r.get('Port',''),r.get('Domain',''),r.get('DomainSource',''),r.get('NameLookupStatus',''),r.get('Status',''),r.get('Sent',0),r.get('Received',0),r.get('CapturePackets',0),r.get('MatchedPackets',0),r.get('ProcmonRetransmit',0),r.get('ProcmonReconnect',0),r.get('Operation',''),r.get('Result',''),r.get('TimeUTC',''),r.get('Evidence','')))
    page+=table(['Тип','Источник','Процесс','PID','Сопоставление','Протокол','IP','Порт','Домен/имя','Источник имени','Проверка имени','Статус','Отпр.','Получ.','Всего пакетов','В окне','Retransmit','Reconnect','Операция','Результат','Время','Основание'],tech)
    if online and netinfo:
        page+='<h3>RDAP / BGP</h3>'+table(['IP','Имя сети','Диапазон RDAP','CIDR','BGP / ASN','Проверено UTC / ошибки'],[(n['ip'],n.get('network_name',''),n.get('range_start','')+' — '+n.get('range_end',''),', '.join(n.get('cidrs',[])),n.get('bgp_prefix','')+' / '+', '.join(n.get('asns',[])),n.get('checked_utc','')+'; '+ '; '.join(n.get('errors',[]))) for n in netinfo])
    page+='<p class="muted">RST и повторные передачи — наблюдаемые симптомы, не автоматическое доказательство блокировки. PTR и владелец сети RDAP не являются доменом, который запросило приложение. Диапазоны не расширяются автоматически. Fake-IP требуют журнала прокси. Полные данные: connections.csv, candidates.csv, session.json, networks.json, name-lookups.json.</p>'
    page+='</details></html>'
    (out/'report.html').write_text(page,encoding='utf-8')
