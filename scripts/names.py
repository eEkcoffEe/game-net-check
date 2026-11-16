"""Observed DNS/SNI names, DNS failures and labelled reverse DNS."""
import collections,concurrent.futures,http.client,ipaddress,json,re,secrets,socket,ssl,struct,time,urllib.parse


def hostname(value):
    value=str(value or '').strip().rstrip('.').lower()
    if len(value)>253 or '.' not in value or not re.fullmatch(r'[a-z0-9_.-]+',value):return ''
    try:ipaddress.ip_address(value);return ''
    except ValueError:return value


def dns_name(data,pos):
    parts=[];end=None;seen=set()
    for _ in range(128):
        if pos>=len(data) or pos in seen:raise ValueError('Invalid DNS name')
        seen.add(pos);n=data[pos]
        if n&0xc0==0xc0:
            if pos+1>=len(data):raise ValueError('DNS pointer')
            if end is None:end=pos+2
            pos=((n&63)<<8)|data[pos+1];continue
        if n&0xc0 or pos+1+n>len(data):raise ValueError('DNS label')
        pos+=1
        if n==0:return '.'.join(parts).lower(),end if end is not None else pos
        parts.append(data[pos:pos+n].decode('ascii'));pos+=n
    raise ValueError('DNS pointer loop')


def dns_message_info(data):
    if len(data)<12:return
    ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',data)
    if flags&0x7800 or qd>64 or qd+an+ns+ar>2048:return
    questions=[];pos=12
    for _ in range(qd):
        name,pos=dns_name(data,pos)
        if pos+4>len(data):raise ValueError('DNS question')
        typ,cls=struct.unpack_from('!HH',data,pos);pos+=4
        questions.append((name,typ,cls))
    return ident,bool(flags&0x8000),flags&15,tuple(questions)


def dns_type_name(value):
    return {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',65:'HTTPS'}.get(value,'TYPE'+str(value))


def dns_rcode_name(value):
    return {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}.get(value,'RCODE '+str(value))


def _dns_type_code(value):
    known={'A':1,'NS':2,'CNAME':5,'SOA':6,'PTR':12,'MX':15,'TXT':16,'AAAA':28,'SRV':33,'HTTPS':65}
    if value in known:return known[value]
    if value.startswith('TYPE'):
        try:return int(value[4:])
        except ValueError:pass
    raise ValueError('Неподдерживаемый тип DNS-запроса: '+str(value))


def _dns_query(name,typ):
    labels=name.rstrip('.').split('.')
    if not name or any(not label for label in labels):raise ValueError('Некорректное DNS-имя')
    encoded=[]
    for label in labels:
        part=label.encode('idna')
        if len(part)>63:raise ValueError('DNS-метка длиннее 63 байт')
        encoded.append(bytes([len(part)])+part)
    qname=b''.join(encoded)+b'\0'
    if len(qname)>255:raise ValueError('DNS-имя длиннее 255 байт')
    ident=secrets.randbits(16);qtype=_dns_type_code(typ)
    question=(name.rstrip('.').lower(),qtype,1)
    return ident,struct.pack('!6H',ident,0x0100,1,0,0,0)+qname+struct.pack('!HH',qtype,1),question


def _dns_response_result(data,ident,question):
    info=dns_message_info(data)
    if not info:raise ValueError('Пустой или некорректный DNS-ответ')
    response_id,is_response,rcode,questions=info
    if response_id!=ident or not is_response or questions!=(question,):
        raise ValueError('DNS-ответ не соответствует запросу')
    name=dns_rcode_name(rcode)
    if rcode==0 and len(data)>=8 and struct.unpack_from('!H',data,6)[0]==0:
        name+=' (без записей)'
    return name


def _dns_check_result(status,rcode='',elapsed_ms=None,error='',reachable=None):
    return {'status':status,'rcode':rcode,'elapsed_ms':elapsed_ms,'error':error,'reachable':reachable}


def _check_dns_server(server,name,typ,protocol):
    started=time.monotonic()
    try:
        address=str(ipaddress.IPv4Address(server))
        ident,query,question=_dns_query(name,typ)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if protocol=='UDP' else socket.SOCK_STREAM) as sock:
            sock.settimeout(2.5)
            sock.connect((address,53))
            if protocol=='TCP':
                sock.sendall(len(query).to_bytes(2,'big')+query)
                header=b''
                while len(header)<2:
                    chunk=sock.recv(2-len(header))
                    if not chunk:raise OSError('TCP DNS соединение закрыто')
                    header+=chunk
                size=int.from_bytes(header,'big')
                if size<12:raise ValueError('Некорректный размер TCP DNS-ответа')
                data=b''
                while len(data)<size:
                    chunk=sock.recv(size-len(data))
                    if not chunk:raise OSError('TCP DNS соединение закрыто')
                    data+=chunk
            else:
                sock.send(query)
                data=sock.recv(65535)
        try:rcode=_dns_response_result(data,ident,question)
        except (ValueError,UnicodeError,struct.error) as exc:
            return _dns_check_result('Некорректный ответ',elapsed_ms=(time.monotonic()-started)*1000,error=str(exc),reachable=True)
        return _dns_check_result('Ответ получен',rcode,(time.monotonic()-started)*1000,reachable=True)
    except socket.timeout:
        return _dns_check_result('Таймаут',elapsed_ms=(time.monotonic()-started)*1000,reachable=False)
    except (OSError,ValueError,UnicodeError) as exc:
        return _dns_check_result('Ошибка проверки',elapsed_ms=(time.monotonic()-started)*1000,error=str(exc),reachable=False)


def _check_doh(provider,name,typ):
    started=time.monotonic()
    https_reachable=False
    strict_fallback=False
    providers={
        'Google':('dns.google','8.8.8.8','/resolve'),
        'Cloudflare':('cloudflare-dns.com','1.1.1.1','/dns-query'),
    }
    host,address,path=providers[provider]
    query=urllib.parse.urlencode({'name':name,'type':typ})

    def request(context):
        with socket.create_connection((address,443),timeout=5) as raw_socket:
            with context.wrap_socket(raw_socket,server_hostname=host) as connection:
                request=('GET '+path+'?'+query+' HTTP/1.1\r\n'
                         +'Host: '+host+'\r\n'
                         +'Accept: application/dns-json\r\n'
                         +'User-Agent: GameNetCheck/1.5\r\n'
                         +'Connection: close\r\n\r\n').encode('ascii')
                connection.sendall(request)
                response=http.client.HTTPResponse(connection)
                response.begin()
                return response.status,response.read(65537)

    try:
        context=ssl.create_default_context()
        try:
            status,raw=request(context)
        except ssl.SSLCertVerificationError as exc:
            strict_flag=getattr(ssl,'VERIFY_X509_STRICT',0)
            verify_message=getattr(exc,'verify_message','') or str(exc)
            if not strict_flag or not (context.verify_flags&strict_flag) or 'Missing Authority Key Identifier' not in verify_message:
                raise
            # Keep CA and hostname verification while tolerating a missing AKI only.
            context=ssl.create_default_context()
            context.verify_flags&=~strict_flag
            status,raw=request(context)
            strict_fallback=True
        https_reachable=True
        if status!=200:
            result=_dns_check_result('HTTP ошибка',elapsed_ms=(time.monotonic()-started)*1000,error='HTTP '+str(status),reachable=True)
            if strict_fallback:result['warning']='TLS-сертификат принят после отключения X.509 strict из-за отсутствующего Authority Key Identifier'
            return result
        if len(raw)>65536:raise ValueError('DoH-ответ слишком большой')
        payload=json.loads(raw)
        if not isinstance(payload,dict) or 'Status' not in payload:
            raise ValueError('В DoH-ответе нет DNS Status')
        try:rcode=int(payload['Status'])
        except (TypeError,ValueError) as exc:raise ValueError('Некорректный DNS Status в DoH-ответе') from exc
        label=dns_rcode_name(rcode)
        if rcode==0 and not payload.get('Answer'):label+=' (без записей)'
        result=_dns_check_result('Ответ получен',label,(time.monotonic()-started)*1000,reachable=True)
        if strict_fallback:result['warning']='TLS-сертификат принят после отключения X.509 strict из-за отсутствующего Authority Key Identifier'
        return result
    except (socket.timeout,TimeoutError):
        return _dns_check_result('Таймаут',elapsed_ms=(time.monotonic()-started)*1000,reachable=https_reachable)
    except (OSError,ValueError,UnicodeError,json.JSONDecodeError,http.client.HTTPException) as exc:
        return _dns_check_result('Ошибка проверки',elapsed_ms=(time.monotonic()-started)*1000,error=str(exc),reachable=https_reachable)


def check_dns_failures(failures,unanswered,online,limit=20):
    items=failures+unanswered
    server_queries=sorted({(item['server'],item['name'],item['type']) for item in items})
    doh_queries=sorted({(item['name'],item['type']) for item in items})
    tested_servers=server_queries[:limit] if online else []
    tested_doh=doh_queries[:limit] if online else []
    results={};tasks={}
    if online:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            for server,name,typ in tested_servers:
                for protocol in ('UDP','TCP'):
                    key=('dns',server,name,typ,protocol)
                    tasks[pool.submit(_check_dns_server,server,name,typ,protocol)]=key
            for name,typ in tested_doh:
                for provider in ('Google','Cloudflare'):
                    key=('doh',provider,name,typ)
                    tasks[pool.submit(_check_doh,provider,name,typ)]=key
            for future in concurrent.futures.as_completed(tasks):
                results[tasks[future]]=future.result()
    skipped=max(0,len(server_queries)-len(tested_servers))+max(0,len(doh_queries)-len(tested_doh))
    for item in items:
        server_key=(item['server'],item['name'],item['type'])
        doh_key=(item['name'],item['type'])
        item['checks']={}
        for protocol in ('UDP','TCP'):
            key=('dns',)+server_key+(protocol,)
            if not online:item['checks']['dns53_'+protocol.lower()]=_dns_check_result('Не запускалась (--offline)')
            elif server_key in tested_servers:item['checks']['dns53_'+protocol.lower()]=results[key]
            else:
                item['checks']['dns53_'+protocol.lower()]=_dns_check_result('Лимит перепроверки')
        for provider in ('Google','Cloudflare'):
            key=('doh',provider)+doh_key
            if not online:item['checks'][provider.lower()+'_doh']=_dns_check_result('Не запускалась (--offline)')
            elif doh_key in tested_doh:item['checks'][provider.lower()+'_doh']=results[key]
            else:
                item['checks'][provider.lower()+'_doh']=_dns_check_result('Лимит перепроверки')
    return skipped


def dns_records(data):
    if len(data)<12:return []
    _,flags,qd,an,ns,ar=struct.unpack_from('!6H',data)
    if not flags&0x8000 or flags&0xf or flags&0x0200 or qd+an+ns+ar>2048:return []
    pos=12;addresses=[];aliases={}
    for _ in range(qd):_,pos=dns_name(data,pos);pos+=4
    for index in range(an+ns+ar):
        name,pos=dns_name(data,pos)
        typ,cls,ttl,n=struct.unpack_from('!HHIH',data,pos);pos+=10;end=pos+n
        if end>len(data):raise ValueError('Truncated DNS record')
        # Only answer records, not unrelated additional/glue records.
        if index<an and cls==1:
            if typ==1 and n==4:addresses.append((str(ipaddress.ip_address(data[pos:end])),name,ttl))
            elif typ==5:
                target,_=dns_name(data,pos);aliases[name]=(target,ttl)
        pos=end
    result=list(addresses)
    for ip,name,ttl in addresses:
        for alias in aliases:
            cur=alias;seen=set();life=ttl
            while cur in aliases and cur not in seen:
                seen.add(cur);cur,at=aliases[cur];life=min(life,at)
                if cur==name:result.append((ip,alias,life));break
    return result


def clienthello_names(data):
    """Parse complete TLS records / ClientHello; no QUIC/ECH decryption."""
    pos=0;handshake=bytearray()
    while pos+5<=len(data):
        typ,major,minor,n=struct.unpack_from('!BBBH',data,pos);pos+=5
        if major!=3 or n>18432 or pos+n>len(data):break
        if typ==22:handshake.extend(data[pos:pos+n])
        elif typ!=20:break
        pos+=n
    pos=0;names=[]
    while pos+4<=len(handshake):
        kind=handshake[pos];n=int.from_bytes(handshake[pos+1:pos+4],'big');pos+=4
        if pos+n>len(handshake):break
        body=handshake[pos:pos+n];pos+=n
        if kind!=1:continue
        p=34
        if len(body)<p+1:continue
        p+=1+body[p]
        if p+2>len(body):continue
        p+=2+int.from_bytes(body[p:p+2],'big')
        if p>=len(body):continue
        p+=1+body[p]
        if p+2>len(body):continue
        limit=p+2+int.from_bytes(body[p:p+2],'big');p+=2
        if limit>len(body):continue
        while p+4<=limit:
            ext,n=struct.unpack_from('!HH',body,p);p+=4;v=body[p:p+n];p+=n
            if len(v)!=n:break
            if ext!=0 or len(v)<2:continue
            q=2;stop=2+int.from_bytes(v[:2],'big')
            if stop>len(v):continue
            while q+3<=stop:
                typ=v[q];nn=int.from_bytes(v[q+1:q+3],'big');q+=3
                if q+nn>stop:break
                if typ==0:
                    try:name=hostname(bytes(v[q:q+nn]).decode('ascii'))
                    except UnicodeDecodeError:name=''
                    if name:names.append(name)
                q+=nn
    return sorted(set(names))


def transport(link,b):
    if link==1:
        if len(b)<14:return
        eth=int.from_bytes(b[12:14],'big');p=14
        while eth in (0x8100,0x88a8):
            if len(b)<p+4:return
            eth=int.from_bytes(b[p+2:p+4],'big');p+=4
        if eth!=0x800:return
        b=b[p:]
    elif link==113:b=b[16:]
    elif link==276:b=b[20:]
    elif link not in (101,228):return
    if len(b)<20 or b[0]>>4!=4 or int.from_bytes(b[6:8],'big')&0x3fff:return
    p=(b[0]&15)*4
    if p<20:return
    q=b[p:int.from_bytes(b[2:4],'big')];proto=b[9]
    if proto not in (6,17) or len(q)<(20 if proto==6 else 8):return
    s=str(ipaddress.ip_address(b[12:16]));d=str(ipaddress.ip_address(b[16:20]));sp,dp=struct.unpack_from('!HH',q)
    if proto==17:return proto,s,sp,d,dp,0,0,q[8:]
    h=(q[12]>>4)*4
    if h<20 or h>len(q):return
    return proto,s,sp,d,dp,int.from_bytes(q[4:8],'big'),q[13],q[h:]


class Collector:
    def __init__(self,local,warnings):
        self.local=local;self.warnings=warnings;self.dns=collections.defaultdict(list);self.sni=collections.defaultdict(list);self.streams={}
        self.dns_queries=collections.defaultdict(list);self.dns_failures=[];self.dns_unanswered=[]
    def dns_message(self,data,t,proto,s,sp,d,dp):
        try:
            info=dns_message_info(data)
            if not info:return
            ident,response,rcode,questions=info
            if response:
                if d!=self.local or sp!=53:return
                key=(proto,ident,d,dp,s,sp,questions)
                matched=bool(self.dns_queries.pop(key,[]))
                if rcode:
                    for name,typ,_ in questions or (('',0,0),):
                        self.dns_failures.append({
                            'time':t,'name':name or '(имя не указано)','type':dns_type_name(typ),
                            'server':s,'protocol':'TCP' if proto==6 else 'UDP',
                            'status':dns_rcode_name(rcode),'query_captured':matched,
                        })
            for ip,name,ttl in dns_records(data):
                name=hostname(name)
                if name:self.dns[ip].append((t,ttl,name))
            if not response and s==self.local and dp==53 and questions:
                key=(proto,ident,s,sp,d,dp,questions)
                self.dns_queries[key].append({
                    'time':t,'name':questions[0][0],'type':dns_type_name(questions[0][1]),
                    'server':d,'protocol':'TCP' if proto==6 else 'UDP',
                })
        except (ValueError,UnicodeDecodeError,struct.error,IndexError):self.warnings['DNS: неполные/неподдерживаемые сообщения при поиске имён']+=1
    def feed(self,t,link,b):
        x=transport(link,b)
        if not x:return
        proto,s,sp,d,dp,seq,flags,payload=x
        if self.local not in (s,d):return
        if proto==17:
            if (s==self.local and dp==53) or (d==self.local and sp==53):
                self.dns_message(payload,t,proto,s,sp,d,dp)
            return
        if not (s==self.local or sp==53 and d==self.local):return
        k=(s,sp,d,dp)
        if flags&2 and k in self.streams:self.finish_stream(k)
        if not payload:return
        if k not in self.streams:
            if len(self.streams)>=512:
                self.warnings['Имена: достигнут лимит 512 TCP-потоков']+=1;return
            self.streams[k]=[]
        chunks=self.streams[k]
        if sum(len(c[2]) for c in chunks)+len(payload)<=65536:chunks.append((seq,t,bytes(payload)))
        else:self.warnings['Имена: TCP-поток ограничен первыми 64 KiB']+=1
    def finish_stream(self,k):
        chunks=self.streams.pop(k,[])
        if not chunks:return
        chunks.sort(key=lambda c:c[0]);data=bytearray();timeline=[];cursor=chunks[0][0];t=min(c[1] for c in chunks)
        for seq,when,b in chunks:
            if seq>cursor:break # Do not invent bytes across capture gaps.
            skip=cursor-seq
            if skip<len(b):
                start=len(data);data.extend(b[skip:]);timeline.append((start,len(data),when));cursor=seq+len(b)
        s,sp,d,dp=k
        if (s==self.local and dp==53) or (sp==53 and d==self.local):
            pos=0
            while pos+2<=len(data):
                n=int.from_bytes(data[pos:pos+2],'big');pos+=2
                if not n or pos+n>len(data):break
                stamp=max((when for begin,end,when in timeline if begin<pos+n and end>pos),default=t)
                self.dns_message(data[pos:pos+n],stamp,6,s,sp,d,dp);pos+=n
        elif s==self.local:
            for name in clienthello_names(data):self.sni[(6,sp,d,dp)].append((t,name))
    def finish(self):
        for k in list(self.streams):self.finish_stream(k)
        for records in self.dns_queries.values():
            self.dns_unanswered.extend(records)
    def find(self,key,start,end):
        tls=sorted({name for t,name in self.sni.get(key,[]) if start-2<=t<=end+2})
        if tls:return '; '.join(tls),'TLS SNI в этом потоке (видимое имя; при ECH может быть внешним)'
        dns=sorted({name for t,ttl,name in self.dns.get(key[2],[]) if t<=end+2 and t+max(ttl,2)>=start-2})
        if dns:return '; '.join(dns),'DNS-ответ в захвате ПК (не привязан к PID)'
        return '',''


def ptr_lookup(ip):
    from netinfo import cached,fetch
    addr=ipaddress.IPv4Address(ip)
    if not addr.is_global or addr.is_multicast:raise ValueError('PTR only for public IPv4')
    def run():
        url='https://dns.google/resolve?'+urllib.parse.urlencode({'name':addr.reverse_pointer,'type':'PTR'})
        result={'ip':ip,'names':[],'source':url,'status':'','error':''}
        try:
            data=fetch(url);code=data.get('Status')
            if code not in (0,3):raise ValueError('DNS status '+str(code))
            result['names']=sorted({n for rr in data.get('Answer',[]) if rr.get('type')==12 for n in [hostname(rr.get('data',''))] if n})
            result['status']='PTR найден' if result['names'] else 'PTR отсутствует'
        except Exception as exc:result['status']='Ошибка PTR';result['error']=str(exc)
        return result
    return cached('ptr-'+ip,86400,run)
