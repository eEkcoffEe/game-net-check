"""Observed DNS/SNI names and labelled reverse DNS, without external packages."""
import collections,ipaddress,re,struct,urllib.parse


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
    def dns_message(self,data,t):
        try:
            for ip,name,ttl in dns_records(data):
                name=hostname(name)
                if name:self.dns[ip].append((t,ttl,name))
        except (ValueError,UnicodeDecodeError,struct.error,IndexError):self.warnings['DNS: неполные/неподдерживаемые сообщения при поиске имён']+=1
    def feed(self,t,link,b):
        x=transport(link,b)
        if not x:return
        proto,s,sp,d,dp,seq,flags,payload=x
        if self.local not in (s,d):return
        if proto==17:
            if sp==53 and d==self.local:self.dns_message(payload,t)
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
        if sp==53 and d==self.local:
            pos=0
            while pos+2<=len(data):
                n=int.from_bytes(data[pos:pos+2],'big');pos+=2
                if not n or pos+n>len(data):break
                stamp=max((when for begin,end,when in timeline if begin<pos+n and end>pos),default=t)
                self.dns_message(data[pos:pos+n],stamp);pos+=n
        elif s==self.local:
            for name in clienthello_names(data):self.sni[(6,sp,d,dp)].append((t,name))
    def finish(self):
        for k in list(self.streams):self.finish_stream(k)
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
