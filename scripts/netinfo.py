"""RDAP registration + RIPE RIS BGP information. Standard library only."""
import datetime, ipaddress, json, os, pathlib, time, urllib.request, urllib.parse
BOOTSTRAP = 'https://data.iana.org/rdap/ipv4.json'
CACHE = pathlib.Path(os.environ.get('LOCALAPPDATA', str(pathlib.Path.home()))) / 'GameNetCheck' / 'cache'


def fetch(url):
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise ValueError('Only HTTPS registry endpoints are supported')
    req = urllib.request.Request(url, headers={'Accept':'application/rdap+json, application/json', 'User-Agent':'GameNetCheck/1.1'})
    with urllib.request.urlopen(req, timeout=8) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024: raise ValueError('Registry response is too large')
    return json.loads(raw)


def cached(key, ttl, producer):
    path = CACHE / (key + '.json')
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
        if 0 <= time.time()-obj['time'] < ttl: return obj['value']
    except (OSError, ValueError, KeyError, TypeError): pass
    value = producer()
    try:
        CACHE.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix('.tmp')
        temp.write_text(json.dumps({'time':time.time(),'value':value}),encoding='utf-8')
        temp.replace(path)
    except OSError: pass
    return value


def rdap_url(addr, bootstrap):
    matches=[]
    for networks, urls in bootstrap.get('services', []):
        for text in networks:
            net=ipaddress.ip_network(text)
            if addr in net:
                for url in urls:
                    if url.startswith('https://'):matches.append((net.prefixlen,url))
    if not matches:raise ValueError('No authoritative HTTPS RDAP endpoint in IANA bootstrap')
    base=max(matches,key=lambda p:p[0])[1]
    return base.rstrip('/')+'/ip/'+str(addr)


def parse_rdap(ip, data):
    addr=ipaddress.IPv4Address(ip)
    start=ipaddress.IPv4Address(data['startAddress']);end=ipaddress.IPv4Address(data['endAddress'])
    if not start <= addr <= end:raise ValueError('RDAP range does not contain requested IP')
    cidrs=[str(n) for n in ipaddress.summarize_address_range(start,end)]
    names=[]
    # Only top-level registrant entities; do not label abuse/technical contacts as owner.
    for entity in data.get('entities',[]):
        if 'registrant' not in entity.get('roles',[]):continue
        vc=entity.get('vcardArray',[])
        for entry in vc[1] if len(vc)>1 else []:
            if len(entry)>3 and entry[0] in ('fn','org'):
                name=entry[3]
                if isinstance(name,list):name='; '.join(map(str,name))
                names.append(str(name))
    return {'range_start':str(start),'range_end':str(end),'cidrs':cidrs,
            'address_count':int(end)-int(start)+1,'network_name':data.get('name',''),
            'registrant':'; '.join(dict.fromkeys(names)), 'handle':data.get('handle',''),
            'registry_country':data.get('country','')}


def parse_bgp(ip, payload):
    if payload.get('status') not in (None,'ok'):raise ValueError('RIPEstat returned non-ok status')
    data=payload.get('data',{});prefix=data.get('prefix')
    if prefix:
        net=ipaddress.ip_network(prefix)
        if ipaddress.ip_address(ip) not in net:raise ValueError('BGP prefix does not contain requested IP')
    return {'bgp_prefix':prefix or '', 'asns':[str(a) for a in data.get('asns',[])]}


def lookup(ip):
    addr=ipaddress.IPv4Address(ip)
    if not addr.is_global or addr.is_multicast:raise ValueError('Only public unicast IPv4 addresses can be looked up')
    def run():
        result={'ip':ip,'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'errors':[], 'rdap_source':'', 'bgp_source':'https://stat.ripe.net/data/network-info/data.json?resource='+ip}
        try:
            bootstrap=cached('iana-ipv4',7*86400,lambda:fetch(BOOTSTRAP))
            url=rdap_url(addr,bootstrap);result['rdap_source']=url
            result.update(parse_rdap(ip,fetch(url)))
        except Exception as exc:result['errors'].append('RDAP: '+str(exc))
        try:result.update(parse_bgp(ip,fetch(result['bgp_source'])))
        except Exception as exc:result['errors'].append('BGP: '+str(exc))
        return result
    # Cache successful/partial results for one day; errors remain visible with timestamp.
    return cached('ip-'+ip,86400,run)
