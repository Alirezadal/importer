import base64, json, re, os, socket, subprocess, tempfile, time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor
import requests
from bs4 import BeautifulSoup

PATTERN = re.compile(r'''(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s<>"']+''')

def decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode()

def collect():
    links = []
    for channel in Path('channels.txt').read_text().splitlines():
        channel = channel.strip().lstrip('@')
        if not channel or channel.startswith('#'): continue
        if not re.fullmatch(r'[A-Za-z0-9_]+', channel): raise ValueError('Invalid channel')
        r = requests.get(f'https://t.me/s/{channel}', timeout=45)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')
        posts = soup.select('.tgme_widget_message[data-post]')
        if not posts: raise RuntimeError('No visible posts; keeping previous output')
        posts.sort(key=lambda p: int(p['data-post'].rsplit('/', 1)[-1]))
        for post in posts[-10:]:
            for msg in post.select('.tgme_widget_message_text'):
                links.extend(PATTERN.findall(msg.get_text(separator='\n')))
                for a in msg.select('a[href]'): links.extend(PATTERN.findall(a['href']))
    return list(dict.fromkeys(links))

def outbound(link):
    scheme = link.split(':', 1)[0]
    if scheme == 'vmess':
        v = json.loads(decode(link.split('://',1)[1].split('#')[0]))
        host, port = v['add'], int(v['port'])
        q = dict(type=v.get('net','tcp'), security=v.get('tls') or 'none', sni=v.get('sni',''), host=v.get('host',''), path=v.get('path',''), headerType=v.get('type','none'), fp=v.get('fp',''))
        settings = {'vnext':[{'address':host,'port':port,'users':[{'id':v['id'],'alterId':int(v.get('aid',0)),'security':v.get('scy','auto')}]}]}
    elif scheme in ('vless','trojan'):
        u = urlsplit(link); host, port = u.hostname, u.port
        q = {k:v[0] for k,v in parse_qs(u.query).items()}
        if scheme == 'vless':
            user = {'id':unquote(u.username or ''),'encryption':q.get('encryption','none')}
            if q.get('flow'): user['flow'] = q['flow']
            settings = {'vnext':[{'address':host,'port':port,'users':[user]}]}
        else:
            settings = {'servers':[{'address':host,'port':port,'password':unquote(u.username or '')}]}
    elif scheme == 'ss':
        raw = link[5:].split('#')[0]
        if '?' in raw: raise ValueError('SS plugin/options unsupported')
        if '@' not in raw: raw = decode(raw)
        auth, addr = raw.rsplit('@',1)
        auth = unquote(auth)
        if ':' not in auth: auth = decode(auth)
        method, password = auth.split(':',1)
        u = urlsplit('ss://'+addr)
        return {'protocol':'shadowsocks','settings':{'servers':[{'address':u.hostname,'port':u.port,'method':method,'password':password}]}}
    else: raise ValueError('Unsupported protocol')
    network = q.get('type','tcp'); security = q.get('security','tls' if scheme=='trojan' else 'none')
    if network not in ('tcp','raw','ws','grpc','httpupgrade','xhttp','splithttp'): raise ValueError('Unsupported transport')
    if security not in ('none','tls','reality'): raise ValueError('Unsupported security')
    stream = {'network':network,'security':security}
    if security == 'tls':
        tls = {'serverName':q.get('sni') or host,'allowInsecure':q.get('allowInsecure')=='1'}
        if q.get('fp'): tls['fingerprint']=q['fp']
        if q.get('alpn'): tls['alpn']=q['alpn'].split(',')
        stream['tlsSettings']=tls
    if security == 'reality':
        stream['realitySettings']={'serverName':q.get('sni',''),'fingerprint':q.get('fp') or 'chrome','publicKey':q.get('pbk',''),'shortId':q.get('sid',''),'spiderX':q.get('spx','')}
    if network == 'ws': stream['wsSettings']={'path':q.get('path') or '/', 'headers':{'Host':q['host']} if q.get('host') else {}}
    if network == 'grpc': stream['grpcSettings']={'serviceName':q.get('serviceName') or q.get('path',''),'multiMode':q.get('mode')=='multi','authority':q.get('authority','')}
    if network in ('httpupgrade','xhttp','splithttp'):
        opts={'path':q.get('path') or '/', 'host':q.get('host','')}
        if network != 'httpupgrade':
            opts['mode']=q.get('mode','auto')
            if q.get('extra'): opts['extra']=json.loads(q['extra'])
        stream[network+'Settings']=opts
    if network in ('tcp','raw') and q.get('headerType')=='http':
        stream['tcpSettings']={'header':{'type':'http','request':{'path':[q.get('path') or '/'],'headers':{'Host':q.get('host','').split(',')}}}}
    return {'protocol':scheme,'settings':settings,'streamSettings':stream}

def test(link):
    try: out = outbound(link)
    except Exception: return 'unsupported', link
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    cfg={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[out]}
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'config.json'; p.write_text(json.dumps(cfg))
        proc=subprocess.Popen(['xray','run','-c',str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(30):
                if proc.poll() is not None: return 'failed',link
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError: time.sleep(.1)
            for url in ('https://www.gstatic.com/generate_204','https://cp.cloudflare.com/generate_204'):
                if proc.poll() is not None: break
                result=subprocess.run(['curl','-fsS','--noproxy','','--proxy',f'socks5h://127.0.0.1:{port}','--connect-timeout','6','--max-time','12','-o','/dev/null','-w','%{http_code}',url],capture_output=True,text=True)
                if result.returncode==0 and result.stdout=='204': return 'passed',link
            return 'failed',link
        finally:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()

def main():
    subprocess.run(['xray','version'],check=True,stdout=subprocess.DEVNULL)
    links=collect()
    with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(test,links))
    good=[link for status,link in results if status=='passed']
    print('Candidates:',len(links),'Passed:',len(good),'Failed:',sum(s=='failed' for s,_ in results),'Unsupported:',sum(s=='unsupported' for s,_ in results))
    # Successful fetch with zero passing links deliberately publishes an empty list.
    Path('subscription.txt').write_text(base64.b64encode('\n'.join(good).encode()).decode()+'\n',encoding='ascii')

if __name__=='__main__': main()
