import base64
import re
from pathlib import Path
from urllib.parse import urlsplit
import requests
from bs4 import BeautifulSoup

pattern = re.compile(r'''(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s<>"']+''')
configs = []
for channel in Path('channels.txt').read_text().splitlines():
    channel = channel.strip().lstrip('@')
    if not channel or channel.startswith('#'):
        continue
    if not re.fullmatch(r'[A-Za-z0-9_]+', channel):
        raise ValueError('Invalid channel name')
    r = requests.get(f'https://t.me/s/{channel}', timeout=45, headers={'User-Agent': 'Mozilla/5.0'})
    r.raise_for_status()
    soup = BeautifulSoup(r.text, 'html.parser')
    found = []
    for msg in soup.select('.tgme_widget_message_text'):
        found.extend(pattern.findall(msg.get_text(separator='\n')))
        for a in msg.select('a[href]'):
            found.extend(pattern.findall(a['href']))
    if not found:
        raise RuntimeError(f'No configurations found in {channel}; keeping previous output')
    configs.extend(found)
configs = list(dict.fromkeys(configs))
if not configs:
    raise RuntimeError('No configurations found')
Path('subscription.txt').write_text(base64.b64encode('\n'.join(configs).encode()).decode()+'\n', encoding='ascii')
print(f'Exported {len(configs)} unique links')
