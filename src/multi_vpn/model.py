from dataclasses import dataclass,asdict,field
import ipaddress,json,pathlib,sys,threading,uuid,os

@dataclass
class Profile:
    name:str='新连接'
    host:str=''
    port:int=443
    username:str=''
    pin:str=''
    id:str=field(default_factory=lambda:uuid.uuid4().hex)
    legacy_udp:bool=True

def config_dir():
    if os.environ.get('MULTIVPN_DATA_DIR'):
        p=pathlib.Path(os.environ['MULTIVPN_DATA_DIR']);p.mkdir(parents=True,exist_ok=True);return p
    if sys.platform=='win32':base=pathlib.Path(os.environ.get('APPDATA',pathlib.Path.home()))
    else:base=pathlib.Path.home()/'Library'/'Application Support'
    p=base/'MultiVPN';p.mkdir(parents=True,exist_ok=True);return p

class Store:
    def __init__(self):self.path=config_dir()/'profiles.json'
    def load(self):
        if not self.path.exists():return []
        return [Profile(**p) for p in json.loads(self.path.read_text(encoding='utf-8'))]
    def save(self,profiles):
        temp=self.path.with_suffix('.tmp')
        temp.write_text(json.dumps([asdict(p) for p in profiles],ensure_ascii=False,indent=2),encoding='utf-8')
        temp.replace(self.path)
    def password(self,profile):
        import keyring
        return keyring.get_password('MultiVPN',profile.id) or ''
    def save_password(self,profile,password):
        import keyring
        keyring.set_password('MultiVPN',profile.id,password)
    def delete_password(self,profile):
        import keyring
        try:keyring.delete_password('MultiVPN',profile.id)
        except keyring.errors.PasswordDeleteError:pass

class RouteRegistry:
    def __init__(self):self.lock=threading.Lock();self.active={}
    def acquire(self,owner,routes):
        networks=[ipaddress.IPv4Network(r) for r in routes]
        if not networks:raise RuntimeError('网关未下发可用内网路由')
        if any(n.prefixlen==0 for n in networks):raise RuntimeError('首版仅支持内网分流，不接管默认路由')
        with self.lock:
            for other,existing in self.active.items():
                if other!=owner and any(a.overlaps(b) for a in networks for b in existing):
                    raise RuntimeError('与另一条已连接 VPN 的网段重叠，请先断开冲突连接')
            self.active[owner]=networks
    def release(self,owner):
        with self.lock:self.active.pop(owner,None)
