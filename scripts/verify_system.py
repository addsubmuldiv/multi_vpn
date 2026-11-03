"""Manual integration acceptance: ordinary OS socket + selected interface, no custom TCP stack."""
import argparse,ipaddress,json,socket,subprocess,threading,time
from multi_vpn.model import Store,RouteRegistry
from multi_vpn.session import Session

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--profile',required=True);parser.add_argument('--target',required=True)
    parser.add_argument('--log',required=True);args=parser.parse_args()
    log=open(args.log,'w',encoding='utf-8',buffering=1);connected=threading.Event();details={};error=[]
    def emit(id,name,data):
        log.write(json.dumps({'event':name,**data},ensure_ascii=False)+'\n')
        if name=='connected':details.update(data);connected.set()
        if name=='error':error.append(data['message']);connected.set()
    store=Store();profile=next(p for p in store.load() if p.id==args.profile)
    session=Session(profile,store.password(profile),RouteRegistry(),emit);session.start()
    try:
        if not connected.wait(90):raise RuntimeError('Connection timeout')
        if error:raise RuntimeError(error[0])
        host,port=args.target.rsplit(':',1)
        host=str(ipaddress.IPv4Address(host))
        command=f"Find-NetRoute -RemoteIPAddress '{host}' | Select-Object -First 1 -ExpandProperty InterfaceIndex"
        r=subprocess.run(['powershell.exe','-NoProfile','-Command',command],capture_output=True,text=True,timeout=20)
        indexes=[int(v.strip()) for v in r.stdout.splitlines() if v.strip().isdigit()]
        if details['index'] not in indexes:raise RuntimeError('Windows selected another interface; test is not independent')
        emit(profile.id,'os_route_verified',{'interface_index':details['index'],'target':host})
        with socket.create_connection((host,int(port)),timeout=12) as sock:
            sock.settimeout(12);banner=sock.recv(1024).split(b'\n',1)[0].decode('ascii','replace').strip()
            if not banner.startswith('SSH-'):raise RuntimeError('No SSH banner received')
            emit(profile.id,'ordinary_socket_pass',{'target':args.target,'banner':banner})
        r=subprocess.run(['ssh-keyscan.exe','-T','8','-p',str(int(port)),'-t','ed25519',host],capture_output=True,text=True,timeout=15)
        if 'ssh-ed25519' not in r.stdout:raise RuntimeError('System ssh-keyscan did not complete key exchange')
        emit(profile.id,'system_ssh_keyscan_pass',{'target':host})
    finally:
        session.stop();session.join(40)
        if session.is_alive():raise RuntimeError('Session did not stop')
        emit(profile.id,'cleanup_complete',{})
        log.close()

if __name__=='__main__':main()
