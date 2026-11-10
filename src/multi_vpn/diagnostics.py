"""Bounded diagnostic files containing only explicitly permitted fields."""
import hashlib,json,logging,os,queue,threading
from datetime import datetime,timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path


class EventLog:
    fields={'state','error_type','protocol','transport','tx','rx','received','pending_rx','rx_backpressure','tx_backpressure','send_queue','last_receive_age','last_gateway_age','rx_queue_age','tx_queue_age','partial_frame_bytes','log_dropped','udp_invalid'}
    fields.update({'tunnel_tx_bytes','tunnel_tx_frames','tunnel_rx_bytes','discarded_tx','udp_acks','udp_repairs','last_control_age'})
    def __init__(self,directory,max_bytes=2*1024*1024,backups=3):
        self.path=Path(directory)/'multi-vpn.log';self.handler=None;self.error=None
        self.queue=queue.Queue(maxsize=256);self.stopping=threading.Event();self.worker=None
        self.lock=threading.Lock();self.closed=False;self.dropped=0
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            self.handler=RotatingFileHandler(self.path,maxBytes=max_bytes,backupCount=backups,encoding='utf-8')
            if os.name!='nt':os.chmod(self.path,0o600)
            self.handler.setFormatter(logging.Formatter('%(message)s'))
            self.handler.handleError=self._handle_error
            self.worker=threading.Thread(target=self._run,daemon=True,name='MultiVPN-logs');self.worker.start()
        except OSError as error:
            self.error=type(error).__name__
            if self.handler:self.handler.close();self.handler=None
    def _handle_error(self,record):self.error='LogWriteError'
    def _run(self):
        try:
            while not self.stopping.is_set() or not self.queue.empty():
                try:record=self.queue.get(timeout=.1)
                except queue.Empty:continue
                try:
                    self.error=None;self.handler.handle(record)
                    if self.error:
                        with self.lock:self.dropped+=1
                except (OSError,ValueError):
                    with self.lock:self.dropped+=1
                finally:self.queue.task_done()
        finally:self.handler.close();self.handler=None
    def write(self,profile,event,data):
        if self.handler is None or self.closed:return False
        row={'time':datetime.now(timezone.utc).isoformat(),'profile':hashlib.sha256(profile.encode()).hexdigest()[:16],'event':event}
        run_id=data.get('run_id','')
        if isinstance(run_id,str) and len(run_id)==32 and all(character in '0123456789abcdef' for character in run_id):row['run_id']=run_id
        for name in self.fields:
            value=data.get(name)
            if isinstance(value,(int,float)) or name=='state' and value in {'connecting','sms','connected','degraded','disconnected'} or name=='protocol' and value in {'legacy','v1'}:
                row[name]=value
            elif name=='transport' and value in ('udp','tcp'):row[name]=value
            elif name=='error_type' and isinstance(value,str) and value.isidentifier():row[name]=value
        record=logging.LogRecord('multi_vpn',logging.INFO,'',0,json.dumps(row,ensure_ascii=False),(),None)
        with self.lock:
            if self.closed:return False
            try:self.queue.put_nowait(record);return True
            except queue.Full:self.dropped+=1;return False
    def close(self):
        with self.lock:self.closed=True;self.stopping.set()
        if self.worker:self.worker.join(timeout=2)
