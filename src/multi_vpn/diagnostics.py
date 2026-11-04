"""Bounded diagnostic files containing only explicitly permitted fields."""
import hashlib,json,logging,os
from datetime import datetime,timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path


class EventLog:
    fields={'state','error_type','protocol','tx','rx','received','pending_rx','rx_backpressure','send_queue','last_receive_age'}
    def __init__(self,directory,max_bytes=2*1024*1024,backups=3):
        self.path=Path(directory)/'multi-vpn.log';self.handler=None;self.error=None
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            self.handler=RotatingFileHandler(self.path,maxBytes=max_bytes,backupCount=backups,encoding='utf-8')
            if os.name!='nt':os.chmod(self.path,0o600)
            self.handler.setFormatter(logging.Formatter('%(message)s'))
            self.handler.handleError=self._handle_error
        except OSError as error:self.error=type(error).__name__
    def _handle_error(self,record):self.error='LogWriteError'
    def write(self,profile,event,data):
        if self.handler is None:return False
        row={'time':datetime.now(timezone.utc).isoformat(),'profile':hashlib.sha256(profile.encode()).hexdigest()[:16],'event':event}
        for name in self.fields:
            value=data.get(name)
            if isinstance(value,(int,float)) or name=='state' and value in {'connecting','sms','connected','degraded','disconnected'} or name=='protocol' and value in {'legacy','v1'}:
                row[name]=value
            elif name=='error_type' and isinstance(value,str) and value.isidentifier():row[name]=value
        try:
            self.error=None
            self.handler.handle(logging.LogRecord('multi_vpn',logging.INFO,'',0,json.dumps(row,ensure_ascii=False),(),None))
            return self.error is None
        except (OSError,ValueError):return False
    def close(self):
        if self.handler:self.handler.close();self.handler=None
