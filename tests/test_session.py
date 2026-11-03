import time
from multi_vpn.session import Session
from multi_vpn.model import Profile,RouteRegistry

def test_cancel_while_waiting_for_sms():
    from multi_vpn.session import Cancelled
    session=Session(Profile(),'secret',RouteRegistry(),lambda *a:None)
    session.stop()
    try:session.wait('sms')
    except Cancelled:pass
    else:assert False,'Cancellation must abort authentication wait'

def test_independent_credentials_and_event_queues():
    registry=RouteRegistry()
    a=Session(Profile(),'one',registry,lambda *a:None);b=Session(Profile(),'two',registry,lambda *a:None)
    a.answer('sms','synthetic')
    assert b.answers.empty()
    assert a.wait('sms')=='synthetic'
