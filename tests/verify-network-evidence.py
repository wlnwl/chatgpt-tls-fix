"""Reject stale, foreign, malformed and unsuccessful response evidence."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from network_evidence import recent_http_evidence, has_successful_response

def record(**updates):
    data={'url':'https://android.chat.openai.com/backend-api/test?secret=not-retained','status_code':200}
    data.update(updates)
    return json.dumps({'timestamp':'2026-11-17T14:00:00Z','category':'http','data':data})

valid=recent_http_evidence('\0\x01broken {'+record()+'\0',0)
assert has_successful_response(valid) and len(valid)==1
assert not any('url' in e or 'secret' in str(e) for e in valid)
assert not has_successful_response(recent_http_evidence(record(),9999999999999))
assert not has_successful_response(recent_http_evidence(record(url='https://example.com/'),0))
assert not has_successful_response(recent_http_evidence(record(status_code=403),0))
assert not has_successful_response(recent_http_evidence(record(status_code='200'),0))
assert not has_successful_response(recent_http_evidence('invalid or empty',0))
print('PASS: mmap HTTP evidence accepted; stale, foreign, 403, malformed status and empty evidence rejected; URLs excluded.')
