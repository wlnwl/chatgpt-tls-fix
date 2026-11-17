"""Regression check using a saved successful controlled device event capture."""
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from test_evidence import has_backend_evidence

events=json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
throws=any(e.get('event')=='self_test_capability' and e.get('outcome')=='original_verifier_throws' for e in events)
assert has_backend_evidence(events,throws)
assert not has_backend_evidence([],throws)
assert not has_backend_evidence([e for e in events if e.get('backend')!='cronet'],throws)
assert not has_backend_evidence([e for e in events if e.get('event')!='verification_bypassed'],throws)
assert not has_backend_evidence([dict(e,source='live') for e in events],throws)
print('PASS: actual trace accepted; four incomplete or misclassified traces rejected.')
