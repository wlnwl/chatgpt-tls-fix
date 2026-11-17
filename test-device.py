"""Install and test on an explicitly selected, already authorized rooted Android device."""
import argparse, datetime, json, pathlib, re, subprocess, time, xml.etree.ElementTree as ET
from test_evidence import has_backend_evidence
from network_evidence import recent_http_evidence, has_successful_response

ROOT = pathlib.Path(__file__).resolve().parent
VERSION = ET.parse(ROOT/'AndroidManifest.xml').getroot().get('{http://schemas.android.com/apk/res/android}versionName')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--adb', default='adb')
parser.add_argument('--serial', required=True)
parser.add_argument('--apk', type=pathlib.Path, default=ROOT/f'out/ChatGPT-TLS-Fix-{VERSION}.apk')
parser.add_argument('--require-recovery', action='store_true', help='Also require the ChatGPT composer, no certificate error page, accepted Android API TLS and a recent app HTTP 2xx. Does not send a chat message.')
args = parser.parse_args()
destination = ROOT/'build'/('device-test-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
destination.mkdir(parents=True)
adb = [args.adb, '-s', args.serial]

def call(*parts, timeout=45):
    r = subprocess.run(adb + list(parts), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if r.returncode: raise RuntimeError(f'ADB {parts[0]} failed: {r.stderr[:500]} {r.stdout[:500]}')
    return r.stdout.strip()

def root(command):
    if "'" in command: raise ValueError('Unexpected shell quote')
    return call('shell', "su -c '" + command + "'")

def events_for(pid):
    raw = call('logcat', '-b', 'main', '-d', '--pid='+pid, '-v', 'raw', '-s', 'ChatGPT-TLS:I', '*:S')
    events = []
    for line in raw.splitlines():
        start = line.find('{')
        if start >= 0:
            try: events.append(json.loads(line[start:]))
            except json.JSONDecodeError: pass
    loaded=[e for e in events if e.get('event')=='loaded' and e.get('version')==VERSION]
    # A recycled PID can have older records in logcat; use only the newest module session.
    current_session=loaded[-1].get('session') if loaded else None
    return raw, [e for e in events if current_session and e.get('session')==current_session]

assert args.apk.is_file(), 'Build APK before running device tests.'
assert call('get-state') == 'device'
assert 'uid=0' in root('id'), 'Root access is required only for the one-shot request marker.'
installed = call('shell', 'pm', 'path', 'local.chatgpt.tlsfix')
base = next((x[8:] for x in installed.splitlines() if x.startswith('package:') and x.endswith('/base.apk')), None)
if base: call('pull', base, str(destination/'previous-module.apk'))
package = call('shell', 'dumpsys', 'package', 'com.openai.chatgpt')
guard_expected=bool(re.search(r'versionCode=2630718\b',package) and re.search(r'versionName=1\.2026\.307\b',package))
uid_match = re.search(r'(?:userId|appId)=(\d+)', package)
assert uid_match, 'Cannot determine ChatGPT UID.'
uid = uid_match.group(1)
install_output = call('install', '-r', str(args.apk.resolve()), timeout=60)
assert 'Success' in install_output, install_output
print('Installed module update; original APK backed up.', flush=True)
call('shell', 'am', 'force-stop', 'com.openai.chatgpt')
request = '/data/user/0/com.openai.chatgpt/cache/chatgpt-tlsfix-selftest.request'
root('printf v'+VERSION+' > '+request+'; chown '+uid+':'+uid+' '+request+'; chmod 600 '+request)
try:
    # Allow LSPosed package replacement notification to refresh its module cache.
    time.sleep(3)
    launch = call('shell', 'am', 'start', '-W', '-n', 'com.openai.chatgpt/com.openai.chatgpt.MainActivity')
    pid = call('shell', 'pidof', 'com.openai.chatgpt').split()[0]
    print('Cold-started ChatGPT PID '+pid+'; waiting for explicit self-test completion.', flush=True)
    deadline = time.monotonic()+45
    events=[]
    while time.monotonic()<deadline:
        time.sleep(2)
        raw, events = events_for(pid)
        if any(e.get('event') == 'self_test_complete' for e in events): break
    (destination/'selftest-log.txt').write_text(raw, encoding='utf-8')
    (destination/'selftest-events.json').write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding='utf-8')
    complete=[e for e in events if e.get('event')=='self_test_complete']
    asserts=[e for e in events if e.get('event')=='self_test_assert']
    required={'conscrypt_original_rejects','conscrypt_failed_then_bypassed','conscrypt_out_of_scope_preserved',
              'conscrypt_valid_unchanged','handshake_observer'}
    capability=[e for e in events if e.get('event')=='self_test_capability' and e.get('backend')=='cronet']
    cronet_throws=any(e.get('outcome')=='original_verifier_throws' for e in capability)
    required.update({'cronet_original_throw_observed','cronet_throw_logged_and_preserved','cronet_out_of_scope_throw_preserved'}
                    if cronet_throws else {'cronet_original_rejects','cronet_failed_then_bypassed','cronet_out_of_scope_preserved'})
    passed={e.get('backend') for e in asserts if e.get('outcome')=='pass' and e.get('source')=='self_test'}
    backend_evidence=has_backend_evidence(events, cronet_throws)
    success=bool(complete) and complete[-1].get('outcome')=='pass' and required<=passed and backend_evidence and all(e.get('outcome')=='pass' for e in asserts)
    print(json.dumps({'self_test_passed':success,'assertions':len(asserts),'completion':complete},ensure_ascii=False), flush=True)
finally:
    root('rm -f '+request)

# Restart without the marker: separate real traffic from controlled fixture verification.
call('shell', 'am', 'force-stop', 'com.openai.chatgpt')
call('shell', 'am', 'start', '-W', '-n', 'com.openai.chatgpt/com.openai.chatgpt.MainActivity')
live_pid=call('shell','pidof','com.openai.chatgpt').split()[0]
print('Observing live-only cold start PID '+live_pid+' for 35 seconds.',flush=True)
time.sleep(35)
raw,live=events_for(live_pid)
(destination/'live-log.txt').write_text(raw,encoding='utf-8')
(destination/'live-events.json').write_text(json.dumps(live,ensure_ascii=False,indent=2),encoding='utf-8')
call('shell','uiautomator','dump','/data/local/tmp/chatgpt-tlsfix-test-window.xml')
xml=call('shell','cat','/data/local/tmp/chatgpt-tlsfix-test-window.xml')
call('shell','rm','-f','/data/local/tmp/chatgpt-tlsfix-test-window.xml')
app_nodes=[node for node in ET.fromstring(xml).iter('node') if node.get('package')=='com.openai.chatgpt']
texts=[node.get('text','') for node in app_nodes]
certificate_screen=any('非预期的 SSL' in t or '网络配置问题' in t for t in texts)
composer_marker=any(node.get('content-desc') in ('开始语音对话','Start voice mode','Start voice conversation') for node in app_nodes)
chat_input=composer_marker and any(node.get('class')=='android.widget.EditText' for node in app_nodes)
accepted_hosts=sorted({e.get('host') for e in live if e.get('event')=='verification_accepted' and e.get('host')})
recovery_passed=not certificate_screen and chat_input and 'android.chat.openai.com' in accepted_hosts
http_rows=[]
http_evidence_error=None
if args.require_recovery:
    try:
        loaded_times=[e['time_ms'] for e in live if e.get('event')=='loaded']
        assert loaded_times, 'No current process load timestamp'
        paths=root('find /data/user/0/com.openai.chatgpt/cache/sentry -maxdepth 3 -name breadcrumbs.json -type f')
        for path in paths.splitlines():
            if re.fullmatch(r'/data/user/0/com\.openai\.chatgpt/cache/sentry/[0-9a-f]+/\.scope-cache/breadcrumbs\.json',path):
                http_rows.extend(recent_http_evidence(root('cat '+path),max(loaded_times)))
    except Exception as error:
        http_evidence_error=type(error).__name__
    (destination/'app-http-status.json').write_text(json.dumps(http_rows,indent=2),encoding='utf-8')
http_success=has_successful_response(http_rows)
no_test_events=not any(e.get('source')=='self_test' for e in live)
live_ready=any(e.get('event')=='loaded' and e.get('version')==VERSION for e in live) and \
           {'conscrypt','cronet','handshake'}<={e.get('backend') for e in live if e.get('event')=='hook_registered'} and \
           any(e.get('event')=='summary' for e in live)
if complete:
    live_ready=live_ready and all(e.get('session')!=complete[-1].get('session') for e in live)
guard_registered=any(e.get('event')=='guard_registered' and e.get('backend')=='network_error_mapper' and
                     e.get('outcome')=='app_1.2026.307_transport_only' for e in live)
guard_passed=guard_registered or not guard_expected
report={'self_test_passed':success,'assertion_count':len(asserts),'live_only_passed':no_test_events and live_ready,
        'backend_evidence_passed':backend_evidence,
        'cronet_device_test_mode':'original_exception_preservation' if cronet_throws else 'nonzero_status_bypass',
        'cronet_capability':capability,
        'live_event_count':len(live),'certificate_screen_present':certificate_screen,
        'chat_input_present':chat_input,'composer_marker_present':composer_marker,
        'accepted_hosts':accepted_hosts,'startup_tls_recovery_passed':recovery_passed,
        'app_http_success_observed':http_success,'http_evidence_error':http_evidence_error,
        'http_status_counts':{str(status):sum(e['status_code']==status for e in http_rows) for status in sorted({e['status_code'] for e in http_rows})},
        'transport_guard_expected':guard_expected,'transport_guard_registered':guard_registered,
        'module_package_version':[line.strip() for line in call('shell','dumpsys','package','local.chatgpt.tlsfix').splitlines() if 'versionName=' in line or 'versionCode=' in line],
        'live_events_by_type':{kind:sum(e.get('event')==kind for e in live) for kind in sorted({e.get('event','unknown') for e in live})}}
(destination/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
print('Evidence: '+str(destination))
raise SystemExit(0 if success and no_test_events and live_ready and guard_passed and ((recovery_passed and http_success) or not args.require_recovery) else 1)
