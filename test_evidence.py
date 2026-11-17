"""Checks backend-specific evidence; counters alone must not satisfy device tests."""
def has_backend_evidence(events, cronet_throws):
    controlled = [event for event in events if event.get('source') == 'self_test']
    def ids(backend, kind):
        return {event['invocation_id'] for event in controlled
                if event.get('backend') == backend and event.get('event') == kind
                and event.get('invocation_id')}
    conscrypt_pair = ids('conscrypt', 'verification_failed') & ids('conscrypt', 'verification_bypassed')
    cronet_failure = ids('cronet', 'verification_failed')
    cronet_bypass = ids('cronet', 'verification_bypassed')
    return bool(conscrypt_pair and cronet_failure and
                (not cronet_bypass if cronet_throws else cronet_failure & cronet_bypass))
