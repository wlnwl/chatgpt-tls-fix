"""Extract only host/status/time from Sentry's bounded breadcrumb storage, including mmap records."""
import datetime
import json
import urllib.parse


def recent_http_evidence(text, since_ms):
    decoder = json.JSONDecoder()
    cursor = 0
    rows = []
    while cursor < len(text):
        start = text.find('{', cursor)
        if start < 0:
            break
        try:
            item, cursor = decoder.raw_decode(text, start)
        except ValueError:
            cursor = start + 1
            continue
        if not isinstance(item, dict) or item.get('category') != 'http':
            continue
        data = item.get('data')
        if not isinstance(data, dict):
            continue
        try:
            timestamp = datetime.datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
            if timestamp.tzinfo is None or timestamp.timestamp() * 1000 < since_ms:
                continue
            host = urllib.parse.urlparse(data.get('url', '')).hostname
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        status = data.get('status_code')
        if host != 'android.chat.openai.com' or type(status) is not int or not 100 <= status <= 599:
            continue
        rows.append({'timestamp':item['timestamp'], 'host':host, 'status_code':status})
    return rows


def has_successful_response(rows):
    return any(200 <= row['status_code'] < 300 for row in rows)
