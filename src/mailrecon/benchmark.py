"""Reproducible owned synthetic API dataset, not a real-world accuracy study."""

from datetime import datetime, timezone
import json

import httpx

from mailrecon.core.models import ProfilePivot
from mailrecon.core.platform_catalog import PLATFORM_BY_NAME
from mailrecon.services.profile_check_service import ProfileCheckService


def run_benchmark() -> dict:
    """Exercise the real classifier via in-memory HTTP; no socket/provider state."""
    records = []
    for platform in ('GitHub', 'GitLab'):
        spec = PLATFORM_BY_NAME[platform]
        field, url_field = ('login', 'html_url') if platform == 'GitHub' else ('username', 'web_url')
        valid = {'id': 42, field: 'DemoExample', url_field: spec.profile_url('DemoExample')}
        wrap = lambda value: value if platform == 'GitHub' else [value]
        cases = [
            ('positive', 200, wrap(valid), 'public_match_possible'),
            ('negative', 404 if platform == 'GitHub' else 200, {} if platform == 'GitHub' else [], 'not_found'),
            ('generic_200', 200, {'message': 'Welcome'}, 'ambiguous'),
            ('soft_404', 200, {'message': 'Not found'}, 'ambiguous'),
            ('login_page', 200, '<html>Sign in</html>', 'ambiguous'),
            ('different_handle', 200, wrap({**valid, field: 'SomeoneElse'}), 'ambiguous'),
            ('untrusted_url', 200, wrap({**valid, url_field: 'https://evil.example/DemoExample'}), 'ambiguous'),
            ('invalid_id', 200, wrap({**valid, 'id': True}), 'ambiguous'),
            ('blocked', 403, {}, 'blocked_by_platform'),
            ('rate_limit', 429, {}, 'rate_limited'),
        ]
        if platform == 'GitLab':
            cases.append(('multiple', 200, [valid, valid], 'ambiguous'))
        for name, code, body, expected in cases:
            encoded = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            def respond(request, status=code, data=encoded):
                return httpx.Response(status, headers={'content-type': 'application/json'}, stream=httpx.ByteStream(data))
            service = ProfileCheckService(transport=httpx.MockTransport(respond), cache_entries=0,
                                          utcnow=lambda: datetime(2026, 10, 7, tzinfo=timezone.utc))
            pivot = ProfilePivot(platform, 'demoexample', spec.profile_url('demoexample'), spec.search_url('demoexample'),
                                 'public_profile_pivot', 'low', 0, 'manual_review')
            result, evidence = service.check_public_profile(pivot)
            records.append({'source': platform, 'case': name, 'expected': expected,
                            'actual': result.resolution_status, 'confidence_scope': result.confidence_scope,
                            'priority': result.review_priority_score, 'consistent': evidence.confidence_scope == result.confidence_scope})
    positive = 'public_match_possible'
    tp = sum(row['expected'] == positive and row['actual'] == positive for row in records)
    fp = sum(row['expected'] != positive and row['actual'] == positive for row in records)
    fn = sum(row['expected'] == positive and row['actual'] != positive for row in records)
    return {'dataset': 'mailrecon-owned-synthetic-api-v1', 'synthetic_only': True,
            'warning': 'Fixture precision is not real-world accuracy or identity correlation.',
            'cases': len(records), 'true_positives': tp, 'false_positives': fp, 'false_negatives': fn,
            'precision': tp / (tp + fp) if tp + fp else None,
            'expectation_matches': sum(row['expected'] == row['actual'] for row in records), 'records': records}


if __name__ == '__main__':
    report = run_benchmark()
    print(json.dumps(report, indent=2))
    if report['expectation_matches'] != report['cases'] or report['false_positives']:
        raise SystemExit(1)
