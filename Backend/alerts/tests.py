"""
Tests for live_alerts view — covers every filter parameter:
  threat_level, protocol, sid, src_ip, dest_ip, date_from, date_to, search, limit
"""

from datetime import datetime, timezone as dt_timezone
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.models import User, Organization
from alerts.models import Alert


def make_alert(**kwargs):
    """Helper: create an Alert with sensible defaults, overridden by kwargs."""
    defaults = dict(
        timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=dt_timezone.utc),
        src_ip='10.0.0.1',
        src_port=1234,
        dest_ip='192.168.1.1',
        dest_port=80,
        protocol='TCP',
        sid='1000001',
        message='Test alert message',
        classification='Test classification',
        priority=3,
        threat_level=Alert.THREAT_SAFE,
        raw_line='raw',
        event_hash=None,  # set below
    )
    defaults.update(kwargs)
    # Auto-generate unique event_hash from key fields if not provided
    if defaults['event_hash'] is None:
        import hashlib, json
        key = json.dumps({k: str(v) for k, v in defaults.items()}, sort_keys=True)
        defaults['event_hash'] = hashlib.sha256(key.encode()).hexdigest()
    return Alert.objects.create(**defaults)


class LiveAlertsFilterTests(TestCase):
    """Test every filter parameter of GET /api/alerts/live/"""

    @classmethod
    def setUpTestData(cls):
        # Create a platform owner (no org required) for auth
        cls.user = User.objects.create_user(
            email='tester@threateye.io',
            password='testpass123',
            role=User.PLATFORM_OWNER,
            is_verified=True,
        )

        # --- Alert fixtures ---
        # A1: HIGH / TCP / SID 1000001 / src 10.0.0.1 / dest 192.168.1.1 / early date
        cls.a1 = make_alert(
            timestamp=datetime(2026, 4, 10, 8, 0, 0, tzinfo=dt_timezone.utc),
            src_ip='10.0.0.1', dest_ip='192.168.1.1',
            protocol='TCP', sid='1000001',
            message='SQL injection attempt detected',
            threat_level=Alert.THREAT_HIGH, priority=1,
            event_hash='hash_a1',
        )
        # A2: MEDIUM / UDP / SID 1000002 / src 10.0.0.2 / dest 192.168.1.2 / mid date
        cls.a2 = make_alert(
            timestamp=datetime(2026, 4, 15, 12, 0, 0, tzinfo=dt_timezone.utc),
            src_ip='10.0.0.2', dest_ip='192.168.1.2',
            protocol='UDP', sid='1000002',
            message='Port scan detected',
            threat_level=Alert.THREAT_MEDIUM, priority=2,
            event_hash='hash_a2',
        )
        # A3: SAFE / ICMP / SID 1000003 / src 10.0.0.3 / dest 192.168.1.3 / late date
        cls.a3 = make_alert(
            timestamp=datetime(2026, 4, 20, 18, 0, 0, tzinfo=dt_timezone.utc),
            src_ip='10.0.0.3', dest_ip='192.168.1.3',
            protocol='ICMP', sid='1000003',
            message='ICMP ping sweep',
            classification='network-scan',
            threat_level=Alert.THREAT_SAFE, priority=3,
            event_hash='hash_a3',
        )
        # A4: HIGH / TCP / SID 1000001 (same SID as A1) / different IPs
        cls.a4 = make_alert(
            timestamp=datetime(2026, 4, 18, 10, 0, 0, tzinfo=dt_timezone.utc),
            src_ip='172.16.0.1', dest_ip='10.10.10.10',
            protocol='TCP', sid='1000001',
            message='Malware C2 communication',
            threat_level=Alert.THREAT_HIGH, priority=1,
            event_hash='hash_a4',
        )

    def setUp(self):
        self.client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(refresh.access_token)}')
        self.url = reverse('live_alerts')

    # ------------------------------------------------------------------ #
    # Helper
    # ------------------------------------------------------------------ #
    def get(self, **params):
        return self.client.get(self.url, params)

    def ids(self, response):
        return {r['id'] for r in response.data['results']}

    # ------------------------------------------------------------------ #
    # Auth
    # ------------------------------------------------------------------ #
    def test_unauthenticated_returns_401(self):
        self.client.credentials()
        r = self.get()
        self.assertEqual(r.status_code, 401)

    # ------------------------------------------------------------------ #
    # No filters — returns all
    # ------------------------------------------------------------------ #
    def test_no_filters_returns_all_alerts(self):
        r = self.get()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 4)

    # ------------------------------------------------------------------ #
    # threat_level filter
    # ------------------------------------------------------------------ #
    def test_filter_single_threat_level_high(self):
        r = self.get(threat_level='high')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a4.id, result_ids)
        self.assertNotIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)

    def test_filter_single_threat_level_medium(self):
        r = self.get(threat_level='medium')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a2.id, result_ids)
        self.assertEqual(len(r.data['results']), 1)

    def test_filter_single_threat_level_safe(self):
        r = self.get(threat_level='safe')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a3.id, result_ids)
        self.assertEqual(len(r.data['results']), 1)

    def test_filter_multiple_threat_levels(self):
        r = self.get(threat_level='high,medium')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a2.id, result_ids)
        self.assertIn(self.a4.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)

    def test_filter_threat_level_case_insensitive(self):
        r = self.get(threat_level='HIGH')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 2)

    def test_filter_threat_level_no_match_returns_empty(self):
        # "critical" is not a valid level — should return 0 results
        r = self.get(threat_level='critical')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 0)

    # ------------------------------------------------------------------ #
    # protocol filter
    # ------------------------------------------------------------------ #
    def test_filter_single_protocol_tcp(self):
        r = self.get(protocol='TCP')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a4.id, result_ids)
        self.assertNotIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)

    def test_filter_single_protocol_udp(self):
        r = self.get(protocol='UDP')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a2.id, self.ids(r))

    def test_filter_single_protocol_icmp(self):
        r = self.get(protocol='ICMP')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a3.id, self.ids(r))

    def test_filter_multiple_protocols(self):
        r = self.get(protocol='TCP,UDP')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a2.id, result_ids)
        self.assertIn(self.a4.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)

    def test_filter_protocol_case_insensitive(self):
        r = self.get(protocol='tcp')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 2)

    # ------------------------------------------------------------------ #
    # sid filter
    # ------------------------------------------------------------------ #
    def test_filter_single_sid(self):
        r = self.get(sid='1000002')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a2.id, self.ids(r))

    def test_filter_multiple_sids(self):
        r = self.get(sid='1000001,1000003')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a3.id, result_ids)
        self.assertIn(self.a4.id, result_ids)  # a4 also has SID 1000001
        self.assertNotIn(self.a2.id, result_ids)

    def test_filter_sid_no_match(self):
        r = self.get(sid='9999999')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 0)

    # ------------------------------------------------------------------ #
    # src_ip filter
    # ------------------------------------------------------------------ #
    def test_filter_src_ip_exact_match(self):
        r = self.get(src_ip='10.0.0.1')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a1.id, self.ids(r))

    def test_filter_src_ip_no_match(self):
        r = self.get(src_ip='1.2.3.4')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 0)

    # ------------------------------------------------------------------ #
    # dest_ip filter
    # ------------------------------------------------------------------ #
    def test_filter_dest_ip_exact_match(self):
        r = self.get(dest_ip='192.168.1.2')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a2.id, self.ids(r))

    def test_filter_dest_ip_no_match(self):
        r = self.get(dest_ip='9.9.9.9')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 0)

    # ------------------------------------------------------------------ #
    # date_from / date_to filters
    # ------------------------------------------------------------------ #
    def test_filter_date_from_full_iso(self):
        # Only alerts on/after Apr 15 — a2, a3, a4
        r = self.get(date_from='2026-04-15T00:00:00')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertNotIn(self.a1.id, result_ids)   # Apr 10 — excluded
        self.assertIn(self.a2.id, result_ids)       # Apr 15
        self.assertIn(self.a3.id, result_ids)       # Apr 20
        self.assertIn(self.a4.id, result_ids)       # Apr 18

    def test_filter_date_to_full_iso(self):
        # Only alerts on/before Apr 15 — a1, a2
        r = self.get(date_to='2026-04-15T23:59:59')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)       # Apr 10
        self.assertIn(self.a2.id, result_ids)       # Apr 15
        self.assertNotIn(self.a3.id, result_ids)    # Apr 20 — excluded
        self.assertNotIn(self.a4.id, result_ids)    # Apr 18 — excluded

    def test_filter_date_range(self):
        # Apr 14 → Apr 19: only a2 (Apr 15) and a4 (Apr 18)
        r = self.get(date_from='2026-04-14T00:00:00', date_to='2026-04-19T23:59:59')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertNotIn(self.a1.id, result_ids)
        self.assertIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)
        self.assertIn(self.a4.id, result_ids)

    def test_filter_date_from_datetime_local_format(self):
        """datetime-local sends YYYY-MM-DDTHH:MM (no seconds) — must not crash."""
        r = self.get(date_from='2026-04-15T00:00')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertNotIn(self.a1.id, result_ids)
        self.assertIn(self.a2.id, result_ids)
        self.assertIn(self.a3.id, result_ids)
        self.assertIn(self.a4.id, result_ids)

    def test_filter_date_to_datetime_local_format(self):
        """datetime-local sends YYYY-MM-DDTHH:MM (no seconds) — must not crash."""
        r = self.get(date_to='2026-04-15T23:59')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)
        self.assertNotIn(self.a4.id, result_ids)

    def test_filter_date_only_format(self):
        """YYYY-MM-DD date_to should include the entire day."""
        r = self.get(date_to='2026-04-15')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)
        self.assertNotIn(self.a4.id, result_ids)

    def test_filter_invalid_date_is_ignored(self):
        """Garbage date values should be silently ignored, not crash."""
        r = self.get(date_from='not-a-date', date_to='also-bad')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 4)

    # ------------------------------------------------------------------ #
    # search filter
    # ------------------------------------------------------------------ #
    def test_filter_search_by_message(self):
        r = self.get(search='SQL injection')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a1.id, self.ids(r))

    def test_filter_search_by_sid(self):
        r = self.get(search='1000003')
        self.assertEqual(r.status_code, 200)
        self.assertIn(self.a3.id, self.ids(r))

    def test_filter_search_by_src_ip(self):
        r = self.get(search='172.16.0.1')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a4.id, self.ids(r))

    def test_filter_search_by_dest_ip(self):
        r = self.get(search='10.10.10.10')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a4.id, self.ids(r))

    def test_filter_search_by_classification(self):
        r = self.get(search='network-scan')
        self.assertEqual(r.status_code, 200)
        self.assertIn(self.a3.id, self.ids(r))

    def test_filter_search_case_insensitive(self):
        r = self.get(search='MALWARE')
        self.assertEqual(r.status_code, 200)
        self.assertIn(self.a4.id, self.ids(r))

    def test_filter_search_no_match(self):
        r = self.get(search='xyzzy_no_match')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 0)

    # ------------------------------------------------------------------ #
    # limit parameter
    # ------------------------------------------------------------------ #
    def test_limit_parameter(self):
        r = self.get(limit=2)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 2)

    def test_limit_clamped_to_minimum_1(self):
        r = self.get(limit=0)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)

    def test_limit_invalid_value_defaults_to_100(self):
        r = self.get(limit='abc')
        self.assertEqual(r.status_code, 200)
        # 4 alerts total, all returned since 4 < 100
        self.assertEqual(len(r.data['results']), 4)

    # ------------------------------------------------------------------ #
    # Combined filters
    # ------------------------------------------------------------------ #
    def test_combined_threat_level_and_protocol(self):
        r = self.get(threat_level='high', protocol='TCP')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a4.id, result_ids)
        self.assertNotIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)

    def test_combined_sid_and_threat_level(self):
        # SID 1000001 has both a1 (HIGH) and a4 (HIGH) — filter to HIGH only
        r = self.get(sid='1000001', threat_level='high')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a1.id, result_ids)
        self.assertIn(self.a4.id, result_ids)
        self.assertEqual(len(r.data['results']), 2)

    def test_combined_src_ip_and_protocol(self):
        r = self.get(src_ip='10.0.0.2', protocol='UDP')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a2.id, self.ids(r))

    def test_combined_date_range_and_threat_level(self):
        # Apr 14–19, HIGH only → a4 (Apr 18, HIGH)
        r = self.get(date_from='2026-04-14T00:00:00', date_to='2026-04-19T23:59:59', threat_level='high')
        self.assertEqual(r.status_code, 200)
        result_ids = self.ids(r)
        self.assertIn(self.a4.id, result_ids)
        self.assertNotIn(self.a1.id, result_ids)
        self.assertNotIn(self.a2.id, result_ids)
        self.assertNotIn(self.a3.id, result_ids)

    def test_combined_search_and_protocol(self):
        r = self.get(search='scan', protocol='UDP')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.data['results']), 1)
        self.assertIn(self.a2.id, self.ids(r))

    # ------------------------------------------------------------------ #
    # Response structure
    # ------------------------------------------------------------------ #
    def test_response_contains_expected_fields(self):
        r = self.get(limit=1)
        self.assertEqual(r.status_code, 200)
        self.assertIn('results', r.data)
        self.assertIn('count', r.data)
        self.assertIn('total_available', r.data)
        alert = r.data['results'][0]
        for field in ['id', 'timestamp', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
                      'protocol', 'sid', 'message', 'threat_level']:
            self.assertIn(field, alert, f"Missing field: {field}")

    def test_results_ordered_newest_first(self):
        r = self.get()
        self.assertEqual(r.status_code, 200)
        timestamps = [r['timestamp'] for r in r.data['results']]
        self.assertEqual(timestamps, sorted(timestamps, reverse=True))
