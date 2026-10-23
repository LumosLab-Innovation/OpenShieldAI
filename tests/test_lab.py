import os
import unittest
import copy
import json

from lab.control import Lab, ROOT, initial_config, route


def record(name, report):
    destination = ROOT / 'artifacts' / 'lab-results'
    destination.mkdir(parents=True, exist_ok=True)
    (destination / (name + '.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')


class LabBoundaryTests(unittest.TestCase):
    def test_control_scope_and_private_admin(self):
        lab = Lab()
        self.assertEqual((lab.lab_id, lab.project_id, lab.asset_id), ('openshield-lab', 'lab', 'lab_web'))
        config = initial_config()
        self.assertEqual(config['admin']['listen'], 'unix//admin/caddy.sock')
        self.assertEqual(list(config['apps']['http']['servers']), ['shield'])
        self.assertIn('http.handlers.waf', config['logging']['logs']['default']['exclude'])

    def test_fixed_templates_reject_unknown_and_preserve_origin_guard(self):
        with self.assertRaises(ValueError):
            route('model-authored-shell-command')
        for mode in ('off', 'detection', 'on'):
            rules = route(mode)['handle'][0]['routes']
            self.assertEqual(rules[0]['match'], [{'path': ['/_lab*']}])
            self.assertEqual(rules[0]['handle'][0]['status_code'], 404)
            self.assertEqual(rules[1]['handle'][1]['upstreams'], [{'dial': 'app:8000'}])
        self.assertEqual(route('maintenance')['handle'][0]['status_code'], 503)

    def test_controller_never_follows_model_url_or_restore_path(self):
        lab = Lab()
        for path in ('https://example.com', '//example.com', '', 'x', '/' + 'a'*4096):
            with self.assertRaises(ValueError):
                lab.request(path)
        for snapshot, label in (('latest', 'clean'), ('a'*64, '../../outside')):
            with self.assertRaises(ValueError):
                lab.restore_check(snapshot, label)
        with self.assertRaises(ValueError):
            lab.observer('contaminate')

    def test_topology_drift_is_rejected_before_mutation(self):
        changed = copy.deepcopy(initial_config())
        changed['apps']['http']['servers']['shield']['listen'].append(':9000')
        with self.assertRaises(RuntimeError):
            Lab.validate_config(changed)
        changed = copy.deepcopy(initial_config())
        changed['apps']['http']['servers']['extra'] = {'listen': [':9001']}
        with self.assertRaises(RuntimeError):
            Lab.validate_config(changed)


@unittest.skipUnless(os.environ.get('SHIELD_RUN_LAB_TESTS') == '1', 'requires explicitly started isolated Docker lab')
class ActualLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = Lab()
        cls.lab.config()

    def test_1_actual_prevention_non_effect_and_negative_controls(self):
        report = self.lab.prevention_trial()
        for row in report['rows']:
            blocked = row['mode'] == 'on' and row['synthetic_harm']
            self.assertEqual(row['status'], 403 if blocked else 200, row)
            self.assertEqual(row['reached_delta'], 0 if blocked else 1, row)
            self.assertEqual(row['harm_delta'], int(row['synthetic_harm'] and not blocked), row)
        self.assertTrue(report['source_log_marker_absent'])
        self.assertTrue(report['origin_has_no_published_port'])
        self.assertEqual(report['observer_route_public_status'], 404)
        record('prevention', report)

    def test_2_actual_conditional_maintenance_and_remaining_work(self):
        report = self.lab.response_trial()
        self.assertEqual(report['applied']['status'], 200)
        self.assertEqual(report['pre_response_harm_delta'], 1)
        self.assertEqual(report['post_response_harm_delta'], 0)
        self.assertEqual(report['post_response_fixture_statuses'], [503, 503, 503])
        self.assertEqual(report['stale_update_status'], 412)
        self.assertFalse(report['during']['new_requests_reach_app'])
        self.assertTrue(report['during']['management_ok'])
        self.assertEqual(report['during']['legitimate_status'], 503)
        self.assertTrue(report['in_flight_finished'])
        self.assertTrue(report['background_continued'])
        self.assertFalse(report['retained_without_native_ttl']['new_requests_reach_app'])
        self.assertFalse(report['after_proxy_restart']['new_requests_reach_app'])
        self.assertTrue(report['after_proxy_restart']['management_ok'])
        self.assertTrue(report['reopened']['new_requests_reach_app'])
        record('response', report)

    def test_3_actual_pinned_restore_application_and_failure_cases(self):
        report = self.lab.recovery_trial()
        self.assertEqual(report['clean']['status'], 'verified', report)
        self.assertTrue(report['clean']['application_http_ok'])
        self.assertTrue(report['data_loss_independently_observed'])
        self.assertEqual(report['broken_app_transaction_status'], 409)
        for negative in ('missing_key', 'wrong_key', 'corrupt', 'contaminated', 'application_inconsistent'):
            self.assertEqual(report[negative]['status'], 'failed', report)
        record('recovery', report)


if __name__ == '__main__':
    unittest.main()
