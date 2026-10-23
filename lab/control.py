"""Operator-owned isolated lab controller, not a production response adapter.

Every subprocess uses fixed argv and a deadline. Only this named project's
containers and artifacts/lab-state paths are touched. No daemon socket is mounted.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / 'lab'
STATE = ROOT / 'artifacts' / 'lab-state'
BUILD = ROOT / 'artifacts' / 'lab-build'
BASE = 'http://127.0.0.1:18780'
CONNECTOR = 'e268cf0f44e95d64da81c641aabebd21364be6f1'
RESTIC_TAG = 'restic/restic@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510'
MODES = {'off': 'Off', 'detection': 'DetectionOnly', 'on': 'On'}


def run(argv, *, data=None, timeout=60, check=True, env=None, cwd=ROOT):
    completed = subprocess.run(argv, input=data, text=True, encoding='utf-8', errors='replace',
                               capture_output=True, timeout=timeout, cwd=cwd, env=env)
    if check and completed.returncode:
        # Do not echo potentially sensitive tool stdout/stderr into normal reports.
        raise RuntimeError(f'{argv[0]} failed with exit {completed.returncode}')
    return completed


def route(mode):
    if mode == 'maintenance':
        return {'handle': [{'handler': 'static_response', 'status_code': 503,
                            'body': 'OpenShieldAI isolated lab maintenance\n'}], 'terminal': True}
    if mode not in MODES:
        raise ValueError('unknown fixed lab mode')
    directives = '\n'.join([
        'Include @coraza.conf-recommended', 'Include @crs-setup.conf.example',
        # Request-phase scope; the pinned full response bundle has a missing data file.
        'Include @owasp_crs/REQUEST-*.conf', f'SecRuleEngine {MODES[mode]}',
        'SecAuditEngine Off', 'SecDebugLogLevel 0', 'SecResponseBodyAccess Off',
        'SecRequestBodyLimit 65536', 'SecRequestBodyInMemoryLimit 65536', 'SecRequestBodyLimitAction Reject',
    ])
    return {'handle': [{'handler': 'subroute', 'routes': [
        {'match': [{'path': ['/_lab*']}], 'handle': [{'handler': 'static_response', 'status_code': 404}], 'terminal': True},
        {'handle': [{'handler': 'waf', 'load_owasp_crs': True, 'directives': directives},
                    {'handler': 'reverse_proxy', 'upstreams': [{'dial': 'app:8000'}]}]},
    ]}], 'terminal': True}


def initial_config():
    return {'admin': {'listen': 'unix//admin/caddy.sock'},
            'logging': {'logs': {'default': {'level': 'ERROR',
                'exclude': ['http.handlers.waf', 'http.log.error', 'admin.api']}}},
            'apps': {'http': {'servers': {'shield': {'listen': [':8080'],
                'automatic_https': {'disable': True}, 'routes': [route('on')]}}}}}


class Lab:
    def __init__(self):
        self.lab_id = 'openshield-lab'
        self.project_id = 'lab'
        self.asset_id = 'lab_web'
        self.env = os.environ.copy()
        self.env['SHIELD_LAB_STATE'] = str(STATE)
        self.env['SHIELD_LAB_APP_REV'] = hashlib.sha256((HERE / 'app.py').read_bytes()).hexdigest()

    def compose(self, *args, data=None, timeout=60, check=True):
        return run(['docker', 'compose', '-p', 'openshield-lab', '-f', str(HERE / 'compose.yml'), *args],
                   data=data, timeout=timeout, check=check, env=self.env)

    def build(self):
        BUILD.mkdir(parents=True, exist_ok=True)
        environment = self.env.copy()
        environment.update({'GOOS': 'linux', 'GOARCH': 'amd64', 'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'local', 'GOMAXPROCS': '4'})
        run(['go', 'build', '-p=4', '-mod=readonly', '-trimpath', '-o', str(BUILD / 'caddy'), '.'],
            cwd=HERE, env=environment, timeout=600)
        shutil.copyfile(HERE / 'Dockerfile', BUILD / 'Dockerfile')
        run(['docker', 'build', '-t', 'openshield-lab-caddy:pinned', str(BUILD)], timeout=180)
        run(['docker', 'pull', RESTIC_TAG], timeout=180)
        digest = json.loads(run(['docker', 'image', 'inspect', RESTIC_TAG, '--format', '{{json .RepoDigests}}']).stdout)[0]
        metadata = {
            'schema': 'isolated_lab_build_v1', 'connector_commit': CONNECTOR,
            'go_modules': run(['go', 'list', '-m', '-json', 'all'], cwd=HERE, timeout=60).stdout,
            'caddy_image_id': run(['docker', 'image', 'inspect', 'openshield-lab-caddy:pinned', '--format', '{{.Id}}']).stdout.strip(),
            'binary_sha256': hashlib.sha256((BUILD / 'caddy').read_bytes()).hexdigest(),
            'caddy_version': run(['docker', 'run', '--rm', '--network', 'none', 'openshield-lab-caddy:pinned', 'version']).stdout.strip(),
            'restic_image': digest,
            'restic_version': run(['docker', 'run', '--rm', '--network', 'none', digest, 'version']).stdout.strip(),
            'source_logging_patch': None,
            'logging_policy': 'waf/http.error/admin.api excluded; access/audit/debug disabled; seeded marker check required separately',
        }
        (BUILD / 'provenance.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
        return {key: value for key, value in metadata.items() if key != 'go_modules'}

    def start(self):
        for name in ('app', 'config', 'admin', 'persist', 'backup', 'restore'):
            (STATE / name).mkdir(parents=True, exist_ok=True)
        config = STATE / 'config' / 'caddy.json'
        config.write_text(json.dumps(initial_config()), encoding='utf-8')
        self.compose('up', '-d', timeout=90)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if self.request('/').get('status') in {200, 503}:
                    return self.probe()
            except (OSError, RuntimeError, ValueError):
                pass
            time.sleep(.25)
        raise RuntimeError('isolated lab failed readiness')

    def stop(self):
        self.compose('down', '--timeout', '5', timeout=40)

    def state(self):
        return self.observer('state')

    def observer(self, operation):
        if operation != 'state':
            raise ValueError('unknown observation operation')
        return json.loads(self.compose('exec', '-T', 'observer', 'python', '/lab/observer.py', operation).stdout)

    def stimulus(self, operation):
        if operation not in {'checkpoint', 'contaminate', 'clean-fixture', 'data-loss', 'reset-data', 'inconsistent'}:
            raise ValueError('unknown experiment stimulus')
        return json.loads(self.compose('exec', '-T', 'observer', 'python', '/lab/stimulus.py', operation).stdout)

    def request(self, path):
        if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or len(path) > 4096:
            raise ValueError('only bounded relative lab paths permitted')
        started = time.perf_counter()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(BASE + path, timeout=8) as response:
                status, body = response.status, response.read(65536).decode('utf-8', 'replace')
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read(65536).decode('utf-8', 'replace')
        return {'status': status, 'body': body, 'elapsed_ms': round((time.perf_counter()-started)*1000, 3)}

    def admin(self, payload):
        return json.loads(self.compose('exec', '-T', 'broker', 'python', '/lab/admin.py',
                                      data=json.dumps(payload), timeout=15).stdout)

    def config(self):
        result = self.admin({'operation': 'read'})
        if result['status'] != 200 or not result['etag']:
            raise RuntimeError('management config unavailable')
        self.validate_config(result['config'])
        return {'etag': result['etag'], 'release': hashlib.sha256(
            json.dumps(result['config'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()}

    @staticmethod
    def validate_config(config):
        expected = initial_config()
        try:
            current = config['apps']['http']['servers']['shield']['routes'][0]
            if current not in [route(mode) for mode in (*MODES, 'maintenance')]:
                raise ValueError('unknown route')
            expected['apps']['http']['servers']['shield']['routes'][0] = current
            if config != expected:
                raise ValueError('dedicated topology changed')
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise RuntimeError('lab target outside accepted fixed topology') from exc

    def set_mode(self, mode, expected_etag=None):
        selected = route(mode)
        observed = self.config()
        if expected_etag is None:
            expected_etag = observed['etag']
        result = self.admin({'operation': 'replace_route', 'route': selected, 'etag': expected_etag})
        current = self.config()
        return {'status': result['status'], **current, 'mode_requested': mode}

    def probe(self):
        before = self.state()['counts']
        response = self.request('/')
        after = self.state()['counts']
        return {'new_requests_reach_app': after['reached'] > before['reached'],
                'management_ok': bool(self.config()['etag']), 'legitimate_status': response['status'],
                'harm_count': after['harm'], 'request_count': after['reached']}

    def prevention_trial(self):
        attacks = ['1%20OR%201%3D1--', '%3Cscript%3Ealert(1)%3C/script%3E', '..%2F..%2Fetc%2Fpasswd']
        benign = ['hello', 'product-100', 'quarterly-report']
        rows = []
        for mode in ('off', 'detection', 'on'):
            self.set_mode(mode)
            for harmful, corpus in ((True, attacks), (False, benign)):
                for index, query in enumerate(corpus):
                    before = self.state()['counts']
                    endpoint = '/fixture-operation' if harmful else '/transaction'
                    observed = self.request(endpoint + '?input=' + query)
                    after = self.state()['counts']
                    rows.append({'mode': mode, 'fixture_id': ('pattern-' if harmful else 'benign-') + str(index),
                                 'synthetic_harm': harmful, 'status': observed['status'],
                                 'reached_delta': after['reached'] - before['reached'],
                                 'harm_delta': after['harm'] - before['harm'], 'elapsed_ms': observed['elapsed_ms']})
        marker = 'LAB_QUERY_SENTINEL_7e20d309'
        self.request('/fixture-operation?input=%3Cscript%3E' + marker + '%3C/script%3E')
        logs = self.compose('logs', '--no-color', 'proxy', 'app').stdout
        ports = self.compose('port', 'app', '8000', check=False)
        inspect = json.loads(self.compose('ps', '-q', 'app').stdout and run(
            ['docker', 'inspect', self.compose('ps', '-q', 'app').stdout.strip()]).stdout)[0]
        return {'rows': rows, 'source_log_marker_absent': marker not in logs,
                'origin_has_no_published_port': ports.returncode != 0 and not inspect['NetworkSettings']['Ports'].get('8000/tcp'),
                'observer_route_public_status': self.request('/_lab/state')['status'],
                'limitations': ['Synthetic planted operation, not demonstrated SQLi/XSS/RCE exploitation.',
                                'Tiny corpus; no general WAF efficacy or false-positive rate claim.',
                                'No IPv6/external-host origin reachability or volumetric DDoS test.']}

    def response_trial(self):
        self.set_mode('on')
        before = self.state()['counts']
        pre_response = self.request('/fixture-operation?input=business-abuse-fixture')
        before_apply = self.state()['counts']
        self.request('/start-background')
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            ongoing = pool.submit(self.request, '/long?seconds=3')
            deadline = time.monotonic() + 4
            while self.state()['counts']['long_started'] == before['long_started'] and time.monotonic() < deadline:
                time.sleep(.05)
            expected = self.config()['etag']
            dispatch_started = time.perf_counter()
            applied = self.set_mode('maintenance', expected)
            dispatch_elapsed = (time.perf_counter() - dispatch_started) * 1000
            conflict = self.set_mode('on', expected)
            stopped = self.probe()
            post_response = [self.request('/fixture-operation?input=business-abuse-fixture')['status'] for _ in range(3)]
            in_flight = ongoing.result(timeout=6)
        time.sleep(.2)
        after = self.state()['counts']
        control_retained = self.probe()
        self.compose('restart', '--timeout', '3', 'proxy', timeout=20)
        deadline = time.monotonic() + 15
        while True:
            try:
                after_restart = self.probe()
                break
            except (RuntimeError, OSError, ValueError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('proxy restart failed readiness')
                time.sleep(.25)
        self.set_mode('on', self.config()['etag'])
        reopened = self.probe()
        return {'applied': applied, 'stale_update_status': conflict['status'], 'during': stopped,
                'pre_response_fixture_status': pre_response['status'],
                'pre_response_harm_delta': before_apply['harm'] - before['harm'],
                'post_response_fixture_statuses': post_response,
                'post_response_harm_delta': after['harm'] - before_apply['harm'],
                'dispatch_with_readback_ms': round(dispatch_elapsed, 3),
                'in_flight_status': in_flight['status'], 'in_flight_finished': after['long_finished'] > before['long_finished'],
                'background_continued': after['background'] > before['background'],
                'retained_without_native_ttl': control_retained, 'after_proxy_restart': after_restart, 'reopened': reopened,
                'approval_mode': 'controller fixture; no human approval latency measured',
                'limitations': ['Ingress maintenance is not host/session/egress containment.', 'WebSockets not implemented in this fixture.']}

    def restic(self, *args, destination=None, password=None, repository=None, check=True):
        metadata = json.loads((BUILD / 'provenance.json').read_text(encoding='utf-8'))
        image = metadata['restic_image']
        if not re.fullmatch(r'restic/restic@sha256:[a-f0-9]{64}', image):
            raise ValueError('unpinned restic image')
        argv = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp',
                '-v', str(repository or STATE / 'backup') + (':/repo:ro' if args[0] in {'restore', 'check'} else ':/repo'),
                '-v', str(password or STATE / 'restic-password') + ':/run/password:ro',
                '-v', str(STATE / 'app') + ':/source:ro']
        if destination:
            destination = Path(destination).resolve()
            if destination.parent != (STATE / 'restore').resolve():
                raise ValueError('restore destination outside isolated root')
            argv += ['-v', str(destination) + ':/restore']
        if args[0] == 'restore':
            argv += ['--cap-add', 'CHOWN', '--cap-add', 'FOWNER']
        argv += [image, '--repo', '/repo', '--password-file', '/run/password', '--cache-dir', '/tmp/cache', *args]
        if args[0] in {'restore', 'check'}:
            argv.append('--no-lock')
        return run(argv, timeout=90, check=check)

    def restore_check(self, snapshot, label, *, password=None, repository=None):
        if not re.fullmatch('[a-f0-9]{64}', snapshot) or not re.fullmatch('[a-z0-9-]{1,40}', label):
            raise ValueError('full immutable snapshot and safe target label required')
        if not Path(password or STATE / 'restic-password').is_file():
            return {'status': 'failed', 'error': 'MISSING_KEY', 'elapsed_ms': 0}
        target = STATE / 'restore' / (label + '-' + secrets.token_hex(4))
        target.mkdir()
        started = time.perf_counter()
        restored = self.restic('restore', snapshot, '--target', '/restore', destination=target,
                               password=password, repository=repository, check=False)
        if restored.returncode:
            return {'status': 'failed', 'error': 'RESTORE_TOOL_FAILED', 'elapsed_ms': round((time.perf_counter()-started)*1000, 3)}
        # Execute the actual restored DB's integrity/business checks in a separate container.
        checked = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--tmpfs', '/tmp',
                       '-v', str(target) + ':/restore:ro', '-v', str(HERE) + ':/lab:ro',
                       'python:3.12-slim@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17',
                       'python', '/lab/verify_restore.py'], check=False)
        result = json.loads(checked.stdout) if checked.stdout else {'status': 'failed', 'error': 'APP_CHECK_FAILED'}
        result['elapsed_ms'] = round((time.perf_counter()-started)*1000, 3)
        return result

    def recovery_trial(self):
        if not (STATE / 'restic-password').exists():
            (STATE / 'restic-password').write_text(secrets.token_urlsafe(48), encoding='utf-8')
        if not (STATE / 'backup' / 'config').exists():
            self.restic('init')
        self.stimulus('clean-fixture')
        self.stimulus('reset-data')
        self.stimulus('checkpoint')
        captured = time.time()
        backup = self.restic('backup', '/source/checkpoint.db', '--json')
        summary = [json.loads(line) for line in backup.stdout.splitlines() if line.strip()][-1]
        snapshot = summary['snapshot_id']
        self.restic('check', '--read-data')
        self.set_mode('on')
        self.request('/transaction')
        incident_time = time.time()
        self.stimulus('data-loss')
        broken = self.state()
        broken_app_status = self.request('/transaction')['status']
        clean = self.restore_check(snapshot, 'clean')
        wrong = STATE / 'wrong-password'
        wrong.write_text(secrets.token_urlsafe(48), encoding='utf-8')
        wrong_key = self.restore_check(snapshot, 'wrong-key', password=wrong)
        missing_key = self.restore_check(snapshot, 'missing-key', password=STATE / 'not-present-key')
        corrupt_repo = STATE / ('corrupt-repo-' + secrets.token_hex(4))
        shutil.copytree(STATE / 'backup', corrupt_repo)
        packs = sorted((corrupt_repo / 'data').rglob('*'))
        for pack in packs:
            if pack.is_file():
                pack.chmod(0o600)
                pack.write_bytes(b'planted-corrupt-pack')
        corrupt = self.restore_check(snapshot, 'corrupt', repository=corrupt_repo)
        self.stimulus('reset-data')
        self.stimulus('contaminate')
        self.stimulus('checkpoint')
        contaminated_backup = self.restic('backup', '/source/checkpoint.db', '--json')
        contaminated_id = [json.loads(line) for line in contaminated_backup.stdout.splitlines() if line.strip()][-1]['snapshot_id']
        contaminated = self.restore_check(contaminated_id, 'contaminated')
        self.stimulus('clean-fixture')
        self.stimulus('inconsistent')
        self.stimulus('checkpoint')
        inconsistent_backup = self.restic('backup', '/source/checkpoint.db', '--json')
        inconsistent_id = [json.loads(line) for line in inconsistent_backup.stdout.splitlines() if line.strip()][-1]['snapshot_id']
        inconsistent = self.restore_check(inconsistent_id, 'inconsistent')
        self.stimulus('reset-data')
        return {'snapshot_id': snapshot, 'clean': clean, 'missing_key': missing_key, 'wrong_key': wrong_key, 'corrupt': corrupt,
                'contaminated': contaminated, 'application_inconsistent': inconsistent,
                'data_loss_independently_observed': broken['accounts'] == [], 'broken_app_transaction_status': broken_app_status,
                'restore_uses_empty_isolated_target': True,
                'synthetic_rpo_seconds': round(incident_time - captured, 3),
                'rpo_definition': 'Last application-consistent checkpoint to declared synthetic incident after one further committed transaction.',
                'committed_transactions_after_checkpoint': 1,
                'verified_restore_rto_ms': clean['elapsed_ms'],
                'limitations': ['No production overwrite/reconnection.', 'Known planted trust marker is not a malware scanner.',
                                'Recovery does not reverse disclosure.', 'No production backup identity/key-management guarantee.']}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise ValueError('lab redirects forbidden')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['build', 'start', 'stop', 'probe', 'prevention', 'response', 'recovery'])
    args = parser.parse_args()
    lab = Lab()
    method = {'prevention': lab.prevention_trial, 'response': lab.response_trial, 'recovery': lab.recovery_trial}.get(args.operation)
    result = method() if method else getattr(lab, args.operation)()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
