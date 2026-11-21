"""HELD source-only trusted owner for ONE Docker role container. Nothing here runs on import; APPROVED_FOR_EXECUTION=False.

The owner is the only holder of the docker CLI. It sequences: durable intent -> image record -> create (ID bound from stdout) ->
inspect vs exact spec -> attached gated start -> inspect started -> acquire pidfd / namespace fds / cgroup fd with starttime before and
after -> bind_started -> durable launch record -> release byte. Exit evidence is captured BEFORE removal; handles are closed before the
namespace-membership scan; removal and kill use the bound container ID only, never a name. Backends (`docker`, `/proc`) are injected
so tests drive the call path with fakes. A fake-backend test proves ORDER and fail-closed branches, not daemon or kernel behavior.
After owner death nothing here can act: independent recovery stays UNVERIFIED by design.
"""
import json
import os
import select
import subprocess
import time
from pathlib import Path

import docker_lifecycle as dl

APPROVED_FOR_EXECUTION = False


class OwnerError(RuntimeError):
    pass


def _jw(path, obj):
    from handoff_io import json_write
    json_write(path, obj)


# ---- real backends (unexercised in tests; shapes only) ----
class DockerCli:
    def __init__(self, docker='/usr/bin/docker'): self.docker = docker

    def run(self, args, timeout=30):
        r = subprocess.run([self.docker] + list(args), capture_output=True, timeout=timeout, env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr

    def attach(self, args):
        return _Attach(subprocess.Popen([self.docker] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        env={'PATH': '/usr/bin:/bin'}, close_fds=True))


class _Attach:
    def __init__(self, p):
        self.p = p; os.set_blocking(p.stdout.fileno(), False); self.bytes = 0
    def write(self, b): self.p.stdin.write(b); self.p.stdin.flush()
    def poll(self): return self.p.poll()
    def pump(self, sink, ceiling=65536):
        while True:
            try: d = os.read(self.p.stdout.fileno(), 4096)
            except BlockingIOError: return
            if not d: return
            left = ceiling - self.bytes; sink.write(d[:left]); self.bytes += min(left, len(d))
            if len(d) > left: raise OwnerError('attach log ceiling')
    def close(self):
        for f in (self.p.stdin, self.p.stdout):
            try: f.close()
            except OSError: pass


class Handles:
    def __init__(self, pid, pidfd, ns_fds, cgroup_fd, cgroup_path, t0, t1):
        self.pid, self.pidfd, self.ns_fds, self.cgroup_fd = pid, pidfd, ns_fds, cgroup_fd
        self.cgroup_path, self.t0, self.t1, self.closed = cgroup_path, t0, t1, False
    def ns_inodes(self): return {k + '_ns_inode': os.fstat(fd).st_ino for k, fd in self.ns_fds.items()}
    def exited(self): return bool(select.select([self.pidfd], [], [], 0)[0])
    def close(self):
        for fd in [self.pidfd, self.cgroup_fd, *self.ns_fds.values()]:
            try: os.close(fd)
            except OSError: pass
        self.closed = True


class HostProc:
    def starttime(self, pid):
        t = Path('/proc/%d/stat' % pid).read_text()
        return int(t[t.rindex(')') + 2:].split()[19])
    def host_ns(self):
        return {k + '_ns_inode': os.stat('/proc/self/ns/' + k).st_ino for k in ('pid', 'mnt', 'net')}
    def acquire(self, pid):
        t0 = self.starttime(pid); fds = []
        try:
            pidfd = os.pidfd_open(pid); fds.append(pidfd)
            ns = {}
            for k in ('pid', 'mnt', 'net'):
                ns[k] = os.open('/proc/%d/ns/%s' % (pid, k), os.O_RDONLY | os.O_CLOEXEC); fds.append(ns[k])
            cg = [l.split(':', 2)[2].strip() for l in Path('/proc/%d/cgroup' % pid).read_text().splitlines() if l.startswith('0::')][0]
            cfd = os.open('/sys/fs/cgroup' + cg, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC); fds.append(cfd)
            return Handles(pid, pidfd, ns, cfd, cg, t0, self.starttime(pid))
        except BaseException:
            for fd in fds:
                try: os.close(fd)
                except OSError: pass
            raise
    def identity_gone(self, pid, start):
        try: return self.starttime(pid) != start
        except (FileNotFoundError, ProcessLookupError): return True
    def cgroup_unpopulated_or_gone(self, cg):
        try: return 'populated 0' in Path('/sys/fs/cgroup' + cg + '/cgroup.events').read_text()
        except FileNotFoundError: return True
    def ns_members(self, expected):
        found = []
        for pr in Path('/proc').glob('[0-9]*'):
            for k in ('net', 'mnt', 'pid'):
                try:
                    if os.readlink(pr / 'ns' / k) in expected: found.append(str(pr / 'ns' / k))
                except FileNotFoundError: pass
            try:
                for d in (pr / 'fd').iterdir():
                    try:
                        if os.readlink(d) in expected: found.append(str(d))
                    except FileNotFoundError: pass
            except FileNotFoundError: pass
        return found


class RoleHandle:
    """Child-like handle (poll/wait/returncode) so the relay's call sites stay the same shape."""
    def __init__(self, owner): self.o = owner; self.returncode = None; self.pid = owner.bound['pid']
    def poll(self):
        if self.returncode is None and (self.o.handles.exited() or self.o.attach.poll() is not None): self.o.finalize_exit(self)
        return self.returncode
    def wait(self, timeout=None):
        end = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if end is not None and time.monotonic() > end: raise subprocess.TimeoutExpired('docker-role', timeout)
            self.o.sleep(.05)
        return self.returncode
    def pump(self): self.o.attach.pump(self.o.log)


class RoleOwner:
    def __init__(self, root, role, run_id, image, params, backend, proc, host_ns=None, sibling_ns=None, sleep=time.sleep, chown=os.chown):
        self.root, self.role, self.run_id, self.image, self.params = Path(root), role, run_id, image, params
        self.docker, self.proc, self.sleep, self.sibling_ns = backend, proc, sleep, sibling_ns
        self.host_ns = host_ns if host_ns is not None else proc.host_ns()
        self.rec = None; self.bound = None; self.handles = None; self.attach = None; self.log = None; self.exit_obs = None
        self.base = self.root / role; self.chown = chown

    def _inspect(self, target, timeout=30):
        rc, out, err = self.docker.run(['inspect', '--type', 'container', target], timeout)
        if rc != 0: return None, rc, err
        try:
            v = json.loads(out); assert isinstance(v, list) and len(v) == 1
            return v[0], rc, err
        except (ValueError, AssertionError): raise OwnerError('inspect output malformed')

    def launch(self):
        if self.rec is not None: raise OwnerError('single launch per owner')
        intent = dl.launch_intent(self.role, self.run_id)
        _jw(self.root / (self.role + '-launch-intent.json'), {**intent, 'backend': 'docker', 'exact_output': str(self.base), 'root_owned': True})
        # Bind sources: same dirs namespace_supervisor made (work 0700 owned by 65534:primary gid; inbox is relay-created, must pre-exist).
        gid = self.params.get('kvm_gid') if self.role == 'runtime' else 65534
        self.base.mkdir(mode=0o700, exist_ok=True)
        work = self.base / 'work'; work.mkdir(mode=0o700, exist_ok=False); self.chown(work, 65534, gid)
        if not (self.root / (self.role + '-in')).is_dir(): raise OwnerError('inbox must pre-exist')
        rc, out, _ = self.docker.run(['image', 'inspect', self.image])
        try:
            if rc != 0: raise dl.SpecError('image inspect failed')
            imgs = json.loads(out)
            if not isinstance(imgs, list) or len(imgs) != 1: raise dl.SpecError('image record count')
            image_id = dl.validate_image_record(imgs[0], self.image)
        except (ValueError, dl.SpecError) as e:
            raise OwnerError('image not bound: %s' % type(e).__name__)
        argv = dl.create_argv(self.role, self.run_id, self.image, docker=self.docker.docker, **self.params)
        rc, out, _ = self.docker.run(argv[1:])
        self.rec = dl.after_create(intent, out if rc == 0 else b'')
        _jw(self.root / (self.role + '-container-record.json'), self.rec)
        if self.rec['stage'] != 'created':
            raise OwnerError('create output ambiguous: container UNVERIFIED, never removed by name')
        cid = self.rec['container_id']
        try:
            rec, _, _ = self._inspect(cid)
            if rec is None: raise dl.SpecError('created container not inspectable')
            dl.validate_inspect(rec, self.role, self.run_id, self.image, image_id, **{k: v for k, v in self.params.items()})
        except (dl.SpecError, OwnerError) as e:
            self._remove_by_id()   # ID is bound and was created by this attempt
            raise OwnerError('inspect differs from spec: %s' % e)
        self.log = (self.root / (self.role + '.docker.log')).open('xb')
        self.attach = self.docker.attach(['start', '--attach', '--interactive', cid])
        try:
            started, _, _ = self._inspect(cid)
            for _ in range(100):
                if started and (started.get('State') or {}).get('Running') is True and type((started['State']).get('Pid')) is int and started['State']['Pid'] >= 2: break
                self.sleep(.05); started, _, _ = self._inspect(cid)
            pid = ((started or {}).get('State') or {}).get('Pid')
            if type(pid) is not int or pid < 2: raise dl.SpecError('started pid not observed')
            self.handles = self.proc.acquire(pid)
            h = self.handles
            observed = {'pid': pid, 'cgroup_path': h.cgroup_path, 'start_ticks_before': h.t0, 'start_ticks_after': h.t1,
                        'pidfd_held': not h.closed and h.pidfd is not None, 'ns_fds_held': not h.closed and len(h.ns_fds) == 3,
                        'cgroup_fd_held': not h.closed and h.cgroup_fd is not None, **h.ns_inodes()}
            self.bound = dl.bind_started(self.rec, started, observed, self.host_ns, self.sibling_ns)
            _jw(self.base / 'namespace-setup.json', dl.namespace_setup_record(self.bound))
            _jw(self.root / (self.role + '-launch.json'), {'role': self.role, 'backend': 'docker', 'container_id': cid,
                'identity': {'pid': pid, 'start_ticks': h.t0, 'backend': 'docker', 'container_id': cid}, 'started_monotonic': time.monotonic(),
                'root_owned_lifecycle': True})
            self.attach.write(b'\x01')       # release only after identity is durable
            self.bound['gate_released'] = True
        except BaseException as e:
            self._abort(); raise OwnerError('start/bind failed closed: %s' % type(e).__name__)
        return RoleHandle(self)

    # ---- exit, kill, removal, absence ----
    def finalize_exit(self, handle):
        if self.exit_obs is not None: return
        rec, _, _ = self._inspect(self.rec['container_id'])
        obs = dl.leader_exit_observed(rec or {}, self.bound, self.handles.exited(), self.proc.identity_gone(self.bound['pid'], self.bound['start_ticks']))
        self.exit_obs = obs
        _jw(self.base / 'namespace-driver-result.json', dl.driver_result_record(obs))   # before any removal
        handle.returncode = obs['exit_code'] if obs['leader_exit_observed'] else 255

    def kill_bound(self):
        """Live-owner kill, bound container ID only, only while the held identity still matches. Never a group kill or a name."""
        if self.handles is None or self.rec is None or self.handles.exited(): return False
        pid, start = (self.bound['pid'], self.bound['start_ticks']) if self.bound else (self.handles.pid, self.handles.t0)   # also covers a bind that failed after handles were taken
        if self.proc.identity_gone(pid, start): return False
        rc, _, _ = self.docker.run(['kill', '--signal', 'KILL', self.rec['container_id']])
        return rc == 0

    def _remove_by_id(self):
        if self.rec and self.rec.get('container_id'):
            self.docker.run(['rm', '--force', '--volumes', self.rec['container_id']])

    def _abort(self):
        try: self.kill_bound()
        except BaseException: pass
        self._remove_by_id()
        if self.handles is not None: self.handles.close()
        if self.attach is not None: self.attach.close()
        if self.log is not None: self.log.close()

    def cleanup(self, handle):
        """Teardown after exit. Exit evidence first, then handles closed, then removal by ID, then the five absence probes."""
        errors = []
        if handle.poll() is None:
            if not self.kill_bound(): errors.append('kill_not_issued')
            deadline = time.monotonic() + 10
            while handle.poll() is None and time.monotonic() < deadline: self.sleep(.05)
        if self.exit_obs is None: self.finalize_exit(handle)
        if self.attach is not None:
            try: self.attach.pump(self.log)
            except OwnerError as e: errors.append(str(e))
            self.attach.close()
        if self.log is not None: self.log.close()
        self.handles.close()
        rc, _, _ = self.docker.run(['rm', '--volumes', self.rec['container_id']])
        if rc != 0: errors.append('docker_rm_failed')
        rec, rc2, err = self._inspect(self.rec['container_id'])
        not_found = rec is None and rc2 == 1 and b'No such' in (err or b'')
        ids = {'net:[%d]' % self.bound['net_ns_inode'], 'mnt:[%d]' % self.bound['mnt_ns_inode'], 'pid:[%d]' % self.bound['pid_ns_inode']}
        absence = {'inspect_not_found': True if not_found else (False if rec is not None else None),
                   'cgroup_unpopulated_or_gone': self.proc.cgroup_unpopulated_or_gone(self.bound['cgroup_path']),
                   'ns_members_empty': not self.proc.ns_members(ids), 'handles_absent': self.handles.closed,
                   'leader_exit_observed': self.exit_obs['leader_exit_observed']}
        wr = dl.wrapper_record(self.bound, absence, errors)
        _jw(self.base / 'wrapper-cleanup.json', wr)
        return wr
