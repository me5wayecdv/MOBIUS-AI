"""HELD source-only trusted owner for ONE Docker role container. Nothing here runs on import; APPROVED_FOR_EXECUTION=False.

Sequence: durable intent -> image record -> pinned-image closure check (docker save under a size ceiling, streamed inventory vs the
independently locked rows for THIS role) -> create (ID from stdout) -> inspect vs exact spec -> attached gated start -> inspect started ->
pidfd / ns fds / cgroup fd with starttime before and after -> bind_started -> durable records -> release byte.
Every post-create failure goes through one cleanup path (`abort`/`cleanup`). Exit is confirmed (daemon record plus held pidfd) BEFORE removal;
namespace/pidfd handles are released before the global scan, the cgroup handle is kept through verification. Attach-client failure is not
container exit. Kill and rm use the bound container ID only. Backends (`docker`, `/proc`) are injected: fake tests prove order and
fail-closed branches, not daemon or kernel behavior. After owner death nothing here can act: recovery stays UNVERIFIED.
"""
import errno
import json
import os
import resource
import select
import subprocess
import time
import tempfile
import shutil
from contextlib import contextmanager
from pathlib import Path

import docker_lifecycle as dl

APPROVED_FOR_EXECUTION = False
SAVE_CEILING = 12 * 1024**3
EXIT_RETRIES = 100


class OwnerError(RuntimeError):
    pass


def _jw(path, obj, replace=False):
    from handoff_io import json_write
    json_write(path, obj, replace=replace)


# ---- real backends (never executed by tests) ----
class DockerCli:
    def __init__(self, docker='/usr/bin/docker', export_guard=None):
        self.docker = docker; self.export_guard = export_guard

    def run(self, args, timeout=30):
        r = subprocess.run([self.docker] + list(args), capture_output=True, timeout=timeout, env={'PATH': '/usr/bin:/bin'}, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr

    @contextmanager
    def export_scratch(self, parent):
        """Client output and ALL CLI temp files live in one private size-bounded tmpfs. Source only, not provisioned or run.
        Daemon staging is separate: save() refuses without a separately implemented export-resource guard."""
        path = Path(tempfile.mkdtemp(prefix='image-export-', dir=parent)); mounted = False
        try:
            subprocess.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', 'size=%d,mode=700,nosuid,nodev,noexec' % SAVE_CEILING,
                            'tmpfs', str(path)], check=True, timeout=5)
            mounted = True
            yield path
        finally:
            if mounted:
                # Delete the whole owned scratch, including hidden .docker_temp_* after a failed save.
                for item in path.iterdir():
                    if item.is_dir() and not item.is_symlink(): shutil.rmtree(item)
                    else: item.unlink()
                subprocess.run(['/usr/bin/umount', str(path)], check=True, timeout=5)
            path.rmdir()

    def save(self, image_id, path):
        """CLI-side `docker save -o`: the client process writes the file, so RLIMIT_FSIZE bounds it. Ceiling failure is an error."""
        if self.export_guard is None: raise OwnerError('daemon export budget not implemented: all real image export HELD')
        self.export_guard(image_id)  # independently enforced daemon/whole-VM budget, not a supplied success boolean
        def lim(): resource.setrlimit(resource.RLIMIT_FSIZE, (SAVE_CEILING, SAVE_CEILING))
        r = subprocess.run([self.docker, 'save', '-o', str(path), image_id], capture_output=True, timeout=1800, env={'PATH': '/usr/bin:/bin'},
                           stdin=subprocess.DEVNULL, preexec_fn=lim)
        return r.returncode

    def attach(self, args):
        return _Attach(subprocess.Popen([self.docker] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        env={'PATH': '/usr/bin:/bin'}, close_fds=True))


class _Attach:
    CEILING = 65536
    QUANTUM = 65536
    def __init__(self, p):
        self.p = p; os.set_blocking(p.stdout.fileno(), False); self.bytes = 0; self.truncated = False; self.closed = False
    def write(self, b): self.p.stdin.write(b); self.p.stdin.flush()
    def poll(self): return self.p.poll()
    def pump(self, sink):
        """Always drains so the workload never blocks on a full pipe; bytes past the ceiling are discarded and flagged, not fatal."""
        drained = 0
        while drained < self.QUANTUM:
            try: d = os.read(self.p.stdout.fileno(), min(4096, self.QUANTUM-drained))
            except BlockingIOError: return
            if not d: return
            drained += len(d)
            left = max(0, self.CEILING - self.bytes)
            if left: sink.write(d[:left]); self.bytes += min(left, len(d))
            if len(d) > left: self.truncated = True
    def close(self):
        if self.closed: return
        errors=[]
        try:
            for f in (self.p.stdin,self.p.stdout):
                try: f.close()
                except (OSError,ValueError) as e: errors.append(type(e).__name__)
        finally:
            # Stream-close failure cannot bypass CLI termination/wait. Never confuse this child with the daemon-owned workload.
            try:
                if self.p.poll() is None: self.p.terminate()
                try: self.p.wait(5)
                except subprocess.TimeoutExpired:
                    self.p.kill();self.p.wait(5)
            finally: self.closed=True
        if errors: raise OwnerError('attach stream close failed: '+','.join(errors))


class Handles:
    def __init__(self, pid, pidfd, ns_fds, cgroup_fd, cgroup_path, t0, t1):
        self.pid, self.pidfd, self.ns_fds, self.cgroup_fd = pid, pidfd, ns_fds, cgroup_fd
        self.cgroup_path, self.t0, self.t1 = cgroup_path, t0, t1
        self.identity_closed = False; self.cgroup_closed = False
    @property
    def closed(self): return self.identity_closed and self.cgroup_closed
    def ns_inodes(self): return {k + '_ns_inode': os.fstat(fd).st_ino for k, fd in self.ns_fds.items()}
    def exited(self): return bool(select.select([self.pidfd], [], [], 0)[0])
    def cgroup_populated(self):
        """Through the HELD cgroup fd. True/False, or None when unreadable (unverified). A removed cgroup reads as ENODEV/ENOENT = gone."""
        try:
            fd = os.open('cgroup.events', os.O_RDONLY, dir_fd=self.cgroup_fd)
            try: text = os.read(fd, 4096).decode()
            finally: os.close(fd)
        except OSError as e:
            return False if e.errno in (errno.ENODEV, errno.ENOENT) else None
        if 'populated 0' in text: return False
        if 'populated 1' in text: return True
        return None
    def close_identity(self):
        if self.identity_closed: return
        for fd in [self.pidfd, *self.ns_fds.values()]:
            try: os.close(fd)
            except OSError: pass
        self.identity_closed = True
    def close_cgroup(self):
        if self.cgroup_closed: return
        try: os.close(self.cgroup_fd)
        except OSError: pass
        self.cgroup_closed = True
    def close(self): self.close_identity(); self.close_cgroup()


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
    def cgroup_path_gone_or_unpopulated(self, cg):
        try: return 'populated 0' in Path('/sys/fs/cgroup' + cg + '/cgroup.events').read_text()
        except FileNotFoundError: return True
        except OSError: return None
    def ns_scan(self, expected):
        """Global scan. Any unreadable entry is counted: callers must treat errors>0 as UNVERIFIED, never as clean."""
        r = {'members': [], 'handles': [], 'errors': 0}
        for pr in Path('/proc').glob('[0-9]*'):
            for k in ('net', 'mnt', 'pid'):
                try:
                    if os.readlink(pr / 'ns' / k) in expected: r['members'].append(str(pr / 'ns' / k))
                except FileNotFoundError: pass
                except OSError: r['errors'] += 1
            try:
                for d in (pr / 'fd').iterdir():
                    try:
                        if os.readlink(d) in expected: r['handles'].append(str(d))
                    except FileNotFoundError: pass
                    except OSError: r['errors'] += 1
            except FileNotFoundError: pass
            except OSError: r['errors'] += 1
        return r


class RoleHandle:
    """Child-like handle. poll() is None until the CONTAINER exit is confirmed; an attach-client death alone never ends it."""
    def __init__(self, owner): self.o = owner; self.returncode = None; self.pid = owner.bound['pid']
    def poll(self):
        if self.o.cleaned: return self.returncode if self.returncode is not None else 255
        self.o.remaining()
        if self.returncode is None: self.o.pump()
        if self.returncode is None and self.o.handles.exited(): self.o.finalize_exit(self)
        return self.returncode
    def wait(self, timeout=None):
        end = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if end is not None and time.monotonic() > end: raise subprocess.TimeoutExpired('docker-role', timeout)
            self.o.sleep(.05)
        return self.returncode
    def pump(self): self.o.pump()


class RoleOwner:
    def __init__(self, root, role, run_id, image, params, backend, proc, host_ns=None, sibling_ns=None, sleep=time.sleep, chown=os.chown,
                 lock_loader=None, limits=None, clock=time.monotonic):
        self.root, self.role, self.run_id, self.image, self.params = Path(root), role, run_id, image, params
        self.docker, self.proc, self.sleep, self.sibling_ns, self.chown = backend, proc, sleep, sibling_ns, chown
        self.lock_loader, self.limits = lock_loader, limits
        self.clock = clock; self.deadline = None; self.prepared_image_id = None; self.cleanup_result = None; self.terminal_failure = False
        self.exit_deadline = None; self.emergency_removal = False
        self.host_ns = host_ns if host_ns is not None else proc.host_ns()
        self.rec = None; self.bound = None; self.handles = None; self.attach = None; self.log = None; self.exit_obs = None
        self.exit_tries = 0; self.base = self.root / role; self.cleaned = False; self.attach_lost = False

    def remaining(self, cap=1):
        if self.deadline is None: return cap
        left = self.deadline-self.clock()
        if left <= 0: raise TimeoutError('absolute owner deadline')
        return min(cap,left)

    def _inspect(self, target, timeout=1):
        rc, out, err = self.docker.run(['inspect', '--type', 'container', target], self.remaining(timeout))
        if rc != 0: return None, rc, err
        try:
            v = json.loads(out); assert isinstance(v, list) and len(v) == 1
            return v[0], rc, err
        except (ValueError, AssertionError): raise OwnerError('inspect output malformed')

    def _closure_gate(self, image_id):
        """Mandatory, before create: the ACTUAL image ID's final filesystem must equal THIS role's independently locked rows."""
        import image_closure
        if self.lock_loader is None: raise OwnerError('role-bound closure lock loader required')
        lock = self.lock_loader(self.role)
        if (not isinstance(lock, dict) or lock.get('role') != self.role or lock.get('image_id') != image_id
                or lock.get('version') != 'docker-image-closure/1' or not isinstance(lock.get('files'), list)):
            raise OwnerError('closure lock not bound to this role and image id')
        try:
            with self.docker.export_scratch(self.root) as scratch:
                path = scratch / 'image.tar'
                if self.docker.save(image_id, path) != 0: raise OwnerError('docker save failed')
                inv = image_closure.inventory_from_save_file(path, image_id, self.limits)
                if not dl.inventory_matches(self.role, inv, lock['files']): raise OwnerError('image inventory differs from the locked closure')
        except image_closure.ClosureError as e:
            raise OwnerError('image archive rejected: %s' % e)

    def prepare_image(self):
        """Must be called for BOTH roles before either role launches. No live workload may coexist with export/inventory work."""
        if self.rec is not None: raise OwnerError('image verification after launch forbidden')
        if self.prepared_image_id is not None: return self.prepared_image_id
        rc, out, _ = self.docker.run(['image', 'inspect', self.image], timeout=5)
        try:
            if rc != 0: raise dl.SpecError('image inspect failed')
            imgs = json.loads(out)
            if not isinstance(imgs, list) or len(imgs) != 1: raise dl.SpecError('image record count')
            image_id = dl.validate_image_record(imgs[0], self.image)
        except (ValueError, dl.SpecError) as e:
            raise OwnerError('image not bound: %s' % type(e).__name__)
        self._closure_gate(image_id)
        self.prepared_image_id = image_id
        return image_id

    def launch(self):
        if self.rec is not None: raise OwnerError('single launch per owner')
        intent = dl.launch_intent(self.role, self.run_id)
        self.rec = {**intent, 'stage': 'before_create', 'container_id': None}
        _jw(self.root / (self.role + '-launch-intent.json'), {**intent, 'backend': 'docker', 'exact_output': str(self.base), 'root_owned': True})
        gid = self.params.get('kvm_gid') if self.role == 'runtime' else 65534
        self.base.mkdir(mode=0o700, exist_ok=True)
        work = self.base / 'work'; work.mkdir(mode=0o700, exist_ok=False); self.chown(work, 65534, gid)
        if not (self.root / (self.role + '-in')).is_dir(): raise OwnerError('inbox must pre-exist')
        image_id = self.prepared_image_id
        if image_id is None: raise OwnerError('both role images must be preverified before launch')
        self.deadline = self.clock()+5  # entire create/start/acquire/release, not per-iteration timeout
        argv = dl.create_argv(self.role, self.run_id, self.image, docker=self.docker.docker, **self.params)
        rc, out, _ = self.docker.run(argv[1:], timeout=self.remaining())
        self.rec = dl.after_create(intent, out if rc == 0 else b'')
        if self.rec['stage'] != 'created':
            raise OwnerError('create output ambiguous: container UNVERIFIED, never removed by name')
        cid = self.rec['container_id']
        try:  # ID persistence and ALL post-create states
            _jw(self.root / (self.role + '-container-record.json'), self.rec)
            rec, _, _ = self._inspect(cid)
            if rec is None: raise dl.SpecError('created container not inspectable')
            dl.validate_inspect(rec, self.role, self.run_id, self.image, image_id, **self.params)
            self.log = (self.root / (self.role + '.docker.log')).open('xb')
            self.attach = self.docker.attach(['start', '--attach', '--interactive', cid])
            started, _, _ = self._inspect(cid)
            while True:
                if started and (started.get('State') or {}).get('Running') is True and type((started['State']).get('Pid')) is int and started['State']['Pid'] >= 2: break
                self.remaining(); self.sleep(.05); self.pump(); started, _, _ = self._inspect(cid)
            pid = ((started or {}).get('State') or {}).get('Pid')
            if type(pid) is not int or pid < 2: raise dl.SpecError('started pid not observed')
            self.handles = self.proc.acquire(pid)
            h = self.handles
            observed = {'pid': pid, 'cgroup_path': h.cgroup_path, 'start_ticks_before': h.t0, 'start_ticks_after': h.t1,
                        'pidfd_held': not h.identity_closed and h.pidfd is not None, 'ns_fds_held': not h.identity_closed and len(h.ns_fds) == 3,
                        'cgroup_fd_held': not h.cgroup_closed and h.cgroup_fd is not None, **h.ns_inodes()}
            self.bound = dl.bind_started(self.rec, started, observed, self.host_ns, self.sibling_ns)
            _jw(self.base / 'namespace-setup.json', dl.namespace_setup_record(self.bound))
            _jw(self.root / (self.role + '-launch.json'), {'role': self.role, 'backend': 'docker', 'container_id': cid,
                'identity': {'pid': pid, 'start_ticks': h.t0, 'backend': 'docker', 'container_id': cid}, 'started_monotonic': time.monotonic(),
                'root_owned_lifecycle': True})
            self.remaining()
            self.attach.write(b'\x01')       # release only after identity is durable
            self.bound['gate_released'] = True
            self.deadline = self.clock()+420
        except BaseException as e:
            self.abort(); raise OwnerError('launch failed closed after create: %s' % type(e).__name__)
        return RoleHandle(self)

    def pump(self):
        if self.attach is None or self.log is None or self.log.closed: return
        try: self.attach.pump(self.log)
        except (OSError, ValueError): pass
        if self.attach.poll() is not None and not self.attach_lost:
            self.attach_lost = True      # recorded, NOT treated as container exit; workload is still bounded by relay deadlines and kill_bound

    # ---- exit, kill, removal, absence ----
    def finalize_exit(self, handle):
        """Terminal only when the daemon's exit record is present with the pidfd exit, or after a bounded number of tries (then 255, UNVERIFIED)."""
        if self.exit_obs is not None and self.exit_obs['leader_exit_observed']: return
        rec, _, _ = self._inspect(self.rec['container_id'])
        obs = dl.leader_exit_observed(rec or {}, self.bound, self.handles.exited(), self.proc.identity_gone(self.bound['pid'], self.bound['start_ticks']))
        self.exit_tries += 1
        if self.exit_deadline is None: self.exit_deadline = self.clock()+3
        if not obs['leader_exit_observed'] and self.exit_tries < EXIT_RETRIES and self.clock() < self.exit_deadline:
            return                                     # not terminal: daemon record may lag the pidfd; poll again
        self.exit_obs = obs
        _jw(self.base / 'namespace-driver-result.json', dl.driver_result_record(obs))
        handle.returncode = obs['exit_code'] if obs['leader_exit_observed'] else 255

    def kill_bound(self):
        """Live-owner kill, bound container ID only, only while the held identity still matches. Never a group kill or a name."""
        if self.handles is None or self.rec is None or self.handles.identity_closed or self.handles.exited(): return False
        pid, start = (self.bound['pid'], self.bound['start_ticks']) if self.bound else (self.handles.pid, self.handles.t0)
        if self.proc.identity_gone(pid, start): return False
        rc, _, _ = self.docker.run(['kill', '--signal', 'KILL', self.rec['container_id']], timeout=self.remaining())
        return rc == 0

    def _rm(self, force):
        cid = (self.rec or {}).get('container_id')
        if not cid: return None
        if force: self.emergency_removal = True  # exact-owned-ID emergency effect, NEVER identity-guarded kill or verified absence
        return self.docker.run(['rm'] + (['--force'] if force else []) + ['--volumes', cid], timeout=self.remaining())[0]

    def abort(self):
        """One path for every post-create failure: kill by held identity if possible, remove by ID, release every handle, reap the CLI."""
        if self.cleaned: return self.cleanup_result
        self.deadline = self.clock()+5
        self.terminal_failure = True
        errors = []
        for step in (self.kill_bound, lambda: self._rm(True)):
            try: step()
            except BaseException as e: errors.append(type(e).__name__)
        for c in (lambda: self.handles and self.handles.close(), lambda: self.attach and self.attach.close(), lambda: self.log and self.log.close()):
            try: c()
            except BaseException as e: errors.append(type(e).__name__)
        self.cleaned = True
        try: _jw(self.root / (self.role + '-launch-failure.json'), {'role': self.role, 'run_id': self.run_id, 'container_id': (self.rec or {}).get('container_id'),
                 'state': 'UNVERIFIED', 'emergency_exact_owned_id_removal_attempted': self.emergency_removal, 'errors': errors, 'not_a_cleanup_proof': True})
        except BaseException: pass

    def cleanup(self, handle=None):
        if self.cleaned: return self.cleanup_result
        try:
            self.cleanup_result = self._cleanup(handle)
            return self.cleanup_result
        except BaseException:
            self.terminal_failure = True
            # Conservative emergency exact-ID cleanup. It makes NO exit or absence claim.
            self.deadline = self.clock()+3
            try: self._rm(True)
            except BaseException: pass
            try:
                _jw(self.root / (self.role+'-cleanup-failure.json'), {'state':'UNVERIFIED', 'role':self.role,
                    'run_id':self.run_id, 'container_id':(self.rec or {}).get('container_id'),
                    'emergency_exact_owned_id_removal_attempted':self.emergency_removal, 'not_a_cleanup_proof':True})
            except BaseException: pass
            raise
        finally:
            for closer in (lambda: self.handles and self.handles.close(), lambda: self.attach and self.attach.close(), lambda: self.log and self.log.close()):
                try: closer()
                except BaseException: self.terminal_failure = True
            self.cleaned = True

    def _cleanup(self, handle=None):
        """Teardown after exit. Order: confirm exit (kill by ID if still live), release identity handles, rm by ID, probes, release cgroup fd."""
        if self.bound is None:
            if not self.cleaned: self.abort()
            return None
        errors = []
        self.deadline = self.clock()+10
        h = handle or RoleHandle(self)
        if h.poll() is None:
            if not self.kill_bound(): errors.append('kill_not_issued')
            while h.poll() is None and self.clock() < self.deadline: self.sleep(.05)
        if self.exit_obs is None:
            self.exit_tries = EXIT_RETRIES; self.finalize_exit(h)
        if not self.exit_obs['leader_exit_observed']: errors.append('exit_unverified')
        self.pump()
        if self.attach is not None: self.attach.close()
        if self.log is not None: self.log.close()
        self.handles.close_identity()
        rc = self._rm(not self.exit_obs['leader_exit_observed'])   # force only when exit was never confirmed
        if rc != 0: errors.append('docker_rm_failed')
        rec, rc2, err = self._inspect(self.rec['container_id'])
        not_found = rec is None and rc2 == 1 and b'No such' in (err or b'')
        ids = {'net:[%d]' % self.bound['net_ns_inode'], 'mnt:[%d]' % self.bound['mnt_ns_inode'], 'pid:[%d]' % self.bound['pid_ns_inode']}
        via_fd = self.handles.cgroup_populated(); via_path = self.proc.cgroup_path_gone_or_unpopulated(self.bound['cgroup_path'])
        cg = None if (via_fd is None or via_path is None) else (via_fd is False and via_path is True)
        if via_fd is True or via_path is False: cg = False
        scan = self.proc.ns_scan(ids)
        self.handles.close_cgroup()
        clean_scan = scan['errors'] == 0
        absence = {'inspect_not_found': True if not_found else (False if rec is not None else None), 'cgroup_unpopulated_or_gone': cg,
                   'ns_members_empty': False if scan['members'] else (True if clean_scan else None),
                   'handles_absent': False if (scan['handles'] or not self.handles.closed) else (True if clean_scan else None),
                   'leader_exit_observed': self.exit_obs['leader_exit_observed']}
        self.cleaned = True
        if self.emergency_removal:
            errors.append('emergency_exact_id_removal_not_verified_absence')
            absence['leader_exit_observed'] = False
        wr = dl.wrapper_record(self.bound, absence, errors)
        _jw(self.base / 'wrapper-cleanup.json', wr)
        return wr


def prepare_pair(owners):
    """Owner-side preflight, not a predicate: actual verification of both distinct role images, no launch until both return."""
    if set(owners) != set(dl.ROLES) or any(o.rec is not None for o in owners.values()):
        raise OwnerError('two unlaunched owners required')
    if owners['runtime'].image == owners['control'].image: raise OwnerError('distinct role images required')
    for role in dl.ROLES: owners[role].prepare_image()
    if owners['runtime'].prepared_image_id == owners['control'].prepared_image_id:
        raise OwnerError('distinct actual role image IDs required')
