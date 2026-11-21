"""HELD source-only Docker lifecycle adapter for the outer owner (v2). Nothing here runs docker.

Builds the exact `docker create` argv for ONE run-bound role container and validates supplied engine records
(`docker inspect`, `docker image inspect`) against that exact spec. Predicates validate supplied records and cannot
create provenance, permission or host evidence. Field names follow the Docker Engine API schema (moby swagger.yaml v27.3.1:
ContainerInspectResponse.HostConfig, MountPoint{Type,Source,Destination,Mode,RW,Propagation}, DeviceMapping{PathOnHost,
PathInContainer,CgroupPermissions}); it is a PARTIAL ALLOWLIST of security-relevant fields, not every-field exactness.
No privileged mode, no host PID/net/IPC, no docker socket in a payload, no broad mount, no pull. The daemon API is
host-root-level and belongs only to the trusted outer owner.
Mirrors namespace_supervisor.py run controls: uid 65534, gid=kvm_gid (runtime), /work rw, /control inbox ro, fixed env,
rlimits cpu 300s / as 8GiB / fsize 4GiB, entrypoint /runtime/bin/python <driver> /work, no uplink, KVM only for runtime.
"""
import re

APPROVED_FOR_EXECUTION = False
ROLES = ('runtime', 'control')
DIGEST = re.compile(r'[a-z0-9][a-z0-9._/-]{0,127}@sha256:[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
RUN_ID = re.compile(r'[0-9a-f]{32}')
CONTAINER_ID = re.compile(r'[0-9a-f]{64}')
KVM_DEV = {'PathOnHost': '/dev/kvm', 'PathInContainer': '/dev/kvm', 'CgroupPermissions': 'rw'}
EXE = '/runtime/bin/python'
GATE = '/fixture/container_gate.py'
DRIVER = {'runtime': '/fixture/contained_driver.py', 'control': '/fixture/control_driver.py'}
ENV = ['PATH=/opt/android/platform-tools:/runtime/bin:/usr/bin:/bin', 'HOME=/home/fixture', 'ANDROID_USER_HOME=/home/fixture',
       'TMPDIR=/tmp', 'LANG=C.UTF-8', 'ADB_SERVER_SOCKET=tcp:127.0.0.1:5037', 'ADB_MDNS_AUTO_CONNECT=0']
ULIMITS = [('as', 8 * 1024**3), ('core', 0), ('cpu', 300), ('fsize', 4 * 1024**3), ('nofile', 512), ('nproc', 512)]
# nproc=512 restores namespace_supervisor.child_setup. CAVEAT: RLIMIT_NPROC counts per real uid across the HOST, so the two sibling
# containers (both uid 65534) and any other 65534 process share one budget; --pids-limit is the separate per-container cgroup bound.
GATE_SECONDS = 30   # container_gate.py deadline; kept in sync by test
SCRATCH = (('/tmp', 'size=256m,mode=1777'), ('/run', 'size=16m,mode=755'), ('/dev/shm', 'size=512m,mode=1777'), ('/home/fixture', 'size=4g,mode=700'))


class SpecError(ValueError):
    pass


def container_name(role, run_id):
    return 'd061-%s-%s' % (role, run_id)


def _root(run_id):
    return '/opt/d061-owned-android-run-' + run_id


def mount_sources(role, run_id):
    """work (rw, child-written) and inbox (ro, relay-written), exactly the dirs namespace_supervisor binds today."""
    return _root(run_id) + '/%s/work' % role, _root(run_id) + '/%s-in' % role


def _check(role, run_id, image, mem_mb, pids, cpus, kvm_gid):
    if role not in ROLES: raise SpecError('role')
    if not RUN_ID.fullmatch(run_id or ''): raise SpecError('run id')
    if not DIGEST.fullmatch(image or ''): raise SpecError('image must be a pinned digest')
    if type(mem_mb) is not int or not 256 <= mem_mb <= 16384: raise SpecError('memory MiB 256..16384')
    if type(pids) is not int or not 16 <= pids <= 4096: raise SpecError('pids 16..4096')
    if type(cpus) is not int or not 1 <= cpus <= 4: raise SpecError('whole cpus 1..4')
    if role == 'runtime' and (type(kvm_gid) is not int or not 1 <= kvm_gid <= 65533): raise SpecError('kvm gid required for runtime')


def user_for(role, kvm_gid):
    return '65534:%d' % kvm_gid if role == 'runtime' else '65534:65534'


def scratch_for(role, kvm_gid):
    """Exact tmpfs map equivalent to namespace_supervisor's private bounded mounts (owner uid 65534, gid as the role's primary gid).
    Same option set as the jail: nosuid,nodev, exec allowed (the jail did not set noexec). The engine's treatment of default
    tmpfs options (it may add noexec unless `exec` is given) and of `uid=`/`gid=` is NOT verified; any mismatch fails closed."""
    gid = kvm_gid if role == 'runtime' else 65534
    return {path: 'rw,nosuid,nodev,exec,%s,uid=65534,gid=%d' % (opts, gid) for path, opts in SCRATCH}


def cmd_for(role):
    return [GATE, DRIVER[role], '/work']


def create_argv(role, run_id, image, *, mem_mb, pids, cpus, kvm_gid=None, docker='/usr/bin/docker'):
    _check(role, run_id, image, mem_mb, pids, cpus, kvm_gid)
    work, inbox = mount_sources(role, run_id)
    a = [docker, 'create', '--name', container_name(role, run_id), '--pull', 'never', '--network', 'none', '--ipc', 'none',
         '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--interactive',
         '--user', user_for(role, kvm_gid), '--memory', '%dm' % mem_mb, '--memory-swap', '%dm' % mem_mb,
         '--pids-limit', str(pids), '--cpus', str(cpus), '--restart', 'no', '--log-driver', 'none', '--no-healthcheck',
         '--cgroupns', 'private', '--runtime', 'runc', '--workdir', '/work', '--entrypoint', EXE,
         '--label', 'd061.run_id=' + run_id, '--label', 'd061.role=' + role]
    for n, v in ULIMITS: a += ['--ulimit', '%s=%d:%d' % (n, v, v)]
    for path, opts in scratch_for(role, kvm_gid).items(): a += ['--tmpfs', '%s:%s' % (path, opts)]
    for e in ENV: a += ['--env', e]
    a += ['--mount', 'type=bind,src=%s,dst=/work,bind-propagation=rprivate' % work,
          '--mount', 'type=bind,src=%s,dst=/control,readonly,bind-propagation=rprivate' % inbox]
    if role == 'runtime': a += ['--device', '/dev/kvm:/dev/kvm:rw']
    return a + [image] + cmd_for(role)


def validate_image_record(img, image):
    """`docker image inspect` record read independently of create. Returns the image ID the container must run."""
    if not DIGEST.fullmatch(image or ''): raise SpecError('image must be a pinned digest')
    try:
        if not IMAGE_ID.fullmatch(img['Id']) or image not in (img.get('RepoDigests') or []): raise SpecError('image id/digest binding')
    except (KeyError, TypeError, AttributeError):
        raise SpecError('image record malformed')
    return img['Id']


def validate_inspect(rec, role, run_id, image, image_id, *, mem_mb, pids, cpus, kvm_gid=None):
    _check(role, run_id, image, mem_mb, pids, cpus, kvm_gid)
    if not IMAGE_ID.fullmatch(image_id or ''): raise SpecError('image id')
    work, inbox = mount_sources(role, run_id)
    bad = []
    def need(ok, what):
        if not ok: bad.append(what)
    try:
        h, c = rec['HostConfig'], rec['Config']
        need(CONTAINER_ID.fullmatch(rec.get('Id', '')) is not None, 'id')
        need(rec.get('Name') == '/' + container_name(role, run_id), 'name')
        need(rec.get('Image') == image_id and c.get('Image') == image, 'image binding')
        need(h.get('NetworkMode') == 'none', 'network')
        need(h.get('Privileged') is False, 'privileged')
        need(h.get('PidMode') in ('', None), 'pidmode')
        need(h.get('IpcMode') == 'none', 'ipc')
        need(h.get('UTSMode') in ('', None), 'uts')
        need(h.get('UsernsMode') in ('', None), 'userns')
        need(h.get('CgroupnsMode') == 'private', 'cgroupns')
        need(h.get('Runtime') == 'runc', 'runtime')
        need(h.get('CapDrop') == ['ALL'] and not h.get('CapAdd'), 'caps')
        need(h.get('SecurityOpt') in (['no-new-privileges'], ['no-new-privileges:true']), 'security opts exact')
        need(h.get('ReadonlyRootfs') is True, 'rootfs')
        need(not h.get('GroupAdd'), 'group add')
        need(not h.get('DeviceRequests'), 'device requests')
        need(not h.get('ExtraHosts') and not h.get('Dns') and not h.get('Links') and not h.get('VolumesFrom')
             and not h.get('PortBindings') and not h.get('Binds') and not h.get('DeviceCgroupRules'), 'extra host config')
        need(h.get('OomKillDisable') in (False, None), 'oom')
        need((h.get('RestartPolicy') or {}).get('Name') in ('no', ''), 'restart')
        need((h.get('LogConfig') or {}).get('Type') == 'none', 'log driver')
        mem = mem_mb * 1048576
        need(h.get('Memory') == mem and h.get('MemorySwap') == mem, 'memory')
        need(h.get('PidsLimit') == pids and h.get('NanoCpus') == cpus * 10**9, 'pids/cpus')
        need(sorted((u.get('Name'), u.get('Soft'), u.get('Hard')) for u in (h.get('Ulimits') or [])) == sorted((n, v, v) for n, v in ULIMITS), 'ulimits')
        need((h.get('Devices') or []) == ([KVM_DEV] if role == 'runtime' else []), 'devices exact tuple')
        need((h.get('Tmpfs') or {}) == scratch_for(role, kvm_gid), 'tmpfs scratch exact (as supplied, engine normalization unverified)')
        def norm(m):   # declared normalization: drop falsy engine defaults, keep every truthy field
            o = {k: v for k, v in m.items() if v not in (False, None, '', {}, [])}
            if isinstance(o.get('BindOptions'), dict):
                o['BindOptions'] = {k: v for k, v in o['BindOptions'].items() if v not in (False, None, '', {}, [])}
            return o
        want_m = [{'Type': 'bind', 'Source': inbox, 'Target': '/control', 'ReadOnly': True, 'BindOptions': {'Propagation': 'rprivate'}},
                  {'Type': 'bind', 'Source': work, 'Target': '/work', 'BindOptions': {'Propagation': 'rprivate'}}]
        got_m = sorted((norm(m) for m in (h.get('Mounts') or [])), key=lambda m: str(m.get('Target')))
        need(got_m == sorted(want_m, key=lambda m: m['Target']), 'HostConfig.Mounts exact (after falsy-default normalization)')
        want = [{'Type': 'bind', 'Source': inbox, 'Destination': '/control', 'RW': False, 'Propagation': 'rprivate'},
                {'Type': 'bind', 'Source': work, 'Destination': '/work', 'RW': True, 'Propagation': 'rprivate'}]
        got = sorted(({k: m.get(k) for k in ('Type', 'Source', 'Destination', 'RW', 'Propagation')} for m in (rec.get('Mounts') or [])),
                     key=lambda m: str(m['Destination']))
        need(got == want, 'mounts exact (control ro, work rw, nothing else)')
        need(c.get('User') == user_for(role, kvm_gid), 'user')
        need(c.get('Entrypoint') == [EXE] and c.get('Cmd') == cmd_for(role), 'entrypoint/cmd')
        need(sorted(c.get('Env') or []) == sorted(ENV), 'env exact (image must add none)')
        need(c.get('WorkingDir') == '/work' and not c.get('Volumes'), 'workdir/declared volumes')
        need(c.get('Healthcheck') in (None, {'Test': ['NONE']}), 'healthcheck')
        need(c.get('OpenStdin') is True and c.get('Tty') is False and c.get('AttachStdin') is False, 'stdin gate')
        lb = c.get('Labels') or {}
        need(lb.get('d061.run_id') == run_id and lb.get('d061.role') == role, 'labels')
        need((rec.get('State') or {}).get('Status') == 'created', 'state not created')
    except (KeyError, TypeError, AttributeError):
        raise SpecError('inspect record malformed')
    if bad: raise SpecError('inspect differs from exact spec: ' + ','.join(bad))
    return {'validated_record_only': True, 'daemon_enforcement_verified': False}


def role_closure_ok(role, names, *, kvm_gid_unused=None):
    """Predicate over a SUPPLIED file-name list of the role image. Acquisition of that list is an open item."""
    if role not in ROLES or not isinstance(names, list): return False
    if role == 'control':
        low = [str(n).lower() for n in names]
        if any(n.startswith('/opt/android/') or '/adb' in n or 'emulator' in n or 'qemu' in n for n in low): return False
    return all(isinstance(n, str) and n.startswith('/') for n in names) and DRIVER[role] in names and GATE in names


# Launch lifecycle: intent (before effects) -> create -> bind ID -> start gated -> bind observed identity -> release.
def launch_intent(role, run_id):
    if role not in ROLES or not RUN_ID.fullmatch(run_id or ''): raise SpecError('role/run')
    return {'role': role, 'run_id': run_id, 'name': container_name(role, run_id), 'stage': 'before_create', 'may_remove_by_name': False}


def after_create(intent, create_stdout):
    """The ID exists only after `docker create` returns. Missing/garbled output keeps the attempt UNVERIFIED: never delete by name."""
    if intent.get('stage') != 'before_create': raise SpecError('stage')
    s = create_stdout.decode('ascii', 'replace') if isinstance(create_stdout, bytes) else create_stdout
    if not isinstance(s, str) or not CONTAINER_ID.fullmatch(s.strip()) or not s.endswith('\n'):
        return {**intent, 'stage': 'create_unverified', 'container_id': None, 'may_remove_by_name': False, 'state': 'UNVERIFIED'}
    return {**intent, 'stage': 'created', 'container_id': s.strip(), 'may_remove_by_name': False}


NS_KEYS = ('pid_ns_inode', 'mnt_ns_inode', 'net_ns_inode')
_UNSET = object()


def complete_ns(d):
    """Typed complete identity: exactly pid/mnt/net namespace inodes, positive ints."""
    return isinstance(d, dict) and set(d) == set(NS_KEYS) and all(type(d[k]) is int and d[k] > 0 for k in NS_KEYS)


def bind_started(rec, inspect_started, observed, host_ns, sibling_ns=_UNSET):
    """`observed` = owner's reads made FROM ITS HELD HANDLES for the leader pid (built by docker_owner from a Handles object, not
    caller booleans). `host_ns` must be the complete typed host pid/mnt/net identity. `sibling_ns` is required: None only when the
    other role has not been launched, otherwise the sibling's complete identity. Gate is still closed here."""
    cid = rec.get('container_id')
    if rec.get('stage') != 'created' or not cid: raise SpecError('created container id required')
    st = (inspect_started or {}).get('State') or {}
    pid = st.get('Pid')
    if inspect_started.get('Id') != cid or st.get('Running') is not True or type(pid) is not int or pid < 2: raise SpecError('started state')
    if observed.get('pid') != pid: raise SpecError('observed pid differs')
    cg = observed.get('cgroup_path')
    if not isinstance(cg, str) or not re.fullmatch(r'/[A-Za-z0-9_./:@-]{1,300}', cg) or '..' in cg or cid not in cg: raise SpecError('cgroup path not bound to this container id')
    ns = {k: observed.get(k) for k in NS_KEYS}
    if not complete_ns(ns): raise SpecError('complete namespace identity required')
    t0, t1 = observed.get('start_ticks_before'), observed.get('start_ticks_after')
    if type(t0) is not int or t0 <= 0 or t0 != t1: raise SpecError('same-process start identity (stat starttime before/after) required')
    if not (observed.get('pidfd_held') is True and observed.get('ns_fds_held') is True and observed.get('cgroup_fd_held') is True):
        raise SpecError('pidfd, namespace fds and cgroup dir fd must be held before release')
    if not complete_ns(host_ns): raise SpecError('complete typed host pid/mnt/net identity required')
    if any(ns[k] == host_ns[k] for k in NS_KEYS): raise SpecError('container shares a host namespace')
    if sibling_ns is _UNSET: raise SpecError('sibling identity must be given explicitly (None only when no sibling was launched)')
    if sibling_ns is not None:
        if not complete_ns(sibling_ns): raise SpecError('complete typed sibling identity required')
        if any(ns[k] == sibling_ns[k] for k in NS_KEYS): raise SpecError('container shares a namespace with the sibling')
    return {**rec, 'stage': 'started_gated', 'pid': pid, 'start_ticks': t0, 'cgroup_path': cg, **ns,
            'gate_seconds': GATE_SECONDS, 'gate_released': False, 'identity_scope': 'owner_held_fds_and_starttime_not_a_daemon_child'}


def absence_verdict(rec):
    """All five required; Docker removal alone is never accepted. Missing evidence is UNVERIFIED, any False is PRESENT."""
    keys = ('inspect_not_found', 'cgroup_unpopulated_or_gone', 'ns_members_empty', 'handles_absent', 'leader_exit_observed')
    if not isinstance(rec, dict): return 'UNVERIFIED'
    vals = [rec.get(k) for k in keys]
    if any(v is False for v in vals): return 'PRESENT'
    if all(v is True for v in vals): return 'VERIFIED_ABSENT_RECORD'
    return 'UNVERIFIED'


def leader_exit_observed(inspect_exited, bound, pidfd_readable, identity_changed_or_gone):
    """Translated `leader_reaped`: the container init is a daemon child, not ours, so waitpid is impossible. Accepts only the
    DAEMON's exit record (Running false, Status exited, Pid 0, integer ExitCode, same container ID) AND the owner's own held pidfd
    reporting exit (or an exact-identity check showing that pid/starttime is gone). Labeled as translated, not as a reap."""
    st = (inspect_exited or {}).get('State') or {}
    ok = (bound.get('stage') == 'started_gated' and inspect_exited.get('Id') == bound.get('container_id') and st.get('Running') is False
          and st.get('Status') == 'exited' and st.get('Pid') == 0 and type(st.get('ExitCode')) is int
          and (pidfd_readable is True or identity_changed_or_gone is True))
    return {'leader_exit_observed': bool(ok), 'exit_code': st.get('ExitCode') if ok else None, 'scope': 'translated_daemon_exit_plus_owner_pidfd_not_waitpid'}


# Translated trusted evidence producer: the OWNER writes these from held observations. They replace files namespace_supervisor wrote from
# inside the jail. Existing consumers (owned_absence.inspect, owned_collect, final_export ROLE_FILES) expect jail-shaped fields
# (e.g. wrapper-cleanup.jail under /opt/d061-owned-android-jail-*), so they CANNOT consume these unchanged: a reviewed sibling schema change is required.
def namespace_setup_record(bound):
    if bound.get('stage') != 'started_gated': raise SpecError('bound identity required')
    return {'namespaces': {'net': 'net:[%d]' % bound['net_ns_inode'], 'mnt': 'mnt:[%d]' % bound['mnt_ns_inode'], 'pid': 'pid:[%d]' % bound['pid_ns_inode']},
            'backend': 'docker', 'run_id': bound['run_id'], 'role': bound['role'], 'container_id': bound['container_id'],
            'cgroup_path': bound['cgroup_path'], 'start_ticks': bound['start_ticks'], 'scope': 'docker_translated_owner_observation'}


def driver_result_record(exit_obs):
    if not exit_obs.get('leader_exit_observed'): return {'complete': False, 'driver_rc': None, 'scope': exit_obs.get('scope')}
    return {'complete': exit_obs['exit_code'] == 0, 'driver_rc': exit_obs['exit_code'], 'backend': 'docker', 'scope': exit_obs['scope']}


ABSENCE_KEYS = ('inspect_not_found', 'cgroup_unpopulated_or_gone', 'ns_members_empty', 'handles_absent', 'leader_exit_observed')


def wrapper_record(bound, absence, errors):
    """Backend-tagged replacement for wrapper-cleanup.json. `container_absent` is derived from the five-part absence verdict only."""
    verdict = absence_verdict(absence)
    return {'backend': 'docker', 'run_id': bound['run_id'], 'role': bound['role'], 'container_id': bound['container_id'],
            'absence': {k: (absence or {}).get(k) for k in ABSENCE_KEYS}, 'verdict': verdict,
            'container_absent': verdict == 'VERIFIED_ABSENT_RECORD' and not errors, 'errors': list(errors),
            'scope': 'docker_translated_owner_observation_not_daemon_enforcement_proof'}


def wrapper_problems(setup, wrapper, role=None, run_id=None):
    """Consumer-side check of backend-tagged records. Empty list = acceptable. Mixed backend/run/role/container records fail."""
    p = []
    if not isinstance(setup, dict) or not isinstance(wrapper, dict): return ['records']
    if setup.get('backend') != 'docker' or wrapper.get('backend') != 'docker': p.append('mixed_or_untagged_backend')
    if setup.get('container_id') != wrapper.get('container_id') or not CONTAINER_ID.fullmatch(str(wrapper.get('container_id'))): p.append('container_id')
    if setup.get('run_id') != wrapper.get('run_id') or not RUN_ID.fullmatch(str(wrapper.get('run_id'))): p.append('run_id')
    if setup.get('role') != wrapper.get('role') or wrapper.get('role') not in ROLES: p.append('role')
    if role is not None and wrapper.get('role') != role: p.append('role_differs_from_directory')
    if run_id is not None and wrapper.get('run_id') != run_id: p.append('run_differs_from_root')
    if wrapper.get('errors') != [] or wrapper.get('container_absent') is not True or absence_verdict(wrapper.get('absence')) != 'VERIFIED_ABSENT_RECORD' or wrapper.get('verdict') != 'VERIFIED_ABSENT_RECORD':
        p.append('absence_not_verified')
    return p


def inventory_matches(role, inventory, lock_rows):
    """Typed equality between an image inventory (image_closure.inventory_from_save: {path: entry}) and independently supplied lock rows
    ([{path, type, mode, ...}]) including type/mode/link/sha256, plus gate/driver presence and control-lacks-runtime."""
    if role not in ROLES or not isinstance(inventory, dict) or not isinstance(lock_rows, list): return False
    try: want = {r['path']: {k: v for k, v in r.items() if k != 'path'} for r in lock_rows}
    except (KeyError, TypeError, AttributeError): return False
    if len(want) != len(lock_rows) or inventory != want: return False
    return role_closure_ok(role, sorted(inventory))
