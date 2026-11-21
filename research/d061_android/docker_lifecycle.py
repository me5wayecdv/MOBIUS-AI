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
ULIMITS = [('as', 8 * 1024**3), ('cpu', 300), ('fsize', 4 * 1024**3)]
ALLOWED_BIND_OPTS = {'Propagation', 'NonRecursive', 'CreateMountpoint', 'ReadOnlyNonRecursive', 'ReadOnlyForceRecursive'}


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


def cmd_for(role):
    return [GATE, DRIVER[role], '/work']


def create_argv(role, run_id, image, *, mem_mb, pids, cpus, kvm_gid=None, docker='/usr/bin/docker'):
    _check(role, run_id, image, mem_mb, pids, cpus, kvm_gid)
    work, inbox = mount_sources(role, run_id)
    a = [docker, 'create', '--name', container_name(role, run_id), '--pull', 'never', '--network', 'none', '--ipc', 'none',
         '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--interactive',
         '--user', user_for(role, kvm_gid), '--memory', '%dm' % mem_mb, '--memory-swap', '%dm' % mem_mb,
         '--pids-limit', str(pids), '--cpus', str(cpus), '--restart', 'no', '--log-driver', 'none', '--no-healthcheck',
         '--cgroupns', 'private', '--workdir', '/work', '--entrypoint', EXE,
         '--label', 'd061.run_id=' + run_id, '--label', 'd061.role=' + role]
    for n, v in ULIMITS: a += ['--ulimit', '%s=%d:%d' % (n, v, v)]
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
        need(not h.get('Tmpfs') and not h.get('ExtraHosts') and not h.get('Dns') and not h.get('Links') and not h.get('VolumesFrom')
             and not h.get('PortBindings') and not h.get('Binds') and not h.get('DeviceCgroupRules'), 'extra host config')
        need(h.get('OomKillDisable') in (False, None), 'oom')
        need((h.get('RestartPolicy') or {}).get('Name') in ('no', ''), 'restart')
        need((h.get('LogConfig') or {}).get('Type') == 'none', 'log driver')
        mem = mem_mb * 1048576
        need(h.get('Memory') == mem and h.get('MemorySwap') == mem, 'memory')
        need(h.get('PidsLimit') == pids and h.get('NanoCpus') == cpus * 10**9, 'pids/cpus')
        need(sorted((u.get('Name'), u.get('Soft'), u.get('Hard')) for u in (h.get('Ulimits') or [])) == sorted((n, v, v) for n, v in ULIMITS), 'ulimits')
        need((h.get('Devices') or []) == ([KVM_DEV] if role == 'runtime' else []), 'devices exact tuple')
        for m in h.get('Mounts') or []:
            bo = m.get('BindOptions') or {}
            need(set(bo) <= ALLOWED_BIND_OPTS and bo.get('Propagation') == 'rprivate' and not bo.get('CreateMountpoint'), 'bind options')
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


def bind_started(rec, inspect_started, observed, host_netns_inode):
    """`observed` = owner's own host-side reads for the leader pid: pid, unified cgroup path from /proc/<pid>/cgroup,
    pid/mnt/net namespace inodes. Gate is still closed here. Returns the identity record to persist before release."""
    cid = rec.get('container_id')
    if rec.get('stage') != 'created' or not cid: raise SpecError('created container id required')
    st = (inspect_started or {}).get('State') or {}
    pid = st.get('Pid')
    if inspect_started.get('Id') != cid or st.get('Running') is not True or type(pid) is not int or pid < 2: raise SpecError('started state')
    if observed.get('pid') != pid: raise SpecError('observed pid differs')
    cg = observed.get('cgroup_path')
    if not isinstance(cg, str) or not re.fullmatch(r'/[A-Za-z0-9_./:@-]{1,300}', cg) or '..' in cg or cid not in cg: raise SpecError('cgroup path not bound to this container id')
    ns = {k: observed.get(k) for k in ('pid_ns_inode', 'mnt_ns_inode', 'net_ns_inode')}
    if any(type(v) is not int or v <= 0 for v in ns.values()): raise SpecError('namespace inodes required')
    if ns['net_ns_inode'] == host_netns_inode: raise SpecError('container shares the host network namespace')
    return {**rec, 'stage': 'started_gated', 'pid': pid, 'cgroup_path': cg, **ns, 'gate_released': False}


def absence_verdict(rec):
    """All five required; Docker removal alone is never accepted. Missing evidence is UNVERIFIED, any False is PRESENT."""
    keys = ('inspect_not_found', 'cgroup_unpopulated_or_gone', 'ns_members_empty', 'handles_absent', 'leader_reaped')
    if not isinstance(rec, dict): return 'UNVERIFIED'
    vals = [rec.get(k) for k in keys]
    if any(v is False for v in vals): return 'PRESENT'
    if all(v is True for v in vals): return 'VERIFIED_ABSENT_RECORD'
    return 'UNVERIFIED'
