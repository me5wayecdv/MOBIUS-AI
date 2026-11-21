"""HELD source-only Docker lifecycle adapter for the outer owner. Nothing here runs docker.

Scope: build the exact `docker create` argument vector for ONE run-bound role container and validate a
supplied `docker inspect` record against that exact spec. Predicates validate supplied records and cannot
create provenance, permission or host evidence. The Docker daemon API is host-root-level: only the trusted
outer owner may ever hold it, never a relay, runtime or control payload. No privileged mode, no host PID/net/IPC,
no docker socket in any payload, no broad mounts, no pull (image is a pinned digest that must already exist).
Compatibility choice (explicit): the inner unshare/mount namespace provisioning of namespace_supervisor is NOT run
inside the container (default seccomp/caps would block it and the only fix is privilege). Its controls are translated to
container configuration, each with a changed proof obligation listed in DOCKER_ADAPTER.md.
"""
import re

APPROVED_FOR_EXECUTION = False
ROLES = ('runtime', 'control')
DIGEST = re.compile(r'[a-z0-9][a-z0-9._/-]{0,127}@sha256:[0-9a-f]{64}')
RUN_ID = re.compile(r'[0-9a-f]{32}')
MOUNT_SRC = re.compile(r'/opt/d061-owned-android-run-[0-9a-f]{32}/(runtime|control)-work')
USER = '65534:65534'
KVM = '/dev/kvm'


class SpecError(ValueError):
    pass


def _check(role, run_id, image, mem_mb, pids, cpus, work_src):
    if role not in ROLES: raise SpecError('role')
    if not RUN_ID.fullmatch(run_id or ''): raise SpecError('run id')
    if not DIGEST.fullmatch(image or ''): raise SpecError('image must be a pinned digest')
    if type(mem_mb) is not int or not 256 <= mem_mb <= 16384: raise SpecError('memory MiB 256..16384')
    if type(pids) is not int or not 16 <= pids <= 4096: raise SpecError('pids 16..4096')
    if type(cpus) is not int or not 1 <= cpus <= 4: raise SpecError('whole cpus 1..4')
    m = MOUNT_SRC.fullmatch(work_src or '')
    if not m or m.group(1) != role or run_id not in work_src: raise SpecError('work mount must be this run and role only')


def container_name(role, run_id):
    return 'd061-%s-%s' % (role, run_id)


def create_argv(role, run_id, image, *, mem_mb, pids, cpus, work_src, docker='/usr/bin/docker'):
    """Exact argv for `docker create`. Only runtime gets /dev/kvm. Control never gets SDK/emulator/KVM."""
    _check(role, run_id, image, mem_mb, pids, cpus, work_src)
    a = [docker, 'create', '--name', container_name(role, run_id), '--pull', 'never', '--network', 'none',
         '--ipc', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only',
         '--user', USER, '--memory', '%dm' % mem_mb, '--memory-swap', '%dm' % mem_mb, '--pids-limit', str(pids),
         '--cpus', str(cpus), '--restart', 'no', '--label', 'd061.run_id=' + run_id, '--label', 'd061.role=' + role,
         '--mount', 'type=bind,src=%s,dst=/work' % work_src]
    if role == 'runtime': a += ['--device', KVM]
    return a + [image]


def validate_inspect(rec, role, run_id, image, *, mem_mb, pids, cpus, work_src):
    """Fail closed: every field must equal the exact spec. `rec` is one parsed inspect object."""
    _check(role, run_id, image, mem_mb, pids, cpus, work_src)
    try:
        h, c = rec['HostConfig'], rec['Config']
        bad = []
        def need(ok, what):
            if not ok: bad.append(what)
        need(re.fullmatch('[0-9a-f]{64}', rec.get('Id', '')) is not None, 'id')
        need(rec.get('Name') == '/' + container_name(role, run_id), 'name')
        need(h.get('NetworkMode') == 'none', 'network')
        need(h.get('Privileged') is False, 'privileged')
        need(h.get('PidMode') in ('', None), 'pidmode')
        need(h.get('IpcMode') == 'none', 'ipc')
        need(h.get('UsernsMode') in ('', None), 'userns')
        need(h.get('CapDrop') == ['ALL'] and not h.get('CapAdd'), 'caps')
        need(any(s in ('no-new-privileges', 'no-new-privileges:true') for s in (h.get('SecurityOpt') or [])), 'nnp')
        need(len(h.get('SecurityOpt') or []) == 1, 'no extra security opts')
        need(h.get('ReadonlyRootfs') is True, 'rootfs')
        need(h.get('Memory') == mem_mb * 1048576 and h.get('MemorySwap') == mem_mb * 1048576, 'memory')
        need(h.get('PidsLimit') == pids, 'pids')
        need(h.get('NanoCpus') == cpus * 10**9, 'cpus')
        need(not h.get('PortBindings') and not h.get('Links') and not h.get('VolumesFrom'), 'ports/links/volumes-from')
        need(not h.get('Binds') or h.get('Binds') == [], 'legacy binds')
        devs = [d.get('PathOnHost') for d in (h.get('Devices') or [])]
        need(devs == ([KVM] if role == 'runtime' else []), 'devices')
        need(not h.get('DeviceCgroupRules') and not h.get('Tmpfs'), 'cgroup rules/tmpfs')
        mounts = rec.get('Mounts') or []
        need(len(mounts) == 1 and mounts[0].get('Type') == 'bind' and mounts[0].get('Source') == work_src
             and mounts[0].get('Destination') == '/work', 'mounts')
        need(c.get('User') == USER, 'user')
        need(rec.get('Image', '') != '' and c.get('Image') == image, 'image')
        need(c.get('Labels', {}).get('d061.run_id') == run_id and c.get('Labels', {}).get('d061.role') == role, 'labels')
        need((rec.get('State') or {}).get('Status') == 'created', 'state not created')
    except (KeyError, TypeError, AttributeError):
        raise SpecError('inspect record malformed')
    if bad: raise SpecError('inspect differs from exact spec: ' + ','.join(bad))
    return {'validated_record_only': True, 'daemon_enforcement_verified': False}


def absence_verdict(rec):
    """Validates a supplied record: container inspect returned not-found after removal AND the role's held cgroup
    reported populated 0 or is gone. Docker removal alone is never accepted. Missing evidence is UNVERIFIED."""
    if not isinstance(rec, dict): return 'UNVERIFIED'
    a, b = rec.get('inspect_not_found'), rec.get('cgroup_unpopulated_or_gone')
    if a is True and b is True: return 'VERIFIED_ABSENT_RECORD'
    if a is False or b is False: return 'PRESENT'
    return 'UNVERIFIED'
