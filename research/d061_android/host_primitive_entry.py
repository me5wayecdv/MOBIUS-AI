"""HELD entrypoint for the benign F1 + natural-F2 host primitive check. Unwired, not registered.

Permission is NOT created by any argument, environment value, repository text or workflow input.
It exists only if a reviewed commit sets APPROVED_FOR_EXECUTION True here, in host_primitive_probe
and in audience_gate. `--expected-commit` is a cross-check against the MEASURED checkout HEAD, never a grant.

Measured here, then placed in the envelope by this module (never taken from arguments):
  source_commit  git HEAD of a clean checkout (fixed /usr/bin/git, empty environment)
  runner_image   ImageOS/ImageVersion labels observed in the environment (a label, not an attestation)
Sleep identity is verified by RealOps against the supplied sha256 (same-fd pre-hash).

Output: ONE private local file via audience_gate.publish_private, under $RUNNER_TEMP only. That file
disappears with the VM, so it is NOT a retained or retrievable route. Nothing is printed. The process
exit code (0 all checks ok, 1 a check failed, 2 refused or setup error, 3 publish failed) and the job
conclusion are the only other signals, and any retained location of them is a separate disclosure
decision. There is no public fallback: if publication fails the result is dropped.

Claims: no intentional workload network (child env is empty, probe makes no connection). That is
NOT network isolation. Cleanup in the probe is live-owner cleanup only; failure stays False/UNVERIFIED.
Provider decommissioning after the job is the independent fallback, with no attested timing.
"""
import argparse,os,re,subprocess,sys

APPROVED_FOR_EXECUTION=False
GIT='/usr/bin/git'
RC_OK,RC_CHECK_FAILED,RC_REFUSED,RC_PUBLISH_FAILED=0,1,2,3


class Refused(Exception):pass


def measure_commit(repo,*,git=GIT,runner=subprocess.run):
    def g(*a):
        r=runner([git,'-C',repo]+list(a),env={},capture_output=True,timeout=20,check=False)
        if r.returncode!=0:raise Refused('git measurement failed')
        return r.stdout.decode('ascii','replace').strip()
    head=g('rev-parse','HEAD')
    if not re.fullmatch('[0-9a-f]{40}',head):raise Refused('measured HEAD is not a 40-hex commit')
    if g('status','--porcelain','--untracked-files=all')!='':raise Refused('checkout is not clean')
    return head


def measure_runner_image(environ):
    os_,ver=environ.get('ImageOS',''),environ.get('ImageVersion','')
    lab=r'[A-Za-z0-9._-]{1,40}'
    if not (re.fullmatch(lab,os_) and re.fullmatch(lab,ver)):raise Refused('runner image labels not observed')
    return '%s/%s'%(os_,ver)


def parse(argv):
    class Quiet(argparse.ArgumentParser):
        def error(self,message):raise Refused('closed arguments required')   # no usage text to stderr/logs
    ap=Quiet(add_help=False,allow_abbrev=False)
    for a in ('expected-commit','sleep-path','sleep-sha256','parent','dest','run-id','route-evidence-ref','repo'):ap.add_argument('--'+a,required=True)
    return ap.parse_args(argv)


def main(argv=None,*,environ=None,modules=None,measure=None):
    """Returns an exit code; never prints. `modules`/`measure` are injection points for tests only."""
    environ=os.environ if environ is None else environ
    import host_primitive_probe as hp,audience_gate as ag
    hp=(modules or {}).get('hp',hp);ag=(modules or {}).get('ag',ag)
    ops=None
    try:
        if not (APPROVED_FOR_EXECUTION is True and hp.APPROVED_FOR_EXECUTION is True and ag.APPROVED_FOR_EXECUTION is True):raise Refused('held')
        a=parse(sys.argv[1:] if argv is None else argv)
        if not re.fullmatch('[0-9a-f]{40}',a.expected_commit):raise Refused('expected commit must be 40-hex')
        head=(measure or measure_commit)(a.repo)
        if head!=a.expected_commit:raise Refused('measured commit differs from expected')
        image=measure_runner_image(environ)
        tmp=environ.get('RUNNER_TEMP','')
        dest=ag.canonical_path(a.dest)
        if not tmp or ag.canonical_path(tmp)!=tmp or not (dest==tmp or dest.startswith(tmp+'/')):raise Refused('output must be under RUNNER_TEMP')
        plan={'route':'local_private_file','destination':dest,'content_class':'host_primitive_result','declared_retention_days':1,'route_evidence_ref':a.route_evidence_ref}
        ag.check_plan(plan)
        env=hp.envelope(a.run_id,head,a.sleep_sha256,image)
        ops=hp.RealOps(a.parent,a.sleep_path,a.sleep_sha256)
    except Refused:return RC_REFUSED
    except Exception:
        if ops is not None:
            try:ops.close()
            except Exception:pass
        return RC_REFUSED
    try:
        result=hp.run(ops,env)
    except BaseException:
        return RC_CHECK_FAILED
    finally:
        try:ops.close()
        except Exception:pass
    try:
        ag.publish_private(plan,'host-primitive-%s.json'%a.run_id,result)
    except Exception:
        return RC_PUBLISH_FAILED
    return RC_OK if all(r['ok'] for r in result['results']) else RC_CHECK_FAILED


if __name__=='__main__':
    sys.exit(main())
