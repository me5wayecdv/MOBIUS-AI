"""HELD fixed private-namespace ADB broker operations, never host auto-connect.

This class is not a product adapter. No command runs before its source gate,
request validation and private host-namespace check. It cannot boot an emulator
or grant a caller approval. Namespace supervisor/runtime registration remains held.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tempfile
import resource

from profile import OwnedAppRequest,PACKAGE

APPROVED_FOR_EXECUTION = False
SERIAL='emulator-5554'


def validate_reverse_list(output, *, expected):
    rows=[line.split() for line in output.splitlines() if line.strip()]
    if not expected:
        if rows:raise ValueError('private reverse list must start empty')
    elif len(rows)!=1 or len(rows[0])!=3 or rows[0][0]!='(reverse)' or rows[0][1:]!=['tcp:18080','tcp:18080']:
        raise ValueError('fixed reverse pair absent or additional broker mapping')
    return rows


class FixedPrivateADB:
    def __init__(self,adb,request,*,private_home,output,host_netns):
        if not APPROVED_FOR_EXECUTION:raise RuntimeError('owned ADB scope execution HELD')
        if not isinstance(request,OwnedAppRequest):raise TypeError('typed owned APK request required')
        request.validate()
        if os.readlink('/proc/self/ns/net')==host_netns:raise RuntimeError('refuse adb on host network namespace')
        self.adb=Path(adb)
        if not self.adb.is_file() or self.adb.is_symlink():raise ValueError('verified fixed adb executable required')
        self.request=request;self.output=Path(output);self.private_home=Path(private_home)
        if not self.private_home.is_dir() or self.private_home.is_symlink():raise ValueError('private adb home required')
        self.env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(self.private_home),
            'ANDROID_USER_HOME':str(self.private_home),'ADB_SERVER_SOCKET':'tcp:127.0.0.1:5037',
            'ANDROID_SERIAL':SERIAL,'ADB_MDNS_AUTO_CONNECT':'0'}
        self.records=[]

    def command(self,args,*,timeout=5,check=True):
        # All args are fixed literals or validated nonce/owned APK path at call
        # sites below, never a remotely supplied script/URL/arbitrary adb action.
        argv=[str(self.adb),'-H','127.0.0.1','-P','5037','-s',SERIAL,*args]
        start=time.monotonic()
        def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
        with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
            result=subprocess.run(argv,env=self.env,stdin=subprocess.DEVNULL,
                stdout=stdout,stderr=stderr,close_fds=True,timeout=timeout,preexec_fn=output_limit)
            if os.fstat(stdout.fileno()).st_size+os.fstat(stderr.fileno()).st_size>65536:
                raise ValueError('ADB output bound')
            stdout.seek(0);stderr.seek(0)
            row={'argv':argv,'rc':result.returncode,'stdout':stdout.read(65537).decode(errors='replace'),
                'stderr':stderr.read(65537).decode(errors='replace'),'duration_ms':int((time.monotonic()-start)*1000)}
        self.records.append(row)
        (self.output/'adb-commands.json').write_text(json.dumps(self.records,sort_keys=True))
        if check and result.returncode:raise RuntimeError('fixed ADB action failed')
        return row['stdout']

    def verify_ready(self):
        state=self.command(['get-state']).strip()
        if state!='device':raise RuntimeError('owned emulator not ready')
        if self.command(['shell','getprop','ro.kernel.qemu']).strip()!='1':raise RuntimeError('not a verified emulator')
        if self.command(['shell','getprop','sys.boot_completed']).strip()!='1':raise RuntimeError('guest not booted')
        before=self.command(['reverse','--list'])
        validate_reverse_list(before,expected=False)
        return {'state':state,'reverse_before':before}

    def launch_owned(self,apk):
        path=Path(apk)
        if not path.is_file() or path.is_symlink() or path.stat().st_size>4*1024*1024:
            raise ValueError('bounded owned APK file required')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=self.request.apk_sha256:raise ValueError('owned APK digest mismatch')
        self.verify_ready()
        # Test-only source is explicit. -t installs this owned test APK only.
        result=self.command(['install','-t','--no-streaming',str(path)],timeout=15)
        if result.strip()!='Success':raise RuntimeError('owned APK install not successful')
        self.command(['reverse','--no-rebind','tcp:18080','tcp:18080'])
        validate_reverse_list(self.command(['reverse','--list']),expected=True)
        self.command(['shell','am','start','-W','-n',PACKAGE+'/.FixtureActivity',
            '--es','fixture_nonce',self.request.nonce,'--es','fixture_phase','prepare'],timeout=10)
        pid=self.command(['shell','pidof','-s',PACKAGE]).strip()
        if not re.fullmatch('[1-9][0-9]*',pid):raise ValueError('owned app PID absent')
        package=self.command(['shell','dumpsys','package',PACKAGE])
        # Required real UID and code path readback; do not infer from package text.
        uid=re.search(r'(?m)^\s*userId=([0-9]+)\s*$',package)
        if uid is None:raise ValueError('owned app UID evidence missing')
        proc_status=self.command(['shell','cat','/proc/'+pid+'/status'])
        proc_uid=re.search(r'(?m)^Uid:\s+([0-9]+)\s',proc_status)
        commandline=self.command(['shell','cat','/proc/'+pid+'/cmdline']).strip('\x00\r\n')
        if proc_uid is None or int(proc_uid.group(1))!=int(uid.group(1)) or commandline!=PACKAGE:
            raise ValueError('observed app process identity/UID differs')
        record={'package':PACKAGE,'pid':int(pid),'guest_uid':int(uid.group(1)),
            'observed_process_status':proc_status,'observed_process_cmdline':commandline,
            'apk_sha256':self.request.apk_sha256,'nonce':self.request.nonce,
            'app_traffic_claim':'pending_native_capture_and_app_completion_not_proved_by_launch',
            'request':asdict(self.request)}
        (self.output/'owned-app-launch.json').write_text(json.dumps(record,sort_keys=True))
        return record

    def commit_owned(self, launch):
        # No native traffic on prepare. The same observed process must still own
        # the activity before this separate fixed commit can send the one request.
        pid=self.command(['shell','pidof','-s',PACKAGE]).strip()
        if pid!=str(launch['pid']):raise RuntimeError('prepared app process changed')
        self.command(['shell','am','start','-W','-n',PACKAGE+'/.FixtureActivity',
            '--es','fixture_nonce',self.request.nonce,'--es','fixture_phase','commit'],timeout=10)

    def completion(self):
        # Filtered log is corroboration, never sufficient attribution alone.
        text=self.command(['logcat','-d','-t','100','-s','MobiusOwnedFixture:I','*:S'])
        success='OWNED_FIXTURE_REQUEST_COMPLETED nonce='+self.request.nonce
        if text.count(success)!=1 or 'OWNED_FIXTURE_FAILED' in text:raise RuntimeError('owned app did not complete exactly one request')
        return text

    def cleanup(self):
        errors=[]
        for args in (['shell','am','force-stop',PACKAGE],['reverse','--remove','tcp:18080'],['uninstall',PACKAGE]):
            try:
                self.command(args,check=False)
                if self.records[-1]['rc']!=0:errors.append({'action':args,'rc':self.records[-1]['rc']})
            except Exception as exc:errors.append({'action':args,'class':type(exc).__name__})
        try:validate_reverse_list(self.command(['reverse','--list']),expected=False)
        except Exception as exc:errors.append({'stage':'reverse_absence','class':type(exc).__name__})
        (self.output/'adb-cleanup.json').write_text(json.dumps({'errors':errors,
            'emulator_and_adb_process_teardown':'owned_namespace_supervisor_still_required'},sort_keys=True))
        if errors:raise RuntimeError('owned ADB cleanup incomplete')
