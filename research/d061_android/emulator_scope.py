"""HELD fixed emulator/private-ADB infrastructure lifecycle source.

No APK, app launch, proxy/origin or model request occurs here. Only a future
reviewed no-uplink child may instantiate this class after runtime closure review.
Options are documentation-grounded candidates, NOT pinned-binary compatibility
results. Unexpected listeners, including gRPC, refuse readiness.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

APPROVED_FOR_EXECUTION = False
SDK=Path('/opt/android')
IMAGE=SDK/'system-images/android-29/default/x86_64'


def process_identity(pid):
    text=Path('/proc/'+str(pid)+'/stat').read_text()
    return {'pid':pid,'starttime':text[text.rindex(')')+2:].split()[19],
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def validate_listeners(rows,*,proxy_origin_ready=False):
    expected={5037,5554,5555}|({18080,18443} if proxy_origin_ready else set())
    observed=set()
    for row in rows:
        if row['state']!='0A':continue
        if row['family']=='tcp':
            if row['address']!='0100007F':raise ValueError('non-loopback TCP listener')
        elif row['family']=='tcp6':
            if row['address']!='00000000000000000000000001000000':raise ValueError('non-loopback TCP6 listener')
        else:raise ValueError('unexpected listener family')
        if row['port'] not in expected:raise ValueError('unexpected listener, no implicit gRPC grant')
        observed.add(row['port'])
    if observed!=expected:raise ValueError('required private broker/console listeners missing')
    return True


def socket_rows():
    rows=[]
    for name in ('tcp','tcp6'):
        for line in Path('/proc/net/'+name).read_text().splitlines()[1:]:
            fields=line.split();address,port=fields[1].split(':')
            rows.append({'family':name,'address':address,'port':int(port,16),
                'state':fields[3],'uid':int(fields[7]),'inode':fields[9]})
    return rows


def validate_no_udp_broker():
    # The closed fixture needs no host-side UDP service. Guest background traffic
    # may produce connected UDP sockets, but unconnected/wildcard UDP bindings
    # are not silently admitted as emulator infrastructure.
    records=[]
    for family in ('udp','udp6'):
        for line in Path('/proc/net/'+family).read_text().splitlines()[1:]:
            fields=line.split()
            record={'family':family,'local':fields[1],'remote':fields[2],'state':fields[3]}
            records.append(record)
            if int(fields[2].split(':')[1],16)==0:
                raise ValueError('unexpected unconnected UDP binding')
    return records


class PrivateEmulator:
    def __init__(self,output,*,host_netns):
        if not APPROVED_FOR_EXECUTION:raise RuntimeError('emulator lifecycle HELD')
        if os.geteuid()==0 or os.readlink('/proc/self/ns/net')==host_netns:
            raise RuntimeError('unprivileged fresh no-uplink child required')
        self.output=Path(output);self.processes=[];self.records=[];self.log_sinks=[]
        self.home=Path('/home/fixture');self.avd=self.home/'owned.avd'
        if self.avd.exists():raise ValueError('fresh private AVD required')
        self.avd.mkdir(mode=0o700)
        self.env={'PATH':str(SDK/'platform-tools')+':/runtime/bin:/usr/bin:/bin',
            'HOME':str(self.home),'ANDROID_USER_HOME':str(self.home),
            'ANDROID_AVD_HOME':str(self.home),'TMPDIR':'/tmp','LANG':'C.UTF-8',
            'ANDROID_SDK_ROOT':str(SDK),'ADB_SERVER_SOCKET':'tcp:127.0.0.1:5037',
            'ADB_MDNS_AUTO_CONNECT':'0','QT_QPA_PLATFORM':'offscreen'}

    def record(self):
        (self.output/'emulator-processes.json').write_text(json.dumps(self.records,sort_keys=True))

    def start(self,argv,name):
        log=(self.output/(name+'.log')).open('xb')
        try:
            child=subprocess.Popen(list(map(str,argv)),env=self.env,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
        except BaseException:
            log.close();raise
        os.set_blocking(child.stdout.fileno(),False)
        self.log_sinks.append({'name':name,'child':child,'log':log,'bytes':0})
        self.processes.append((name,child));self.records.append(dict(process_identity(child.pid),name=name,argv=list(map(str,argv))))
        self.record();return child

    def drain_logs(self):
        # No background reader and no unbounded capture_output allocation. A
        # full pipe stalls its producer until the fixed driver pumps it. Raw
        # logs stop at64KiB per process, fail rather than silently drop bytes.
        for sink in self.log_sinks:
            while True:
                try:data=os.read(sink['child'].stdout.fileno(),4096)
                except BlockingIOError:break
                if not data:break
                left=65536-sink['bytes']
                sink['log'].write(data[:left]);sink['bytes']+=min(left,len(data));sink['log'].flush()
                if len(data)>left:raise RuntimeError('infrastructure log output exceeded fixed ceiling')

    def boot(self,adb,*,seconds=120):
        if seconds!=120:raise ValueError('fixed separate boot ceiling')
        # Config is fixture-owned. No avdmanager/Gradle/SDK-manager call, downloads,
        # snapshots, imported AVD/userdata, broad host home or host USB devices.
        config={'AvdId':'owned','avd.ini.displayname':'Owned Offline Fixture',
            'abi.type':'x86_64','hw.cpu.arch':'x86_64','hw.cpu.ncore':'2',
            'hw.ramSize':'2048','hw.lcd.width':'480','hw.lcd.height':'800',
            'hw.lcd.density':'160','hw.gpu.enabled':'yes','hw.gpu.mode':'swiftshader_indirect',
            'hw.audioInput':'no','hw.audioOutput':'no','hw.camera.back':'none','hw.camera.front':'none',
            'hw.keyboard':'no','hw.sdCard':'no','disk.dataPartition.size':'1536M',
            'image.sysdir.1':str(IMAGE),'tag.id':'default','PlayStore.enabled':'false',
            'fastboot.forceColdBoot':'yes','fastboot.forceFastBoot':'no'}
        (self.home/'owned.ini').write_text('avd.ini.encoding=UTF-8\npath='+str(self.avd)+'\ntarget=android-29\n')
        (self.avd/'config.ini').write_text(''.join(k+'='+v+'\n' for k,v in sorted(config.items())))
        (self.output/'avd-config.json').write_text(json.dumps(config,sort_keys=True))
        deadline=time.monotonic()+seconds
        server=self.start([SDK/'platform-tools/adb','-L','tcp:127.0.0.1:5037','server','nodaemon'],'adb-server')
        emulator=self.start([SDK/'emulator/emulator','-avd','owned','-sysdir',IMAGE,
            '-datadir',self.avd,'-ports','5554,5555','-no-window','-no-audio','-no-boot-anim',
            '-camera-back','none','-camera-front','none','-gpu','swiftshader_indirect',
            '-accel','on','-no-snapshot','-wipe-data'],'emulator')
        last_error=None
        while time.monotonic()<deadline:
            self.drain_logs()
            if server.poll() is not None or emulator.poll() is not None:
                raise RuntimeError('private infrastructure exited before boot readiness')
            try:
                ready=adb.verify_ready()
                rows=socket_rows();validate_listeners(rows)
                udp_rows=validate_no_udp_broker()
                record={'boot_state':ready,'socket_rows':rows,'identities':self.records,
                    'namespace':os.readlink('/proc/self/ns/net'),'udp_socket_rows':udp_rows,'actual_apk_launched':False,
                    'actual_network_experiment_executed':False}
                (self.output/'emulator-readiness.json').write_text(json.dumps(record,sort_keys=True))
                return record
            except (RuntimeError,ValueError,subprocess.TimeoutExpired) as error:last_error=type(error).__name__
            time.sleep(0.25)
        raise TimeoutError('fixed boot ceiling reached; last_state='+str(last_error))

    def cleanup(self):
        errors=[];states=[]
        for name,child in reversed(self.processes):
            try:
                if child.poll() is None:
                    # Child handle is our direct unreaped process. Never signal a
                    # numeric PID discovered by name/prefix or imported record.
                    os.killpg(child.pid,signal.SIGTERM)
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
                states.append({'name':name,'rc':child.returncode,'leader_reaped':True})
            except BaseException as error:errors.append({'stage':name,'class':type(error).__name__})
        try:self.drain_logs()
        except BaseException as error:errors.append({'stage':'log_drain','class':type(error).__name__})
        for sink in self.log_sinks:
            sink['log'].close();sink['child'].stdout.close()
        record={'complete':not errors,'errors':errors,'processes':states,
            'daemon_descendant_absence':'UNVERIFIED_REQUIRES_NAMESPACE_TEARDOWN_AND_INDEPENDENT_CHECK'}
        (self.output/'emulator-cleanup.json').write_text(json.dumps(record,sort_keys=True))
        if errors:raise RuntimeError('private emulator/ADB cleanup incomplete')
        return record
