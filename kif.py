#!/usr/bin/env python
# KIF: Kill It with Fire (or a depressed space alien)
# Requires: python-psutil, python-yaml

# Initial module imports
from __future__ import print_function
import os
import sys
import psutil
import yaml
import re
import subprocess
import argparse
import socket
import smtplib
import email.mime.text
import requests
import time
import logging
import atexit
import signal

# define a megabyte and gigabyte
mb = (2 ** 20)
gb = (2 ** 30)

# hostname, pid file etc
me = socket.gethostname()
pidfile = "/var/run/kif.pid"
config = None

# Miscellaneous auxiliary functions
def notifyEmail(fro, to, subject, msg):
    msg = email.mime.text.MIMEText(msg, _charset = "utf-8")
    msg['Subject'] = subject
    msg['To'] = to
    msg['From'] = fro
    s = smtplib.SMTP('localhost')
    s.sendmail(fro, to, msg.as_string())

def notifyHipchat(room, token, msg):
    payload = {
            'room_id': room,
            'auth_token': token,
            'from': "Kif",
            'message_format': 'html',
            'notify': '0',
            'color':'yellow',
            'message': msg
        }
    requests.post('https://api.hipchat.com/v1/rooms/message', data = payload)


def getmem(pid):
    proc = psutil.Process(pid)
    mem = proc.memory_info().rss
    return mem

def getmempct(pid):
    proc = psutil.Process(pid)
    mem = proc.memory_percent()
    return mem

def getfds(pid):
    proc = psutil.Process(pid)
    return proc.num_fds()

def getuser(pid):
    proc = psutil.Process(pid)
    return proc.username()

def getage(pid):
    proc = psutil.Process(pid)
    return proc.create_time()

def getstate(pid):
    proc = psutil.Process(pid)
    return proc.status()

def getcons(pid, lan = False):
    proc = psutil.Process(pid)
    if not lan:
        return len(proc.connections())
    else:
        lancons = 0
        for connection in proc.connections():
            if len(connection.raddr) > 0 and connection.raddr[0]:
                if re.match(r"^(10|192|127)\.", connection.raddr[0]) or connection.raddr[0] == '::1':
                    lancons += 1
        return lancons

# getprocs: Get all processes and their command line stack
def getprocs():
    procs = {}
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            content = p.cmdline()
            if len(content) > 0 and len(content[0]) > 0:
                content = [c for c in content if len(c) > 0]
                procs[pid] = content
        except Exception:
            continue
    return procs



def checkTriggers(id, alist, triggers):
    if len(triggers) > 0:
        print("  - Checking triggers:")
    for trigger, value in triggers.items():
        print("    - Checking against trigger %s" % trigger)

        # maxmemory: Process can max use N amount of memory or it triggers
        if trigger == 'maxmemory':
            if value.find("%") != -1: # percentage check
                maxmem = float(value.replace('%',''))
                cmem = alist['memory_pct']
                cvar = '%'
            elif value.find('mb') != -1:    # mb check
                maxmem = int(value.replace('mb','')) * mb
                cmem = alist['memory_bytes']
                cvar = ' bytes'
            elif value.find('gb') != -1:    # gb check
                maxmem = int(value.replace('gb','')) * gb
                cmem = alist['memory_bytes']
                cvar = ' bytes'
            lstr = "      - Process '%s' is using %u%s memory, max allowed is %u%s" % (id, cmem+0.5, cvar, maxmem+0.5, cvar)
            print(lstr)
            if cmem > maxmem:
                print("    - Trigger fired!")
                return lstr

        # maxfds: maximum number of file descriptors
        if trigger == 'maxfds':
            maxfds = int(value)
            cfds = alist['fds']
            lstr = "      - Process '%s' is using %u FDs, max allowed is %u" % (id, cfds, value)
            print(lstr)
            if cfds > maxfds:
                print("    - Trigger fired!")
                return lstr

        # maxconns: maximum number of open connections
        if trigger == 'maxconns':
            maxconns = int(value)
            ccons = alist['connections']
            lstr = "      - Process '%s' is using %u connections, max allowed is %u" % (id, ccons, value)
            print(lstr)
            if ccons > maxconns:
                print("    - Trigger fired!")
                return lstr

        # maxlocalconns: maximum number of open connections in local network
        if trigger == 'maxlocalconns':
            maxconns = int(value)
            ccons = alist['connections_local']
            lstr ="      - Process '%s' is using %u LAN connections, max allowed is %u" % (id, ccons, value)
            print(lstr)
            if ccons > maxconns:
                print("    - Trigger fired!")
                return lstr
            
        # maxage: maximum age of a process (NOT cpu time)
        if trigger == 'maxage':
            if value.find('s') != -1:    # seconds
                maxage = int(value.replace('s',''))
                cage = alist['process_age']
                cvar = ' seconds'
            elif value.find('m') != -1:    # minutes
                maxage = int(value.replace('m','')) * 60
                cage = alist['process_age']
                cvar = ' minutes'
            elif value.find('h') != -1:    # hours
                maxage = int(value.replace('h','')) * 360
                cage = alist['process_age']
                cvar = ' hours'
            elif value.find('d') != -1:    # days
                maxage = int(value.replace('d','')) * 86400
                cage = alist['process_age']
                cvar = ' days'
            else:
                maxage = int(value)
                cage = alist['process_age']
            lstr ="Process '%s' is %u seconds old, max allowed is %u" % (id, cage,maxage)
            print(lstr)
            if cage > maxage:
                print("Trigger fired!")
                return lstr
        
        # state: kill processes in a specific state (zombie etc)
        if trigger == 'state':
            cstate = alist['process_state']
            lstr ="Process '%s' is in state '%s'" % (id, cstate)
            print(lstr)
            if cstate == value:
                print("Trigger fired!")
                return lstr
    return None

def scanForTriggers():
    procs = getprocs() # get all current processes
    runlist = set()
    killlist = {}
    errs = []
    if 'rules' in config:

        # For each rule..
        for id, rule in config['rules'].items():
            print("- Running rule %s" % id)
            # Is this process running here?
            pids = []
            if 'procid' in rule:
                procid = rule['procid']
                print("  - Checking for process %s" % procid)
                for xpid, cmdline in procs.items():
                    addit = False
                    if isinstance(procid, str):
                        if " ".join(cmdline).find(rule['procid']) != -1:
                            addit = True
                    elif isinstance(procid, list):
                        if cmdline == procid:
                            addit = True
                    if addit:
                        if not ('ignore' in rule):
                            addit = True
                        elif isinstance(rule['ignore'], str) and " ".join(cmdline) != rule['ignore']:
                            addit = True
                        elif isinstance(rule['ignore'], list) and cmdline != rule['ignore']:
                            addit = True
                        if 'ignorepidfile' in rule:
                            try:
                                ppid = int(open(rule['ignorepidfile']).read())
                                if ppid == xpid:
                                    print("Ignoring %u, matches pid file %s!" % (ppid, rule['ignorepidfile']))
                                    addit = False
                            except Exception as err:
                                print(err)
                        if addit:
                            pids.append(xpid)
            if 'uid' in rule:
                for xpid, cmdline in procs.items():
                    uid = getuser(xpid)
                    if uid == rule['uid']:
                        addit = False
                        if not ('ignore' in rule):
                            addit = True
                        elif isinstance(rule['ignore'], str) and " ".join(cmdline) != rule['ignore']:
                            addit = True
                        elif isinstance(rule['ignore'], list) and cmdline != rule['ignore']:
                            addit = True
                        if 'ignorepidfile' in rule:
                            try:
                                ppid = int(open(rule['ignorepidfile']).read())
                                if ppid == xpid:
                                    print("Ignoring %u, matches pid file %s!" % (ppid, rule['ignorepidfile']))
                                    addit = False
                            except Exception as err:
                                print(err)
                        if addit:
                            pids.append(xpid)

            # If proc is running, analyze it
            analysis = {}
            for pid in pids:
                proca = {}
                print("  - Found process at PID %u" % pid)

                # Get all relevant data from this PID
                proca['memory_pct'] = getmempct(pid)
                proca['memory_bytes'] = getmem(pid)
                proca['fds'] = getfds(pid)
                proca['connections'] = getcons(pid)
                proca['connections_local'] = getcons(pid, True)
                proca['process_age'] = time.time() - getage(pid)
                proca['process_state'] = getstate(pid)

                # If combining, combine into the analysis hash
                if 'combine' in rule and rule['combine'] == True:
                    for k, v in proca.items():
                        if not k in analysis and ( isinstance(v, int) or isinstance(v, float) ):
                            analysis[k] = 0
                        if ( isinstance(v, int) or isinstance(v, float) ):
                            analysis[k] += v
                        else:
                            analysis[k] = ''
                else:
                    # If running a per-pid test, run it:
                    err = checkTriggers(id, proca, rule['triggers'])
                    if err:
                        if 'runlist' in rule and len(rule['runlist']) > 0:
                            runlist.update(set(rule['runlist']))
                        if 'kill' in rule and rule['kill'] == True:
                            sig = 9
                            if 'killwith' in rule:
                                sig = int(rule['killwith'])
                            killlist[pid] = sig
                        errs.append(err)
            if len(pids) > 0:
                # If combined trigger test, run it now
                if 'combine' in rule and rule['combine'] == True:
                    err = checkTriggers(id, analysis, rule['triggers'])
                    if err:
                        if 'runlist' in rule and len(rule['runlist']) > 0:
                            runlist.update(set(rule['runlist']))
                        if 'kill' in rule and rule['kill'] == True:
                            sig = 9
                            if 'killwith' in rule:
                                sig = int(rule['killwith'])
                            for ypid in pids:
                                killlist[pid] = sig
                        errs.append(err)
            else:
                print("  - No matching processes found")
    return errs, runlist, killlist


# Get args, if any
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="Debug run (don't execute runlists)", action = 'store_true')
parser.add_argument("-D", "--daemonize", help="Daemonize Kif", action = 'store_true')
parser.add_argument("-s", "--stop", help="Stop the Kif daemon", action = 'store_true')
parser.add_argument("-r", "--restart", help="Restart the Kif daemon", action = 'store_true')
parser.add_argument("-c", "--config", help="Path to the config file if not in ./kif.yaml")
args = parser.parse_args()

if not args.config:
    config = yaml.load(open("kif.yaml"))
else:
    config = yaml.load(open(args.config))

def main():
    global config
    # Now actually run things
    err, runlist, killlist = scanForTriggers()
    if len(runlist) > 0 or len(killlist) > 0:
        goods = 0
        bads = 0

        msgerr = ""
        msgrl = ""
        if len(err) > 0:
            print("Following triggers were detected:")
            for item in err:
                print("- %s" % item)
                msgerr += "- %s\n" % item
        print("Running triggered commands:")
        for item in runlist:
            print("- %s" % item)
            msgrl += "- %s" % item
            try:
                if not args.debug:
                    subprocess.check_output(item, shell = True, stderr=subprocess.STDOUT)
                    msgrl += "(<kbd>success</kbd>)"
                else:
                    print("(disabled due to --debug flag)")
                    msgrl += "(disabled due to --debug)"
                goods += 1
            except subprocess.CalledProcessError as e:
                print("command failed: %s" % e.output)
                msgrl += "(failed!: <kbd>%s</kbd>)" % e.output
                bads += 1
            msgrl += "\n"
        for pid, sig in killlist.items():
            print("- KILL PID %u with sig %u" % (pid, sig))
            msgrl += "- KILL PID %u with sig %u" % (pid, sig)
            if not args.debug:
                os.kill(pid, sig)
            else:
                print(" (disabled due to --debug flag)")
                msgrl += " (disabled due to --debug flag)"
            msgrl += "\n"
            goods += 1
        print("%u calls succeeded, %u failed." % (goods, bads))

        if 'notifications' in config and 'email' in config['notifications']:
            ecfg = config['notifications']['email']
            if 'rcpt' in ecfg and 'from' in ecfg:
                subject = "[KIF] %s: triggered %u events" % (me, len(runlist))
                msg = """Hullo there,

    KIF has detectect the following issues on %s:

    %s

    As a precaution, the following commands were run to fix issues:

    %s

    With regards and sighs,
    Your loyal KIF service.
                """ % (me, msgerr, msgrl)
                notifyEmail(ecfg['from'], ecfg['rcpt'], subject, msg)
        if 'notifications' in config and 'hipchat' in config['notifications']:
            hcfg = config['notifications']['hipchat']
            if 'token' in hcfg and 'room' in hcfg:
                msg = """KIF has detectect the following issues on %s:<br/>
    <pre>
    %s
    </pre><br/>
    As a precaution, the following commands were run to fix issues:<br/>
    <pre>
    %s
    </pre><br/>
    With regards and sighs,<br/>
    Your loyal KIF service.
                """ % (me, msgerr, msgrl)
                notifyHipchat(hcfg['room'], hcfg['token'], msg)

    print("KIF run finished!")

class Daemonize:
    """A generic daemon class.

    Usage: subclass the daemon class and override the run() method."""

    def __init__(self, pidfile): self.pidfile = pidfile

    def daemonize(self):
        """Deamonize class. UNIX double fork mechanism."""

        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #1 failed: {0}\n'.format(err))
            sys.exit(1)

        # decouple from parent environment
        os.chdir('/')
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:

                # exit from second parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #2 failed: {0}\n'.format(err))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)

        pid = str(os.getpid())
        with open(self.pidfile,'w+') as f:
            f.write(pid + '\n')

    def delpid(self):
        os.remove(self.pidfile)

    def start(self, args):
        """Start the daemon."""

        # Check for a pidfile to see if the daemon already runs
        try:
            with open(self.pidfile,'r') as pf:

                pid = int(pf.read().strip())
        except IOError:
            pid = None
        if pid:
            message = "pidfile {0} already exist. " + \
                            "Daemon already running?\n"
            sys.stderr.write(message.format(self.pidfile))
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run(args)

    def stop(self):
        """Stop the daemon."""

        # Get the pid from the pidfile
        try:
            with open(self.pidfile,'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        if not pid:
            message = "pidfile {0} does not exist. " + \
                            "Daemon not running?\n"
            sys.stderr.write(message.format(self.pidfile))
            return # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print (str(err.args))
                sys.exit(1)

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def run(self):
        """You should override this method when you subclass Daemon.

        It will be called after the process has been daemonized by
        start() or restart()."""

if os.getuid() != 0:
    print("Kif must be run as root!")
    sys.exit(-1)


# Overload print
try:
    import __builtin__
except ImportError:
    # Python 3
    import builtins as __builtin__

def print(*pargs, **pkwargs):
    global logging
    if args.daemonize:
        __builtin__.print(*pargs)
        logging.info(*pargs, **pkwargs)
    else:
        __builtin__.print(*pargs)

if 'logging' in config and 'logfile' in config['logging']:
    logging.basicConfig(filename=config['logging']['logfile'], format='[%(asctime)s]: %(message)s', level=logging.INFO)


## Daemon class
class MyDaemon(Daemonize):
    def run(self, args):

        interval = 300
        if 'daemon' in config and 'interval' in config['daemon']:
            interval = int(config['daemon']['interval'])
        while True:
            main()
            time.sleep(interval)

# Get started!
if args.stop:
    print("Stopping Kif")
    daemon = MyDaemon(pidfile)
    daemon.stop()
elif args.restart:
    print("Restarting Kif")
    daemon = MyDaemon(pidfile)
    daemon.restart()
else:
    if args.daemonize:
        print("Daemonizing Kif, using %s..." % pidfile)
        daemon = MyDaemon(pidfile)
        daemon.start(args)
    else:
        main()
