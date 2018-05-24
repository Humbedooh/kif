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
MB = (2 ** 20)
GB = (2 ** 30)

# hostname, pid file etc
ME = socket.gethostname()
PIDFILE = "/var/run/kif.pid"
CONFIG = None

# Miscellaneous auxiliary functions
def notifyEmail(fro, to, subject, msg):
    msg = email.mime.text.MIMEText(msg, _charset = "utf-8")
    msg['Subject'] = subject
    msg['To'] = to
    msg['From'] = fro
    s = smtplib.SMTP('localhost')
    s.sendmail(fro, to, msg.as_string())

def notifyHipchat(room, token, msg, notify = False):
    payload = {
            'room_id': room,
            'auth_token': token,
            'from': "Kif",
            'message_format': 'html',
            'notify': '1' if notify else '0',
            'color':'yellow',
            'message': msg
        }
    requests.post('https://api.hipchat.com/v1/rooms/message', data = payload)


class ProcessInfo(object):
    def __init__(self, pid=None):
        if pid is None:
            # This instance will aggregate values across multiple processes,
            # so we'll zero the numerics.
            self.mem = 0
            self.mempct = 0
            self.fds = 0
            self.age = 0
            self.state = ''  # can't aggregate state, but needs a value
            self.conns = 0
            self.conns_local = 0
            return

        proc = psutil.Process(pid)
        self.mem = proc.memory_info().rss
        self.mempct = proc.memory_percent()
        self.fds = proc.num_fds()
        self.age = time.time() - proc.create_time()
        self.state = proc.status()

        self.conns = len(proc.connections())
        self.conns_local = 0
        for connection in proc.connections():
            if connection.raddr and connection.raddr[0]:
                if RE_LOCAL_IP.match(connection.raddr[0]) \
                   or connection.raddr[0] == '::1':
                    self.conns_local += 1

RE_LOCAL_IP = re.compile(r'^(10|192|127)\.')


def getuser(pid):
    proc = psutil.Process(pid)
    return proc.username()


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



def checkTriggers(id, alist, triggers, dead = False):
    if not alist:
        print("  - No analytical data found, bailing on check!")
        return None
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
                maxmem = int(value.replace('mb','')) * MB
                cmem = alist['memory_bytes']
                cvar = ' bytes'
            elif value.find('gb') != -1:    # gb check
                maxmem = int(value.replace('gb','')) * GB
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
            lstr ="      - Process '%s' is %u seconds old, max allowed is %u" % (id, cage,maxage)
            print(lstr)
            if cage > maxage:
                print("    - Trigger fired!")
                return lstr
        
        # state: kill processes in a specific state (zombie etc)
        if trigger == 'state':
            cstate = alist['process_state']
            lstr ="      - Process '%s' is in state '%s'" % (id, cstate)
            print(lstr)
            if cstate == value:
                print("    - Trigger fired!")
                return lstr
    return None

def scanForTriggers(config):
    procs = getprocs() # get all current processes
    actions = []

    ### TODO: reindent
    if True:

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

                try:
                    # Get all relevant data from this PID
                    info = ProcessInfo(pid)
                    proca['memory_pct'] = info.mempct
                    proca['memory_bytes'] = info.mem
                    proca['fds'] = info.fds
                    proca['connections'] = info.conns
                    proca['connections_local'] = info.conns_local
                    proca['process_age'] = info.age
                    proca['process_state'] = info.state
    
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
                            action = {
                                'pids': [],
                                'trigger': "",
                                'runlist': [],
                                'notify': rule.get('notify', None),
                                'kills': {}
                            }
                            if 'runlist' in rule and len(rule['runlist']) > 0:
                                action['runlist'] = rule['runlist']
                            if 'kill' in rule and rule['kill'] == True:
                                sig = 9
                                if 'killwith' in rule:
                                    sig = int(rule['killwith'])
                                action['kills'][pid] = sig
                            action['trigger'] = err
                            actions.append(action)
                except:
                    print("Could not analyze proc %u, bailing!" % pid)
                    continue
            if len(pids) > 0:
                # If combined trigger test, run it now
                if 'combine' in rule and rule['combine'] == True:
                    err = checkTriggers(id, analysis, rule['triggers'])
                    if err:
                        action = {
                            'pids': [],
                            'trigger': "",
                            'runlist': [],
                            'notify': rule.get('notify', None),
                            'kills': {}
                        }
                        if 'runlist' in rule and len(rule['runlist']) > 0:
                            action['runlist'] = rule['runlist']
                        if 'kill' in rule and rule['kill'] == True:
                            sig = 9
                            if 'killwith' in rule:
                                sig = int(rule['killwith'])
                            for ypid in pids:
                                action['kills'][ypid] = sig
                        action['trigger'] = err
                        actions.append(action)
            else:
                print("  - No matching processes found")
                
    return actions


# Get args, if any
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="Debug run (don't execute runlists)", action = 'store_true')
parser.add_argument("-D", "--daemonize", help="Daemonize Kif", action = 'store_true')
parser.add_argument("-F", "--foreground", help="Run Kif continuous in foreground mode", action = 'store_true')
parser.add_argument("-s", "--stop", help="Stop the Kif daemon", action = 'store_true')
parser.add_argument("-r", "--restart", help="Restart the Kif daemon", action = 'store_true')
parser.add_argument("-c", "--config", help="Path to the config file if not in ./kif.yaml")
args = parser.parse_args()

if not args.config:
    CONFIG = yaml.load(open("kif.yaml"))
else:
    CONFIG = yaml.load(open(args.config))

def main(config):
    if 'rules' not in config:
        print('- NO RULES TO CHECK')
    else:
        # Now actually run things
        actions = scanForTriggers(config)
        if actions:
            run_actions(config, actions)

    print('KIF run finished!')


def run_actions(config, actions):
        ### TODO: reindent

        goods = 0
        bads = 0
        
        for action in actions:

            print("Following triggers were detected:")
            print("- %s" % action['trigger'])
            print("Running triggered commands:")
            rloutput = ""
            for item in action['runlist']:
                print("- %s" % item)
                rloutput += "- %s" % item
                try:
                    if not args.debug:
                        subprocess.check_output(item, shell = True, stderr=subprocess.STDOUT)
                        rloutput += " (success)"
                    else:
                        print("(disabled due to --debug flag)")
                        rloutput += " (disabled due to --debug)"
                    goods += 1
                except subprocess.CalledProcessError as e:
                    print("command failed: %s" % e.output)
                    rloutput += " (failed!: %s)" % e.output
                    bads += 1
                rloutput += "\n"
            for pid, sig in action['kills'].items():
                print("- KILL PID %u with sig %u" % (pid, sig))
                rloutput += "- KILL PID %u with sig %u" % (pid, sig)
                if not args.debug:
                    os.kill(pid, sig)
                else:
                    print(" (disabled due to --debug flag)")
                    rloutput += " (disabled due to --debug flag)"
                rloutput += "\n"
                goods += 1
            print("%u calls succeeded, %u failed." % (goods, bads))
    
            if 'notifications' in config and 'email' in config['notifications'] and ('email' in (action['notify'] or "email")):
                ecfg = config['notifications']['email']
                if 'rcpt' in ecfg and 'from' in ecfg:
                    subject = "[KIF] %s: triggered %u events" % (ME, len(action['runlist']) + len(action['kills'].items()))
                    msg = TEMPLATE_EMAIL % (ME, action['trigger'], rloutput)
                    notifyEmail(ecfg['from'], ecfg['rcpt'], subject, msg)

            if 'notifications' in config and 'hipchat' in config['notifications'] and ('hipchat' in (action['notify'] or "hipchat")):
                hcfg = config['notifications']['hipchat']
                if 'token' in hcfg and 'room' in hcfg:
                    msg = TEMPLATE_HIPCHAT % (ME, action['trigger'], rloutput)
                    notifyHipchat(hcfg['room'], hcfg['token'], msg, hcfg['notify'] if 'notify' in hcfg else False)


TEMPLATE_EMAIL = """Hullo there,

KIF has detected the following issues on %s:

%s

As a precaution, the following commands were run to fix issues:

%s

With regards and sighs,
Your loyal KIF service.
"""

TEMPLATE_HIPCHAT ="""KIF has detected the following issues on %s:<br/>
<pre>
%s
</pre><br/>
As a precaution, the following commands were run to fix issues:<br/>
<pre>
%s
</pre><br/>
With regards and sighs,<br/>
Your loyal KIF service.
"""


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

if 'logging' in CONFIG and 'logfile' in CONFIG['logging']:
    logging.basicConfig(filename=CONFIG['logging']['logfile'], format='[%(asctime)s]: %(message)s', level=logging.INFO)


## Daemon class
class MyDaemon(Daemonize):
    def run(self, args):

        interval = 300
        if 'daemon' in CONFIG and 'interval' in CONFIG['daemon']:
            interval = int(CONFIG['daemon']['interval'])
        while True:
            main(CONFIG)
            time.sleep(interval)

# Get started!
if args.stop:
    print("Stopping Kif")
    daemon = MyDaemon(PIDFILE)
    daemon.stop()
elif args.restart:
    print("Restarting Kif")
    daemon = MyDaemon(PIDFILE)
    daemon.restart()
else:
    if args.daemonize:
        print("Daemonizing Kif, using %s..." % PIDFILE)
        daemon = MyDaemon(PIDFILE)
        daemon.start(args)
    elif args.foreground:
        interval = 300
        if 'daemon' in CONFIG and 'interval' in CONFIG['daemon']:
            interval = int(CONFIG['daemon']['interval'])
        while True:
            main(CONFIG)
            time.sleep(interval)
    else:
        main(CONFIG)
