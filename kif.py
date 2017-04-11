#!/usr/bin/env python
# KIF: Kill It with Fire (or a depressed space alien)
# Requires: python-psutil, python-yaml

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

mb = (2 ** 20)
gb = (2 ** 30)

me = socket.gethostname()


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

# getprocs: hackish way of getting all running commands and their PIDs
def getprocs():
    procs = {}
    for dirname in os.listdir('/proc'):
        try:
            pid = int(dirname)
            with open('/proc/%u/cmdline' % pid, mode='rb') as fd:
                content = fd.read().decode().split('\x00')
                if len(content) > 0 and len(content[0]) > 0:
                    content = [c for c in content if len(c) > 0]
                    procs[pid] = content
        except Exception:
            continue
    return procs

config = yaml.load(open("kif.yaml"))

def checkTriggers(id, alist, triggers):
    for trigger, value in triggers.iteritems():
        print("Checking against trigger %s" % trigger)
        
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
            lstr = "Process '%s' is using %u%s memory, max allowed is %u%s" % (id, cmem+0.5, cvar, maxmem+0.5, cvar)
            print(lstr)
            if cmem > maxmem:
                print("Trigger fired!")
                return lstr
                
        # maxfds: maximum number of file descriptors
        if trigger == 'maxfds':
            maxfds = int(value)
            cfds = alist['fds']
            lstr = "Process '%s' is using %u FDs, max allowed is %u" % (id, cfds,value)
            print(lstr)
            if cfds > maxfds:
                print("Trigger fired!")
                return lstr
                
        # maxconns: maximum number of open connections
        if trigger == 'maxconns':
            maxconns = int(value)
            ccons = alist['connections']
            lstr = "Process '%s' is using %u connections, max allowed is %u" % (id, ccons,value)
            print(lstr)
            if ccons > maxconns:
                print("Trigger fired!")
                return lstr
                
        # maxlocalconns: maximum number of open connections in local network
        if trigger == 'maxlocalconns':
            maxconns = int(value)
            ccons = alist['connections_local']
            lstr ="Process '%s' is using %u LAN connections, max allowed is %u" % (id, ccons,value)
            print(lstr)
            if ccons > maxconns:
                print("Trigger fired!")
                return lstr
    return None

def scanForTriggers():
    procs = getprocs() # get all current processes
    runlist = set()
    errs = []
    if 'rules' in config:
        
        # For each rule..
        for id, rule in config['rules'].iteritems():
            print("Running rule %s" % id)
            # Is this process running here?
            pids = []
            procid = rule['procid']
            
            print("Checking for process %s" % procid)
            for xpid, cmdline in procs.iteritems():
                if isinstance(procid, str):
                    if " ".join(cmdline).find(rule['procid']) != -1:
                        pids.append(xpid)
                elif isinstance(procid, list):
                    if cmdline == procid:
                        pids.append(xpid)
                        
            # If proc is running, analyze it
            analysis = {}
            for pid in pids:
                proca = {}
                print("Found process at PID %u" % pid)
                
                # Get all relevant data from this PID
                proca['memory_pct'] = getmempct(pid)
                proca['memory_bytes'] = getmem(pid)
                proca['fds'] = getfds(pid)
                proca['connections'] = getcons(pid)
                proca['connections_local'] = getcons(pid, True)
                
                # If combining, combine into the analysis hash
                if 'combine' in rule and rule['combine'] == True:
                    for k, v in proca.iteritems():
                        if not k in analysis:
                            analysis[k] = 0
                        analysis[k] += v
                else:
                    # If running a per-pid test, run it:
                    err = checkTriggers(id, proca, rule['triggers'])
                    if err:
                        runlist.update(set(rule['runlist']))
                        errs.append(err)
            if len(pids) > 0:
                # If combined trigger test, run it now
                if 'combine' in rule and rule['combine'] == True:
                    err = checkTriggers(id, analysis, rule['triggers'])
                    if err:
                        runlist.update(set(rule['runlist']))
                        errs.append(err)
            else:
                print("No matching processes found")
    return errs, runlist


# Get args, if any
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", help="Debug run (don't execute runlists)", action = 'store_true')
args = parser.parse_args()

# Now actually run things
err, runlist = scanForTriggers()
if len(runlist) > 0:
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
