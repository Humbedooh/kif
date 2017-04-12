# KIF: Kill It (with) Fire
## A simple find-and-fix program with a yaml configuration

Kif is a simple monitoring program that detects programs running amok
and tries to correct them. It can currently scan for:

- Memory usage (MB, GB or % of total mem available)
- No. of open file descriptors
- No. of TCP connections open
- No. of LAN TCP connections open
- Age of process
- State of process (running, waiting, zombie etc)

and act accordingly, either running a custom command (such as restarting
a service) or killing it with any preferred signal. It can also notify
you of issues found and actions taken, either via email or hipchat.

See [kif.sample.yaml](kif.sample.yaml) for example configuration and
features.

### Requirements:
- python 2.7+ (3.x will work)
- python-yaml
- python-psutil

### Installation and use:
- Download Kif
- Make a kif.yaml configuration (see the [example](kif.sample.yaml))
- Install the yaml and psutil module for python (either via package manager or pip)
- Run as root (required to both read usage and restart services).
- Enjoy!

### Rule syntax:

```yaml
rules:
    apache:
        description:     'sample apache process rule'
        # We can specify the exact cmdline and args to scan for:
        procid: 
            - '/usr/sbin/apache2'
            - '-k'
            - 'start'
        # We'll use combine: true to combine the resource of multiple processes into one check.
        combine:            true
        triggers:
            # Demand no more than 500 LAN connections
            maxlocalconns:  500
            # Require < 1GB memory used (could also be 10%, 512mb etc)
            maxmemory:      1gb
        # If triggered, run this:
        runlist:
            - 'service apache2 restart'
            
    zombies:
        description:    'Any process caught in zombie mode'
        # use empty procid to catch all
        procid:         ''
        triggers:
            # This can be any process state (zombie, sleeping, running, etc)
            state:      'zombie'
        # No runlist here, just kill it with signal 9
        kill:           true
        killwith:       9
```

### Command line arguments:

- `--debug`: Run in debug mode - detect but don't try to fix issues.
- `--daemonize`: Run as a daemonized process in the background
- `--stop`: If daemonized, stop the daemon
- `--restart`: Again, if daemon, restart it
- `--config $filename`: path to config file.


