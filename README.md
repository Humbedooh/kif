# kif
### KIF: Kill It (with) Fire - A simple monitoring program with a yaml configuration

Kif is a simple monitoring program that detects programs running amok and tries to correct them.
It can currently scan for:

- Memory usage (MB, GB or % of total mem available)
- No. of open file descriptors
- No. of TCP connections open
- No. of LAN TCP connections open
- Age of process

and act accordingly, either running a custom command (such as restarting a service) or kill it with any preferred signal.

See [kif.sample.yaml](kif.sample.yaml) for example configuration.

## Requirements:
- python2.7
- python-yaml
- python-psutil

### Installation and use:
- Download Kif
- Make a kif.yaml configuration (see the example)
- Install the yaml and psutil module for python
- Run as root (required to both read usage and restart services).
- Enjoy!

### Command line arguments:

- `--debug`: Run in debug mode - detect but don't try to fix issues.
- `--daemonize`: Run as a daemonized process in the background
- `--stop`: If daemonized, stop the daemon
- `--restart`: Again, if daemon, restart it
- `--config $filename`: path to config file.


