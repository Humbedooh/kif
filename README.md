# kif
### KIF: Kill It (with) Fire - A simple monitoring program with a yaml configuration

Kif is a simple monitoring program that detects programs running amok and tries to correct them.
It can scan for memory usage, file descriptors and connections (both local and global) and act if they reach a certain threshold. 

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


