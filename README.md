# Norimaci

"Norimaci" is a simple and lightweight malware analysis sandbox for macOS. This tool was inspired by "[Noriben](https://github.com/Rurik/Noriben)". Norimaci uses the features of OpenBSM or Monitor.app to monitor macOS system activity instead of Sysinternals Process Monitor (procmon).

Norimaci consists of 3 Python scripts.

- norimaci.py : Main script
- openbsmconv.py : OpenBSM audit log converter
- monitorappconv.py : Monitor.app data converter

OpenBSM is a framework to audit activities on macOS. Please see [their web site](http://www.trustedbsd.org/openbsm.html) for details.

Monitor.app is a free tool which is made by FireEye. Please see [their web site](https://www.fireeye.com/services/freeware/monitor.html) for details.

## Why "Norimaci"?

My former colleague (@cci_forensics) suggested this name.

"Norimaci" is a coined word combining "Noriben" and "Macintosh". It is pronounced "Norimaki", and it represents "のり巻き" in Japanese. It means "sushi roll" in English.

Noriben is a Japanese style lunch box that consists of minimal ingredients. The ingredients of norimaki are similar to noriben (seaweed, rice, and other you prefer).

So, I decided to name this tool "Norimaci".

## Requirement

- OS X 10.6 or later (I tested on macOS 10.13 - 10.15)
- VMware Fusion, Parallels, VirtualBox, etc.
- Python 3.5 or later

### Optional requirement

- [Monitor.app](https://www.fireeye.com/services/freeware/monitor.html)

**Note that, Monitor.app supports only macOS 10.12 - 10.14. You don't have to install it, if you want to execute malware on macOS 10.15 or later. You have to use OpenBSM instead of it.**

You have to install libraries below from their source repositories or pip, if you use Norimaci with Monitor.app.

- [py-applescript](https://github.com/rdhyee/py-applescript)
- [PyObjC](https://bitbucket.org/ronaldoussoren/pyobjc)
- [dnslib](https://bitbucket.org/paulc/dnslib/)

## Preparing

### Build virtual machines to execute malware

You have to build a macOS VM to execute malware samples. In addition, it is highly recommended to build another VM for fake Internet connections. Because, many malware attempt to connect their servers (e.g. C2 servers).

PolarProxy and INetSim are very useful tools to provide fake HTTP/HTTPS and DNS services. Please refer [NETRESEC blog](https://www.netresec.com/?page=Blog&month=2019-12&post=Installing-a-Fake-Internet-with-INetSim-and-PolarProxy) to build a fake Internet.

### Edit /etc/security/audit_control

If you use OpenBSM to monitor system activities, you have to modify /etc/security/audit_control file like below.
Because, OpenBSM records audit logs about only login and authentication by default. But, Norimaci needs more kinds of audit logs (file creation, file deletion, process execution, networking, etc).

The computer has to be rebooted after the modification to apply the setting.

```
#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_control#8 $
#
dir:/var/audit
flags:lo,aa,fc,fd,pc,nt,ex      <- edit here like this
minfree:5
naflags:lo,aa,fc,fd,pc,nt,ex    <- edit here like this
policy:cnt,argv
filesz:2M
expire-after:10M
superuser-set-sflags-mask:has_authenticated,has_console_access
superuser-clear-sflags-mask:has_authenticated,has_console_access
member-set-sflags-mask:
member-clear-sflags-mask:has_authenticated
```

## Usage

### Basic usage with OpenBSM (most standard usage)

1. Run norimaci.py with sudo.
2. Run a sample of malware (You can run any type of malware. For example, DMG, PKG, Mach-O binary, and so on).
3. Wait for a while (Until, the malware can get their goal).
4. Press "Ctrl + C " at the appropriate time in the terminal where Norimaci runs in.
5. 2 kind of reports are generated (Norimaci_dd_Mon_yy__hh_mm_ffffff.txt and Norimaci_dd_Mon_yy__hh_mm_ffffff_timeline.csv).
6. Confirm reports with your favorite tools (e.g. text editors, grep, less, etc).

```bash
$ sudo python3 ./norimaci.py -m openbsm -o ./out/
Password:

--===[ Norimaci v0.1.0
--===[ Minoru Kobayashi [@unkn0wnbit]
[*] Launching OpenBSM agent...
[*] When runtime is complete, press CTRL+C to stop logging.
^C
[*] Termination of OpenBSM agent commencing... please wait
[*] Converting OpenBSM data ...
[*] Loading converted macOS activity data ...
[*] Saving report to: /Users/macforensics/tools/norimaci/out/Norimaci_14_Jan_20__15_55_093219.txt
[*] Saving timeline to: /Users/macforensics/tools/norimaci/out/Norimaci_14_Jan_20__15_55_093219_timeline.csv
```

### Basic usage with Monitor.app

Note: Monitor.app can not run on macOS 10.15. But, it works fine on macOS 10.14 or earlier.

1. Run norimaci.py with sudo.
2. Enter a password after Norimaci launches Monitor.app (Monitor.app needs a password to install its kext).
3. Run a sample of malware (You can run any type of malware. For example, DMG, PKG, Mach-O binary, and so on).
4. Wait for a while (Until, the malware can get their goal).
5. Press "Ctrl + C " at the appropriate time in the terminal where Norimaci runs in.
6. 2 kind of reports are generated (Norimaci_dd_Mon_yy__hh_mm_ffffff.txt and Norimaci_dd_Mon_yy__hh_mm_ffffff_timeline.csv).
7. Confirm reports with your favorite tools (e.g. text editors, grep, less, etc).

### Help of scripts

- norimaci.py

```bash
$ python3 ./norimaci.py -h

--===[ Norimaci v0.1.0
--===[ Minoru Kobayashi [@unkn0wnbit]
usage: norimaci.py [-h] [-m MONITOR] [-j JSON] [-bl OPENBSM_LOG] [-p PROCLIST]
                   [-ml MONITORAPP_LOG] [-o OUTPUT] [--force] [--debug]

Light weight sandbox which works with OpenBSM or Fireeye's Monitor.app

optional arguments:
  -h, --help            show this help message and exit
  -m MONITOR, --monitor MONITOR
                        Specify a program to monitor macOS activity. You can
                        choose 'openbsm' or 'monitorapp'.
  -j JSON, --json JSON  Path to a JSON file which is converted by
                        'openbsmconv.py' or 'monitorappconv.py'.
  -bl OPENBSM_LOG, --openbsm-log OPENBSM_LOG
                        Path to an OpenBSM log file.
  -p PROCLIST, --proclist PROCLIST
                        Path to a process list file to process OpenBSM log
                        file. A file which has ".proclist" extnsion would be
                        used, if this option is not specified.
  -ml MONITORAPP_LOG, --monitorapp-log MONITORAPP_LOG
                        Path to a Monitor.app data file.
  -o OUTPUT, --output OUTPUT
                        Path to an output directory.
  --force               Enable to overwrite output files.
  --debug               Enable debug mode.
```

- openbsmconv.py

```bash
$ python3 ./openbsmconv.py -h
usage: openbsmconv.py [-h] [-f FILE] [-p PROCLIST] [-o OUT] [-c] [-rp]
                      [--with-failure] [--with-failure-socket] [--force]
                      [--debug]

Converts OpenBSM log file to JSON format.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to a bsm log file
  -p PROCLIST, --proclist PROCLIST
                        Path to a process list file
  -o OUT, --out OUT     Path to an output file
  -c, --console         Output JSON data to stdout.
  -rp, --use-running-proclist
                        Use current running process list instead of a existing
                        process list file. And, the process list is saved to a
                        file which places in the same directory of '--file' or
                        to a file which specified '--proclist'.
  --with-failure        Output records which has a failure status too.
  --with-failure-socket
                        Output records which has a failure status too (related
                        socket() syscall only).
  --force               Enable to overwrite an existing output file.
  --debug               Enable debug mode.
```

- monitorappconv.py

```bash
$ python3 ./monitorappconv.py -h
usage: monitorappconv.py [-h] [-f FILE] [-o OUT] [-c] [--force] [--debug]

Parses data of Fireeye Monitor.app and converts it to JSON format. Please note
that strings in JSON data are saved as UTF-8.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to a saved data of Monitor.app.
  -o OUT, --out OUT     Path to an output file.
  -c, --console         Output JSON data to stdout.
  --force               Enable to overwrite an output file.
  --debug               Enable debug mode.
```

## Demo

Analyze AppleJeus.A on macOS 10.15 Catalina with Norimaci. This demo movie was made for Japan Security Analyst Conference 2020 (JSAC2020)

![Norimaci demo](images/JSAC2020_demo2.gif)

## Installation

```bash
git clone https://github.com/mnrkbys/norimaci.git
```

## Future Work

- [ ] YARA scanning
- [ ] VirusTotal scanning

## Author

[Minoru Kobayashi](https://twitter.com/unkn0wnbit)

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
