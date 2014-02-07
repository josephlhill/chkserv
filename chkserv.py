#!/usr/bin/python
# joeh 10/11/13 ver_1.3.

'''
hardening evaluater for IISS linux server builds
vers 1.1: code tweeks to handle rhel5 servers using ancient python 2.4 
vers 1.2 added check for vmtools
vers 1.3 added basic sudo file check
'''

import commands, socket, os, subprocess, string, glob

def main():

    alert = "\x1B[" + "31;40m" + ">>>" + "\x1B[" + "0m " 
    bad_user= ['wstearns', 'rootws', 'mpetti', 'rootmp',' frankc', 'fcastle', 'rootfc']

    if os.geteuid() != 0:
        print "\nWarn: running as non-root user will cause erroneous results"

    sname = socket.gethostname()
    print "Checking server: " +  sname + " \n"

    plist = commands.getoutput('ps -ef')
    if 'tripwire' in plist:
        print "Tripwire ok"
    else: print alert  + "Tripire: fail"
    if 'netbackup' in plist:
        print "Netbackup: ok"
    else: print alert  + "Netbackup: possible fail[proc not running]"
    if 'snmpd' in plist:
        print "smtpd: ok"
    else: print alert +  "snmpd: fail"
    if 'syslog-ng' in plist:
        print "syslog-ng: ok"
    else: print alert + "syslog-ng: fail"
    if 'vmtoolsd' in plist:
        print "vmtools: ok"
    else: print alert + "vmtools: fail [if a vm]"

    ''' check if ssh is allowing root login '''

    try:
        if 'PermitRootLogin yes' in open('/etc/ssh/sshd_config').read():
            print alert +  "sshd_config allows Root login"
        else: print "sshd_config: ok"
    except (IOError, OSError):
        print alert + "sshd_config: read fail"

    ''' if short bp.conf file then its likely missing some bp servers '''

    try:
        num_lines = sum(1 for line in open('/usr/openv/netbackup/bp.conf'))
        if num_lines  > 5: 
            print "bp.conf: ok"
        else: print alert + "bp.conf: fail"
    except (IOError, OSError):
        print alert + "bp.conf: read fail"

    ''' check if up2date has been updated to use neo '''

    try:
        if 'neo.dartmouth.edu' in string.lower(open('/etc/sysconfig/rhn/up2date').read()):
            print "up2date_uses_neo: ok"
        else: print alert + "up2date_config: fail"
    except (IOError, OSError):
        print "up2date: file read fail"

    ''' check if iptables running and check a sample of typical ports added post install'''

    try:
        output,error = subprocess.Popen('/sbin/iptables -L -n'.split(), stdout=subprocess.PIPE).communicate()
        if 'reject-with' not in output:
             print alert + "iptables: fail"
        else: print "iptables: is running,",
	if  '10.230' and 'dpt:13782' and 'dpt:22' not in output: 
            print "but seems to be missing rules"
        else: print "basic port check passed"
    except (IOError, OSError):
        print "iptables: permission denied"

    ''' check selinux '''
    try:
        output,error = subprocess.Popen('/usr/sbin/getenforce'.split(), stdout=subprocess.PIPE).communicate()
        if 'Enforcing' not in output:
             print alert + "selinux: fail (not enforcing)"
        else: print "selinux: ok [Enforcing]"
    except (IOError, OSError):
        print "getenforce: permission denied"

    ''' check /etc/passwd for zenoss user and for accts that should be removed '''

    try:
        f = open('/etc/passwd').read()
	if 'zenoss' not in f:
            print alert + "/etc/passwd: no zenoss user"	
        i = 0
        while i < len(bad_user):
            if bad_user[i] in f: print alert + "passwd: tainted account: " + bad_user[i]
            i+=1
    except (IOError, OSError):
        print "/etc/passwd: read error"
     
    ''' check hosts.deny for all: all '''

    f = open('/etc/hosts.deny').read()
    if 'all:'  not in string.lower(f):
        print alert + "/etc/hosts.deny not denying in hosts.deny"
    else: print "hosts.allow: ok"

    ''' if i didn't disable cups i probably need to tune rc3.d scripts '''

    if  glob.glob('/etc/rc3.d/S*cups'):
        print alert + "rc3.d: disable unnecessary scripts"
    else: print "rc3.d: seems ok"

    ''' very basic check of sudoers file '''

    sudo = False
    try:
        f = open('/etc/sudoers')
        for line in f:
            if 'ALL=' in line and '#' not in line[0] and 'zenoss' not in line:
                sudo = True
    except (IOError, OSError):
        print alert + "/etc/sudoers: read failed"

    if sudo == True:  print alert + "sudoers: allows access"
    else: print "sudoers: ok"


    print "\nAddress any issues and re-run chkserv"

if __name__ == "__main__":
    main()

