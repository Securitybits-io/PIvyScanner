'''
MIT Liscence
Copyright (c) 2018 Christoffer Claesson @ Securitybits.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

__author__ = 'Christoffer Claesson (Christoffer.Claesson@Securitybits.io)'
__copyright__ = 'Copyright (c) 2018 Christoffer Claesson'
__license__ = 'MIT Liscence'
__vcs_id__ = '$Id$'
__version__ = '1.0.0' #Versioning: http://www.python.org/dev/peps/pep-0386/

#Statics
prog_desc = '''
Python script to scan after C&C Servers running Poison Ivy,
which is vulnerable to a Remote Code Execution bug. Exploit-DB: 39907 & 19613
'''

#TODO: Threading?
#TODO: write to file?

import argparse
import iptools
import socket

def createIpRange(cidr): #NOTE: 192.168.0.0/16 = 0.5MB ram
    print("Generating IP Range...")
    range = []
    for ip in iptools.IpRange(cidr):
        range.append(ip)
    return range

def createPortRange(range):
    ports = []
    if(range == None):
        ports = [3460]
    else:
        ports = range.split(",")
    return ports

def ivyScan(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    
    try:
        sock.connect((ip,int(port)))
        sData = "\x00" * 0x100
        sock.sendall(sData)
        rData = sock.recv(0x100)
        if len(rData) != 0x100:
            sock.close()
            return
        else:
            rData = sock.recv(0x4)
            sock.close()
        
        if rData != "\xD0\x15\x00\x00":
            return
        else:
            print("%s:%d - Vulnerable" % (ip,port))
        
    except socket.timeout as e:
        print("Scanning IP: %s:%d" % (ip,port),end='\r')
    except socket.error as e:
        pass
    return

def scan(ipList, portList):
    for target in ipList:
        for port in portList:
            ivyScan(target,port)
    return

def initArgParser():
    parser = argparse.ArgumentParser(prog="PIvyScanner.py", usage='./%(prog)s [options]', description=prog_desc )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i',  '--ip',       type=str, help='Input target ip')#Single Target
    group.add_argument('-r',  '--range',    type=str, help='Input target ip in CIDR Notation eg. 127.0.0.1/24')#CIDR Range
    #group.add_argument('-f',  '--file',     type=str, help='Choose file with one IP on each line')#Targets from file
    parser.add_argument('-p', '--ports',    type=str, help='Input port range separated by comma. (Default=3460)')#Ports
    return parser.parse_args()

def main():
    try:
        args = initArgParser()
        ports = createPortRange(args.ports)
        IPs = []

        if ((args.ip or args.range or args.file) == None):
            print("Please specify an IP to scan")
            return
        elif(args.ip != None):
            IPs.append(args.ip)
        elif(args.range != None):
            IPs = createIpRange(args.range)
        elif(args.file != None):
            with open(args.file) as targetFile:
                IPs = [line.rstrip() for line in targetFile]

        scan(IPs, ports)
        return
    except(KeyboardInterrupt,SystemExit):
        pass
    
if __name__ == '__main__':
    main()
