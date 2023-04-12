import nmap  # import nmap module for scanning network
import os    # import os module for executing command

def scan_network(target):

    nm = nmap.PortScanner()  # create an instance of the nmap.PortScanner class
    nm.scan(target, arguments='-sS -sV --script vuln') # scan the target using TCP SYN scan (-sS), service/version detection (-sV), and vulnerability scanning (--script vuln) modes
    for host in nm.all_hosts():
        if nm[host].hostname():
            print("Host : %s (%s)" % (host, nm[host].hostname()))
        else:
            print("Host : %s" % host)
        print("State : %s" % nm[host].state())
        for proto in nm[host].all_protocols():
            print("Protocol : %s" % proto)
            lport = nm[host][proto].keys()
            sorted_lport = sorted(lport)
            for port in sorted_lport:
                print("port : %s\tstate : %s" % (port, nm[host][proto][port]['state']))
        os_type = os.popen('nmap -O %s' % host).read()
        print(os_type) # print the OS type of the device
        if 'vulners' in nm[host]:
            print("Vulnerabilities :")
            for vulnerability in nm[host]['vulners']:
                print("  %s" % vulnerability)

if __name__ == '__main__':
    target = input("Enter target IP address: ") # prompt the user to enter the target IP address
    scan_network(target)
