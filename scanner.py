import nmap
rang = input("enter the subnet: ")
nm = nmap.PortScanner()
nm.scan(hosts=rang, arguments="-sn")
host_list=[(x,nm[x]['status']['state']) for x in nm.all_hosts()]
final_host_list = []
for i in host_list:
    final_host_list.append(i[0])


for x in final_host_list:
    nm.scan(x, '1-2024')
    print("\n")
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
    
            lport = nm[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                

