from scapy.all import *
import argparse

def main():
    parser = argparse.ArgumentParser(description='A simple command line tool for sniffing packets and returning src, dst, port, flag and sequency number. ' 
                                                'Use -t for tcp, -u for udp and Use -p to specify port. Please see the arguments for examples.')
    parser.add_argument('-i', '--ip', help='sniff packets for the specified ip address')                                            
    parser.add_argument('-t', '--tcp', help='sniff TCP packets on the provided interface', action='store_true')
    parser.add_argument('-u', '--udp', help='sniff UDP packets on the provided interface', action='store_true')
    parser.add_argument('-p', '--port', help='specify port to be sniffed (80 443 22...). ex: sniff.py -t -p 443', type=int)
    parser.add_argument('-c', '--count', help='number of packets to sniff. ex. sniff.py -t -p 443 -c 100')
    parser.add_argument('-T', '--timeout', help='number of packets to sniff. ex. sniff.py -t -p 443 -T 60')
    parser.add_argument('-O', '--offline', help='read a pcap file of your choice. ex. sniff.py -t -p 443 -O /<filepath>/file.pcap')                 
    parser.add_argument('-o', '--output', help='output results to a file of your choice. ex. sniff.py -t -p 443 -o /<filepath>/output.txt')
    args = parser.parse_args()

    def pkt_sniff(ip, port, flag):
        a = sniff(filter='host ' + ip + " and " + flag + ' ' + port, prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% - %TCP.seq%"))
        if args.output:
            with open(args.output, 'w') as o:
                o.writelines(sniff(filter='host ' + ip + " and " + flag + ' ' + port, prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% - %TCP.seq%"), count=100))
    def pkt_sniff_offline(ip, port, flag):
        a = sniff(offline=args.offline, filter='host ' + ip + " and " + flag + port, prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% - %TCP.seq%"))
        if args.output:
            with open(args.output, 'w') as o:
                o.writelines(sniff(filter='host ' + ip + " and " + flag + ' ' + port, prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% - %TCP.seq%"), count=100))

    if args.port:
        port = args.port
    else:
        port = 'portrange 1-1024'
    if args.ip:
        if args.offline and args.tcp == True:
            pkt_sniff_offline(str(args.ip), str(port), ('tcp'))
        if args.offline and args.udp == True:
            pkt_sniff_offline(str(args.ip), str(port), ('udp'))
        else: 
            if args.tcp == True:
                pkt_sniff(str(args.ip), str(port), ('tcp'))
            elif args.udp == True:
                pkt_sniff(str(args.ip), str(port), ('udp'))

if __name__=='__main__':
    main()
