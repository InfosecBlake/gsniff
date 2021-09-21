# gsniff

A simple command line ARP/TCP scanning tool.

                                         _____  _____ _   _ _____ ______ ______ 
                                        / ____|/ ____| \ | |_   _|  ____|  ____|
                                       | |  __| (___ |  \| | | | | |__  | |__   
                                       | | |_ |\___ \| . ` | | | |  __| |  __|  
                                       | |__| |____) | |\  |_| |_| |    | |     
                                        \_____|_____/|_| \_|_____|_|    |_|     
                                          
                                         


## About

#### 
gniff is a simepple command line tool for sniffing packets on a network or from a pcap and returning specified tcp/udp traffic, flags and sequence numbers.

## Installation

Download the `gping.py` script and
use the package manager [pip](https://pip.pypa.io/en/stable/) to install dependencies.
```bash
pip install -r requirements.txt
```
or
```bash
pip install scapy
pip install argparse
```

## Usage

To use the tool, cd to the directory that contains your `gsniff.py scritp and then run the script as shown below:
```bash
python gsniff.py <args>
```
or use the following for help:
```bash
python gsniff.py --help
```
```bash

          _____  _____ _   _ _____ ______ ______
         / ____|/ ____| \ | |_   _|  ____|  ____|
        | |  __| (___ |  \| | | | | |__  | |__
        | | |_ |\___ \| . ` | | | |  __| |  __|
        | |__| |____) | |\  |_| |_| |    | |
         \_____|_____/|_| \_|_____|_|    |_|



usage: sniff.py [-h] [-i IP] [-t] [-u] [-p PORT] [-c COUNT] [-T TIMEOUT] [-O OFFLINE] [-o OUTPUT]

A simple command line tool for sniffing packets and returning src, dst, port, flag and sequency number. Use -t for tcp, -u for udp and
Use -p to specify port. Please see the arguments for examples.

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        sniff packets for the specified ip address
  -t, --tcp             sniff TCP packets on the provided interface
  -u, --udp             sniff UDP packets on the provided interface
  -p PORT, --port PORT  specify port to be sniffed (80 443 22...). ex: sniff.py -t -p 443
  -c COUNT, --count COUNT
                        number of packets to sniff. ex. sniff.py -t -p 443 -c 100
  -T TIMEOUT, --timeout TIMEOUT
                        number of packets to sniff. ex. sniff.py -t -p 443 -T 60
  -O OFFLINE, --offline OFFLINE
                        read a pcap file of your choice. ex. sniff.py -t -p 443 -O /<filepath>/file.pcap
  -o OUTPUT, --output OUTPUT
                        output results to a file of your choice. ex. sniff.py -t -p 443 -o /<filepath>/output.txt
```

## Pipeline
This tool will be continue to be updated, if you would like a feature please put in an issue and I will address it when available. 
Upcoming:
  - remove sniffing twice when outputting to file
  - resolve windows issues when sniffing from pcap

## Contributing
If you would like to become a contributer please open an issue. For changes, please open an issue first to discuss what you would like to change.

If a you would like to commit a change, please open a pull request for review. Please make sure to update tests as appropriate.

## License
MIT License
