# Sunifa

### Sniffing Tool 

## What is Sunifa:
    Ths is my new tool like tcpdump.
    And you can save the results to a pcap file
    You can also read pcap files from the command line by using switch r
    and analyzed using tools GUI such as Wireshark.....

## The Script can sniff 
  ports Like "TCP UDP ICMP IGMP DNS ARP" and more..... 
  

## Installation:

    $ apt-get install git
    $ git clone https://github.com/Lonewolf-13/Sunifa
    $ cd Sunifa
    $ sudo pip3 install -r requirements.txt
    $ sudo chmod +x sunifa.py 

## Or Use this bash script:
    $ sudo bash setup.sh 

## Usage: 
************************************************************
#### Sniffing and Save in Pcap File
    #### Usage: sudo ./Sunifa.py [Interface name] w [Pcap File Name .pcap]
    ##### Example: sudo ./Sunifa.py eth0 w file.pcap 
************************************************************
#### Read Pcap Files
    ##### Usage: sudo ./Sunifa [Interface name] r [Pcap File Name .pcap]
    ##### Example: sudo ./Sunifa eth0 r file.pcap
************************************************************
