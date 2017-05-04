import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

import time

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def get_count(count_packets, address):
    current_time = time.time()
    count_packets.append({'time': current_time, 'source': address})
    
    count = 0;

    # Index
    i = 0

    for x in count_packets:
        if current_time - x['time'] <= 2 and x['source'] == address:
            count = count + 1;
            pass
        i = i + 1
    count_packets = count_packets[i-count:]
    return count_packets, count


def two_sec_analysis(timed_packets, dest_mac, src_mac, proto, src_port, dest_port, sequence, acknowledgment, flag_urg):
    

    # Feature: LAND (1 if connection is from/to the same host/port; 0 otherwise )

    if(dest_mac == src_mac or src_port == dest_port):
        land = 1
    else:
        land = 0

    # Feature: Flag (1 if connection is urgent; 0 otherwise )

    if(flag_urg):
        urg_flag = 1
    else:
        urg_flag = 0

    current_time = time.time()
    # Append the packts to a list which holds only the packets from last two seconds.
    print("In the function")
    count = 0

    # Timed host is the main list which contains packets.
    timed_packets.append({
        'time': current_time, 
        'dest_mac': dest_mac,
        'src_port': src_port,
        'urg_flag': urg_flag
    })


    # Index counter
    i =0 
    for x in timed_packets:
        # If the life of packet more than two seconds.
        if current_time - x['time'] <= 2:
            count = count + 1;
            pass
        i = i + 1
    timed_packets = timed_packets[i-count:]



    same_host_count = 0
    same_service_count = 0
    urg_flag_count = 0

    for x in timed_packets:
        # Same Host count
        if x['dest_mac'] == dest_mac:
            same_host_count = same_host_count + 1

        # Same service count
        if x['src_port'] == src_port:
            same_service_count = same_service_count + 1

        # Urgent packets count
        if x['urg_flag'] == 1:
            urg_flag_count = urg_flag_count + 1
        

    print("same host: ", same_host_count)
    print("same service: ", same_service_count)
    print("Urgent count: ", urg_flag_count)
    
    same_srv_rate = same_service_count / same_host_count * 100
    diff_srv_rate = 100 - same_srv_rate

    print("percentage of same host to same service: ", same_srv_rate, "%")
    print("percentage of same host to differnt service: ", diff_srv_rate, "%")



def main():
    timed_packets = []
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        # print('\nEthernet Frame:')
        # print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # Get count feature

        # timed_packets, count = get_count(timed_packets, eth.dest_mac)
        
        # Analyze the packets for last two seconds.
        
        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            # print(TAB_1 + 'IPv4 Packet:')
            # print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            # print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                # print(TAB_1 + 'ICMP Packet:')
                # print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                # print(TAB_2 + 'ICMP Data:')
                # print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                # print(TAB_1 + 'TCP Segment:')
                # print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                # print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                # print(TAB_2 + 'Flags:')
                # print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                # print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                
                # TODO: Design different functions for different datasets. 

                two_sec_analysis(timed_packets, eth.dest_mac, eth.src_mac, eth.proto, tcp.src_port, tcp.dest_port, tcp.sequence, tcp.acknowledgment, tcp.flag_urg)

                if tcp.flag_urg == 0 and tcp.flag_ack == 0 and tcp.flag_psh == 0 and  tcp.flag_rst == 0 and tcp.flag_syn == 1 and tcp.flag_fin == 0:
                    print("SYN Request Sent!")    
                    pass
                elif tcp.flag_urg == 0 and tcp.flag_ack == 1 and tcp.flag_psh == 0 and  tcp.flag_rst == 0 and tcp.flag_syn == 1 and tcp.flag_fin == 0:
                    print("SYN-ACK Request Sent!")    
                    pass
                elif tcp.flag_urg == 0 and tcp.flag_ack == 1 and tcp.flag_psh == 0 and  tcp.flag_rst == 0 and tcp.flag_syn == 0 and tcp.flag_fin == 0:
                    print("ACK Request Sent!")    
                    pass

                elif tcp.flag_urg == 0 and tcp.flag_ack == 1 and tcp.flag_psh == 0 and  tcp.flag_rst == 0 and tcp.flag_syn == 0 and tcp.flag_fin == 0:
                    print("ACK Request Sent!")    
                    pass

                elif tcp.flag_urg == 0 and tcp.flag_ack == 1 and tcp.flag_psh == 0 and  tcp.flag_rst == 0 and tcp.flag_syn == 0 and tcp.flag_fin == 0:
                    print("ACK Request Sent!")    
                    pass

                elif tcp.flag_urg == 0 and tcp.flag_ack == 1 and tcp.flag_psh == 0 and  tcp.flag_rst == 0 and tcp.flag_syn == 0 and tcp.flag_fin == 0:
                    print("ACK Request Sent!")    
                    pass

                if len(tcp.data) > 0:
                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        # print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print("")
                            # print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print("")
                        # print(TAB_2 + 'TCP Data:')
                        # print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                # print(TAB_1 + 'UDP Segment:')
                # print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print("")
                # print(TAB_1 + 'Other IPv4 Data:')
                # print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print("")
            # print('Ethernet Data:')
            # print(format_multi_line(DATA_TAB_1, eth.data))

    pcap.close()


main()
