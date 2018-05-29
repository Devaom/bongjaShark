import struct
import binascii
import socket

# H(2) unsigned short -> integer
# s(1) char[] -> string
# B(1) unsigned char -> integer
# L(4) unsigned long -> integer

def main():
    ETHERH_LEN = 14
    IPH_LEN = 20
    TCPH_LEN = 20
    UDPH_LEN = 8
    ICMPH_LEN = 4

    HOST = socket.gethostbyname(socket.gethostname())
    print('HOST NAME:{}'.format(HOST))

    # IP 프로토콜부터 패킷을 가져온다
    rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    rawSocket.bind((HOST, 0))
    rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    rawSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while(True):
        packet = rawSocket.recv(65565)

        # 처음 1바이트에 version과 header length 정보가 저장되어 있음
        ip_ver_hlen = packet[ 0 ]
        iph_version = ip_ver_hlen >> 4 # 앞 부분이 version 이므로 4 비트만큼 shift
        iph_hlen = (ip_ver_hlen & 0xf) * 4 # 앞 4비트만큼만 0으로 만들어 주려면 0000 1111을 AND 연산
        iph_tos = struct.unpack('!B', packet[1 : 2])[0]
        iph_total_len = struct.unpack('!H', packet[2 : 4])[0]
        iph_identifier = struct.unpack('!H', packet[4 : 6])[0]
        iph_flags = '안쓸래'
        iph_frag_offset = '안쓸래'
        iph_ttl = '안쓸래'
        iph_protocol = struct.unpack('!B', packet[9 : 10])[0]
        iph_checksum = struct.unpack('!H', packet[10 : 12])[0]
        iph_srcIP = socket.inet_ntoa(packet[12 : 16])
        iph_dstIP = socket.inet_ntoa(packet[16 : 20])
        # 20 바이트 이후에 option, padding이 있을 수도 있지만 어차피 header length를 받아오니까 노상관

        iph_text = '-' * 50 + '\n'
        iph_text += '<IP>\n'
        iph_text += '\t(Version) {}, (Header Length) {}, (Type of Service) {}, (Total Packet Length) {},\n'.format(iph_version, iph_hlen, iph_tos, iph_total_len)
        iph_text += '\t(Identifier) {}, (Protocol) {}, (Checksum) {},\n'.format(iph_identifier, iph_protocol, iph_checksum)
        iph_text += '\t(Source IP) {}, (Destination IP) {}\n'.format(iph_srcIP, iph_dstIP)

        if iph_protocol == 6: # TCP
            tcp = packet[iph_hlen : ]
            tcph_srcPort = struct.unpack('!H', tcp[0 : 2])[0]
            tcph_dstPort = struct.unpack('!H', tcp[2 : 4])[0]
            tcph_seq = struct.unpack('!L', tcp[4 : 8])[0]
            tcph_ack = struct.unpack('!L', tcp[8 : 12])[0]
            tcph_hlen_reserved = struct.unpack('!B', tcp[12 : 13])[0]
            tcph_hlen = (tcph_hlen_reserved >> 4) * 4
            tcph_flags = struct.unpack('!B', tcp[13 : 14])[0]
            tcph_flags = '{0:06b}'.format(tcph_flags) # 06은 왼쪽을 0으로 채우겠다는 의미.

            tcp_text = '<TCP>\n'
            tcp_text += '\t(Source Port) {}, (Destination Port) {}\n'.format(tcph_srcPort, tcph_dstPort)
            tcp_text += '\t(Sequence) {}, (Acknowledge) {}\n'.format(tcph_seq, tcph_ack)
            tcp_text += '\t(Header Length) {}\n'.format(tcph_hlen)
            tcp_text += '\t(Flags) URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}\n'.format(tcph_flags[0], tcph_flags[1], tcph_flags[2], tcph_flags[3], tcph_flags[4], tcph_flags[5])

            if 80 in [tcph_srcPort, tcph_dstPort]:
                http_packet = tcp[tcph_hlen : ]
                http_text = http_process(http_packet)
                print(iph_text + tcp_text + http_text)

            elif 25 in [tcph_srcPort, tcph_dstPort]:
                smtp_packet = tcp[tcph_hlen : ]
                smtp_text = smtp_process(smtp_packet)
                print(iph_text + tcp_text + smtp_text)

        elif iph_protocol == 17: # UDP
            udp = packet[iph_hlen : ]
            udph = struct.unpack('!HHHH', udp[0 : 8]) # UDP 헤더는 8바이트 고정이므로
            udph_srcPort = udph[0]
            udph_dstPort = udph[1]
            udph_len = udph[2] # data(응용)까지 포함한 크기(헤더는 8 바이트 고정)
            udph_checksum = udph[3]

            udp_data = udp[8 : ]

            udp_text = '<UDP>\n'
            udp_text += '\t(Source Port) {}, (Destination Port) {}\n'.format(udph_srcPort, udph_dstPort)
            udp_text += '\t(Total Length) {}, (Checksum) {}\n'.format(udph_len, udph_checksum)

            if 53 in [udph_srcPort, udph_dstPort]:
                dns_text = dns_process(udp_data)
                print(iph_text + udp_text + str(dns_text))

        elif iph_protocol == 0: # ICMP
            pass

def dns_process(dns_packet):
    dnsh_transaction_id = struct.unpack('!H', dns_packet[0 : 2])[0]
    dnsh_flags = struct.unpack('!H', dns_packet[2 : 4])[0]
    dnsh_question = struct.unpack('!H', dns_packet[4 : 6])[0]
    dnsh_answer = struct.unpack('!H', dns_packet[6 : 8])[0]
    dnsh_authority = struct.unpack('!H', dns_packet[8 : 10])[0]
    dnsh_additional = struct.unpack('!H', dns_packet[10 : 12])[0]

    dns_answer_name = list()
    dns_answer_type = list()
    dns_answer_class = list()
    dns_answer_ttl = list()
    dns_answer_datalength = list()
    dns_answer_resource_data = list()

    # find 등의 함수를 이용하기 위해 bytearray로 변환
    dns_array = bytearray(dns_packet)

    # domain name은 null(\x00)로 끝남
    # dns header는 12 bytes length
    dns_query_name_null_idx = dns_array.find(b'\x00', 13)
    dns_query_name = dns_array[12 : dns_query_name_null_idx + 1]
    dns_query_name = domain_processor(dns_query_name, dns_array)

    dns_query_type = dns_array[dns_query_name_null_idx + 1 : dns_query_name_null_idx + 3]
    dns_query_type = struct.unpack('!H', dns_query_type)[0]

    dns_query_class = dns_array[dns_query_name_null_idx + 3 : dns_query_name_null_idx + 5]
    dns_query_class = struct.unpack('!H', dns_query_class)[0]

    # answer 부분
    dns_answer_idx = dns_query_name_null_idx + 5

    for cnt in range(0, dnsh_answer):
        # name 값 처리
        # dns answer의 domain name은 다른 값을 포인팅하므로..(\xc0 \x??)
        # \xc0 \x?? 에서 ?? 부분을 이용해서 dns name을 가져온다
        dns_answer_name_start_idx = dns_array[dns_answer_idx : dns_answer_idx + 2]
        dns_answer_name_start_idx = struct.unpack('!BB', dns_answer_name_start_idx)[1]
        dns_answer_name_end_idx = dns_array.find(b'\x00', dns_answer_name_start_idx)
        dns_name = dns_array[dns_answer_name_start_idx : dns_answer_name_end_idx]
        dns_name = domain_processor(dns_name, dns_array)
        dns_answer_name.append(dns_name)

        # type 값 처리
        dns_type = dns_array[dns_answer_idx + 2: dns_answer_idx + 4]
        dns_type = struct.unpack('!H', dns_type)[0]
        dns_answer_type.append(dns_type)

        # class 값 처리
        dns_class = dns_array[dns_answer_idx + 4 : dns_answer_idx + 6]
        dns_class = struct.unpack('!H', dns_class)[0]
        dns_answer_class.append(dns_class)

        # ttl 값 처리
        dns_ttl = dns_array[dns_answer_idx + 6 : dns_answer_idx + 10]
        dns_ttl = struct.unpack('!L', dns_ttl)[0]
        dns_answer_ttl.append(dns_ttl)

        # data length 값 처리
        dns_datalength = dns_array[dns_answer_idx + 10 : dns_answer_idx + 12]
        dns_datalength = struct.unpack('!H', dns_datalength)[0]
        dns_answer_datalength.append(dns_datalength)

        # answer type 값에 따른 resource data 값 처리
        if dns_answer_type[cnt] == 1: # A(Host Address)
            # IP Address 이므로 Data length는 4 bytes
            ipv4 = dns_array[dns_answer_idx + 12 : dns_answer_idx + 12 + dns_answer_datalength[cnt]]
            ipv4 = struct.unpack('!BBBB', ipv4)
            dns_answer_resource_data.append(ipv4)

        elif dns_answer_type[cnt] == 2: # NS
            domain_name = dns_array[dns_answer_idx + 12 : dns_answer_idx + 12 + dns_answer_datalength[cnt]]
            domain_name = struct.unpack('!' + str(dns_answer_datalength[cnt]) + 's', domain_name)[0]
            dns_answer_resource_data.append(domain_name)

        elif dns_answer_type[cnt] == 5: # CNAME
            cname = dns_array[dns_answer_idx + 12: dns_answer_idx + 12 + dns_answer_datalength[cnt]]
            cname = struct.unpack('!' + str(dns_answer_datalength[cnt]) + 's', cname)[0]
            cname = domain_processor(cname, dns_array)
            dns_answer_resource_data.append(cname)

        elif dns_answer_type == 15: # MX
            mx = dns_array[dns_answer_idx + 12 : dns_answer_idx + 12 + dns_answer_datalength[cnt]]
            mx = struct.unpack('!' + str(dns_answer_datalength[cnt]) + 's', mx)
            dns_answer_resource_data.append(mx)

        elif dns_answer_type == 28: # AAAA
            ipv6 = dns_array[dns_answer_idx + 12 : dns_answer_idx + 12 + dns_answer_datalength[cnt]]
            ipv6 = binascii.hexlify(ipv6)
            dns_answer_resource_data.append(ipv6)

        else:
            print('코딩 안된 Type({})임. '.format(dns_answer_type))

    output = '<DNS>\n'
    output += '\t<Header>\n'
    output += '\t\t(TRANSACTION ID) {}, (FLAGS) {}\n'.format(dnsh_transaction_id, dnsh_flags)
    output += '\t\t(QUESTION) {}, (ANSWER) {}\n'.format(dnsh_question, dnsh_answer)
    output += '\t\t(AUTHORITY) {}, (ADDITIONAL) {}\n'.format(dnsh_authority, dnsh_additional)
    output += '\t<Query>\n'
    output += '\t\t(DOMAIN NAME) {}\n'.format(dns_query_name)
    output += '\t\t(TYPE) {}, (CLASS) {}\n'.format(dns_query_type, dns_query_class)

    for cnt in range(0, dnsh_answer):
        output += '\t<Answer>\n'
        output += '\t\t(NAME) {}\n'.format(dns_answer_name[cnt])
        output += '\t\t(TYPE) {}, (CLASS) {}, (TTL) {}\n'.format(dns_answer_type[cnt], dns_answer_class[cnt], dns_answer_ttl[cnt])
        output += '\t\t(DATA LENGTH) {}\n'.format(dns_answer_datalength[cnt])
        if dns_answer_type[cnt] == 1:
            output += '\t\t(ADDRESS) {}\n'.format(dns_answer_resource_data[cnt])
        elif dns_answer_type[cnt] == 2:
            output += '\t\t(NS) {}\n'.format(dns_answer_resource_data[cnt])
        elif dns_answer_type[cnt] == 5:
            output += '\t\t(CNAME) {}\n'.format(dns_answer_resource_data[cnt])
        elif dns_answer_type[cnt] == 15:
            output += '\t\t(MX) {}\n'.format(dns_answer_resource_data[cnt])
        elif dns_answer_type[cnt] == 28:
            output += '\t\t(AAAA) {}\n'.format(dns_answer_resource_data[cnt])

    output += '\n'
    return output

def http_process(http_packet):
    output = '<HTTP>\n'
    output += str(http_packet, 'utf-8')
    return output

def smtp_process(smtp_packet):
    output = '<SMTP>\n'
    output += str(smtp_packet, 'utf-8')
    output += '\n'
    return output

def domain_processor(domain_name, dns_array):
    # domain 문자열 위치 탐색
    #domain_start = domain_name.find(b'\xc0') + 1

    domain_idx = domain_name.find(b'\xc0') + 1 # find()는 해당 바이트가 없으면 -1 을 리턴하므로..
    if domain_idx:
        domain_start_idx = domain_name[domain_idx]  # \xc0 바로 다음 값의 값이 인덱스값이므로 가져온다.
        domain_end_idx = dns_array.find(b'\x00', domain_start_idx) + 1
        domain_name = domain_name[ : -2] + dns_array[domain_start_idx : domain_end_idx]

    # DNS의 Domain의 . 구분자 치환
    for dot in [b'\n', b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\x09', b'\x0b', b'\x0c', b'\x11']:
        domain_name = domain_name.replace(dot, b'.')

    # NULL 문자 삭제
    domain_name = domain_name.replace(b'\x00', b'')
    try:
    #print('dname : ' + str(domain_name))
        return domain_name.decode('utf-8')
    except:
        print('에러발생!')
        return domain_name

main()