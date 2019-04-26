import dpkt
import copy

"""
Src_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)' \
                '\\네트워크패킷수집\\EZVIZ_dump_from_n604s\\refresh.pcap'
"""
# Src_file_name = 'D:\\VM\\shared\\00_frag_udp.pcapng'
Src_file_name = 'D:\\VM\\shared\\00_frag.pcapng'
Packet_list = list()
Parsed_list = list()

ETH_TYPE_IP = dpkt.ethernet.ETH_TYPE_IP
ETH_TYPE_IP6 = dpkt.ethernet.ETH_TYPE_IP6
IP_PROTO_TCP = dpkt.ip.IP_PROTO_TCP
IP_PROTO_UDP = dpkt.ip.IP_PROTO_UDP
IP_PROTO_ICMP = dpkt.ip.IP_PROTO_ICMP

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80

TIME_WINDOW_SIZE_CNT = 100
TIME_WINDOW_SIZE_SEC = 5
DECIMAL_PRECISION = 6

Feature_list = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 'serror_rate',
                'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'dst_host_count',
                'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

Symbol_fields = ['protocol_type', 'service', 'flag']
Field_symbol = dict()
Field_symbol['protocol_type'] = ['tcp', 'udp', 'icmp']
Field_symbol['service'] = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain',
                           'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher',
                           'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC',
                           'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm',
                           'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump',
                           'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp',
                           'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time',
                           'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50']
Field_symbol['flag'] = ['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH']

Fragment_buffer = dict()


def load_and_read_pcap(file_name):
    src_file = open(file_name, 'rb')

    if Src_file_name.find('.pcapng') >= 0:
        read_instance = dpkt.pcapng.Reader(src_file)
    elif Src_file_name.find('.pcap') >= 0:
        read_instance = dpkt.pcap.Reader(src_file)
    else:
        raise NotImplementedError

    return read_instance


def _convert_addr(addr_bytes, protocol='IPv4'):
    result_addr = ''

    if protocol == 'IPv4' and type(addr_bytes) is bytes and len(addr_bytes) == 4:
        for addr_idx in range(4):
            temp_str = ".%d" % addr_bytes[addr_idx]
            result_addr += temp_str
        return result_addr[1:]
    elif protocol == 'IPv6' and type(addr_bytes) is bytes and len(addr_bytes) == 16:
        for addr_idx in range(16):
            temp_str = ''
            if addr_idx % 2 == 0:
                temp_str += ':'
            temp_str += "%02x" % (addr_bytes[addr_idx])
            result_addr += temp_str
        return result_addr[1:]
    else:
        raise Exception('@ Error\n\tInvalid parameter - convert_addr()')


def _extract_protocol_type(ip_packet):
    if ip_packet.p == IP_PROTO_TCP:
        return 'TCP'
    elif ip_packet.p == IP_PROTO_UDP:
        return 'UDP'
    elif ip_packet.p == IP_PROTO_ICMP:
        return 'ICMP'
    else:
        # raise NotImplementedError
        return 'Not_Implemented'


def _extract_service():
    # TODO - Need to implement
    return 'No_service'


def _extract_ctrl_flag(ip_packet):
    if ip_packet.p == IP_PROTO_TCP:
        result_flag_list = list()
        ctrl_flag = ip_packet.data.flags

        if ctrl_flag & TH_FIN:
            result_flag_list.append('FIN')
        if ctrl_flag & TH_SYN:
            result_flag_list.append('SYN')
        if ctrl_flag & TH_RST:
            result_flag_list.append('RST')
        if ctrl_flag & TH_PUSH:
            result_flag_list.append('PSH')
        if ctrl_flag & TH_ACK:
            result_flag_list.append('ACK')
        if ctrl_flag & TH_URG:
            result_flag_list.append('URG')
        if ctrl_flag & TH_ECE:
            result_flag_list.append('ECE')
        if ctrl_flag & TH_CWR:
            result_flag_list.append('CWR')

        return result_flag_list
    else:
        return 'No_flag'


def _extract_transport_layer_data_len(ip_packet):
    try:
        result = ip_packet.data.data.__len__()
    except Exception as e:
        result = ip_packet.data.__len__()

    return result


def _get_past_2_seconds(curr_time):
    pass


def _reassemble_packet(frag_id):
    # 1. Sorting fragments by order
    Fragment_buffer[frag_id]['packets'].sort(key=lambda pkt: dpkt.ethernet.Ethernet(pkt).data.offset)

    # 2. Temporarily assemble packet
    tmp_assembled_packet = None
    for frag in Fragment_buffer[frag_id]['packets']:
        if tmp_assembled_packet is None:
            tmp_assembled_packet = bytes(frag)  # Including ethernet header and ip header
        else:
            tmp_assembled_packet += bytes(dpkt.ethernet.Ethernet(frag).data.data)   # Including only ip data

    # 3. Modifying ip header length
    packet_front_part = copy.deepcopy(tmp_assembled_packet[:6+6+2+2])
    packet_rear_part = copy.deepcopy(tmp_assembled_packet[6+6+2+2+2:])
    ip_length = 2 + 2 + len(packet_rear_part)   # Version, Header Length (2 bytes) + IP Length (2 bytes) + The rest

    assembled_packet = packet_front_part + bytes(ip_length.to_bytes(2, byteorder='big')) + packet_rear_part
    # assembled_packet = dpkt.ethernet.Ethernet(assembled_packet)

    del tmp_assembled_packet

    Fragment_buffer[frag_id]['reassembled'] = assembled_packet


# Return Value
# True : Fragmentation
# False: Not fragmentation or all fragments has arrived
def _is_fragment(packet, ip_level):
    if ip_level.df:     # Not fragmented
        return False
    else:               # Fragmented
        if not (ip_level.id in Fragment_buffer):    # If this is the first fragment
            Fragment_buffer[ip_level.id] = dict()
            Fragment_buffer[ip_level.id]['packets'] = list()
            Fragment_buffer[ip_level.id]['tot_len'] = 65536
            Fragment_buffer[ip_level.id]['acc_len'] = 0
            Fragment_buffer[ip_level.id]['num_of_frags'] = 0

        if ip_level.mf == 0:    # If this is the last fragmentation
            assert ip_level.len - ip_level.hl * 4 == ip_level.data.__len__()
            Fragment_buffer[ip_level.id]['tot_len'] = ip_level.offset + ip_level.len - ip_level.hl * 4

        Fragment_buffer[ip_level.id]['packets'].append(packet)
        Fragment_buffer[ip_level.id]['acc_len'] += ip_level.data.__len__()
        Fragment_buffer[ip_level.id]['num_of_frags'] += 1

        # If all of fragments has arrived
        if Fragment_buffer[ip_level.id]['acc_len'] >= Fragment_buffer[ip_level.id]['tot_len']:
            _reassemble_packet(ip_level.id)
            return False
        return True


def _get_num_of_frags(ip_packet):
    if ip_packet.id in Fragment_buffer:
        return Fragment_buffer[ip_packet.id]['num_of_frags']
    else:
        return 0


def _is_valid_protocol(ether_frame):
    eth_type = ether_frame.type

    if eth_type in [ETH_TYPE_IP, ETH_TYPE_IP6]:
        return True
    else:
        return False


def _extract_basic_features(read_instance):
    global Packet_list, Parsed_list

    packet_idx = 0
    # ts: timestamp
    # buf: buffer
    for ts, buf in read_instance:
        packet_idx += 1
        ether_level = dpkt.ethernet.Ethernet(buf)
        ip_level = ether_level.data

        if _is_valid_protocol(ether_level) is False:
            continue

        is_need_to_remove = _is_fragment(buf, ip_level)

        if is_need_to_remove is True:
            continue

        new_dict_features = dict()

        if ether_level.type == ETH_TYPE_IP:
            converted_src_ip = _convert_addr(ip_level.src, 'IPv4')
            converted_dst_ip = _convert_addr(ip_level.dst, 'IPv4')
        elif ether_level.type == ETH_TYPE_IP6:
            converted_src_ip = _convert_addr(ip_level.src, 'IPv6')
            converted_dst_ip = _convert_addr(ip_level.dst, 'IPv6')
        else:
            print("### Warning - this packet is not an IP packet. ###")
            print("\tIndex: %d" % packet_idx)
            print("\tEthernet type: 0x%04x" % ether_level.type)
            continue

        protocol_type = _extract_protocol_type(ip_level)
        service = _extract_service()
        ctrl_flag = _extract_ctrl_flag(ip_level)
        num_of_frags = _get_num_of_frags(ip_level)
        if num_of_frags > 0:    # Fragmented
            tl_data_len = Fragment_buffer[ip_level.id]['tot_len']
            whole_packet = Fragment_buffer[ip_level.id]['reassembled']
            del Fragment_buffer[ip_level.id]
        else:                   # Not Fragmented
            tl_data_len = _extract_transport_layer_data_len(ip_level)
            whole_packet = buf
        if converted_src_ip == converted_dst_ip:
            src_dst_same = 1    # True
        else:
            src_dst_same = 0    # False

        # print(whole_packet)
        # print(len(whole_packet))
        new_dict_features['idx'] = packet_idx
        new_dict_features['timestamp'] = ts
        new_dict_features['src_ip'] = converted_src_ip
        new_dict_features['dst_ip'] = converted_dst_ip
        new_dict_features['src_port'] = ip_level.data.sport
        new_dict_features['dst_port'] = ip_level.data.dport

        new_dict_features['protocol_type'] = protocol_type
        new_dict_features['tl_data_len'] = tl_data_len
        new_dict_features['service'] = service
        new_dict_features['flag'] = ctrl_flag
        new_dict_features['num_of_frags'] = num_of_frags
        new_dict_features['src_dst_same'] = src_dst_same

        Parsed_list.append(new_dict_features)
        Packet_list.append(whole_packet)

    assert len(Packet_list) == len(Parsed_list)


def _extract_time_window_features(time_window_sec_stat, target_packet, target_parsed):
    """
    num_of_packets = len(past_packet_parsed_list)
    num_of_acks = 0

    for past_packet, past_parsed in past_packet_parsed_list:
        if 'ACK' in past_parsed['flag']:
            num_of_acks += 1

    if num_of_packets == 0:
        target_parsed['srv_ack_rate'] = 0
    else:
        target_parsed['srv_ack_rate'] = format(num_of_acks / num_of_packets, '0.' + str(DECIMAL_PRECISION) + 'f')
    """
    target_src_ip = target_parsed['src_ip']
    target_dst_ip = target_parsed['dst_ip']
    target_src_port = target_parsed['src_port']
    target_dst_port = target_parsed['dst_port']

    if target_src_ip in time_window_sec_stat['forward']:
        same_sip_pkt_cnt = 0
        same_dip_pkt_cnt = 0
        same_sip_sport_pkt_cnt = 0
        same_dip_dport_pkt_cnt = 0

        same_sip_pkt_dip_cnt = 0
        same_dip_pkt_src_cnt = 0
        same_src_dst_pkt_sport_cnt = 0
        same_src_dst_pkt_dport_cnt = 0

        for src_port in time_window_sec_stat['forward'][target_src_ip]['ports']:
            if src_port == target_src_port:
                same_sip_sport_pkt_cnt = time_window_sec_stat['forward'][target_src_ip]['ports'][src_port]
            same_sip_pkt_cnt += time_window_sec_stat['forward'][target_src_ip]['ports'][src_port]
        same_sip_pkt_dip_cnt = len(time_window_sec_stat['forward'][target_src_ip]['dst_ip'])

        for src_ip in time_window_sec_stat['backward'][target_dst_ip]:
            for dst_port in time_window_sec_stat['forward'][src_ip]['dst_ip'][target_dst_ip]:
                if dst_port == target_dst_port:
                    same_dip_dport_pkt_cnt = time_window_sec_stat['forward'][src_ip]['dst_ip'][target_dst_ip][dst_port]
                same_dip_pkt_cnt += time_window_sec_stat['forward'][src_ip]['dst_ip'][target_dst_ip][dst_port]
        same_dip_pkt_src_cnt = len(time_window_sec_stat['backward'][target_dst_ip])
    else:
        pass

    """
    if target_dst_ip in time_window_sec_stat['dst']:
        same_ip_pkt_cnt = 0
        same_ip_port_pkt_cnt = 0
        for dst_port in time_window_sec_stat['dst'][target_dst_ip].keys():
            if dst_port == target_dst_port:
                same_ip_port_pkt_cnt = time_window_sec_stat['dst'][target_dst_ip][dst_port]
            same_ip_pkt_cnt += time_window_sec_stat['dst'][target_dst_ip][dst_port]
        target_parsed['same_dst_ip_pkt_cnt_sec'] = same_ip_pkt_cnt
        target_parsed['same_dst_ip_port_pkt_cnt_sec'] = same_ip_port_pkt_cnt
    else:
        target_parsed['same_dst_ip_pkt_cnt_sec'] = 0
        target_parsed['same_dst_ip_port_pkt_cnt_sec'] = 0
    """
    pass


def _grasp_first_tcp_state_context(packet):
    tcp_level = dpkt.ethernet.Ethernet(packet).data.data
    ctrl_flag = tcp_level.flags

    if ctrl_flag & TH_SYN:
        if ctrl_flag & TH_ACK:  # SYN,ACK = S0->S1
            return 'S0'
        else:                   # SYN = INIT->S0
            return 'INIT'
    else:
        raise NotImplementedError


def _grasp_tcp_state_context(packet, prev_state, server_ip, client_ip):
    ether_level = dpkt.ethernet.Ethernet(packet)
    ip_level = ether_level.data
    tcp_level = ip_level.data
    ctrl_flag = tcp_level.flags

    if ether_level.type == ETH_TYPE_IP:
        src_ip = _convert_addr(ip_level.src, 'IPv4')
    elif ether_level.type == ETH_TYPE_IP6:
        src_ip = _convert_addr(ip_level.src, 'IPv6')
    else:
        raise NotImplementedError

    if prev_state == 'INIT':
        if ctrl_flag ^ TH_SYN == 0 and src_ip == client_ip:
            return 'S0'
        elif ctrl_flag ^ TH_SYN ^ TH_ACK == 0 and src_ip == server_ip:
            return 'S4'
        elif ctrl_flag ^ TH_FIN == 0 and src_ip == client_ip:
            return 'SH'
        else:
            return 'OTH'
    elif prev_state == 'S0':
        if ctrl_flag ^ TH_SYN ^ TH_ACK == 0 and src_ip == server_ip:
            return 'S1'
        elif ctrl_flag ^ TH_RST == 0 and src_ip == server_ip:
            return 'REJ'
        elif ctrl_flag ^ TH_RST == 0 and src_ip == client_ip:
            return 'RSTOS0'
        else:
            raise NotImplementedError
    elif prev_state == 'S1':
        if ctrl_flag ^ TH_ACK == 0 and src_ip == client_ip:
            return 'ESTAB'
        elif ctrl_flag ^ TH_RST == 0 and src_ip == client_ip:
            return 'RST0'
        elif ctrl_flag ^ TH_RST == 0 and src_ip == server_ip:
            return 'RSTR'
        else:
            raise NotImplementedError
    elif prev_state == 'ESTAB':
        if ctrl_flag ^ TH_RST == 0 and src_ip == client_ip:
            return 'RST0'
        elif ctrl_flag ^ TH_RST == 0 and src_ip == server_ip:
            return 'RSTR'
        elif ctrl_flag & TH_FIN and src_ip == client_ip:
            return 'S2'
        elif ctrl_flag & TH_FIN and src_ip == server_ip:
            return 'S3'
        else:
            return 'ESTAB'
    elif prev_state == 'S2':
        if ctrl_flag ^ TH_FIN ^ TH_ACK == 0 and src_ip == server_ip:
            return 'SF'
        elif ctrl_flag & TH_FIN and src_ip == server_ip:
            return 'S2F'
        else:
            raise NotImplementedError
    elif prev_state == 'S2F':
        if ctrl_flag & TH_ACK and src_ip == client_ip:
            return 'SF'
        else:
            raise NotImplementedError
    elif prev_state == 'S3':
        print(bin(ctrl_flag))
        if ctrl_flag ^ TH_FIN ^ TH_ACK == 0 and src_ip == client_ip:
            return 'SF'
        elif ctrl_flag & TH_FIN and src_ip == client_ip:
            return 'S3F'
        else:
            raise NotImplementedError
    elif prev_state == 'S3F':
        if ctrl_flag & TH_ACK and src_ip == server_ip:
            return 'SF'
        else:
            raise NotImplementedError
    elif prev_state == 'SF':
        if ctrl_flag & TH_ACK:
            return 'SF'
        else:
            raise NotImplementedError
    elif prev_state == 'S4':
        if ctrl_flag ^ TH_RST == 0 and src_ip == server_ip:
            return 'RSTRH'
        elif ctrl_flag ^ TH_FIN == 0 and src_ip == server_ip:
            return 'SHR'
        else:
            raise NotImplementedError
    else:
        raise NotImplementedError


def _extract_state_transition():
    tmp_host_state = dict()

    packet_parsed_list = zip(Packet_list, Parsed_list)
    for packet, parsed in packet_parsed_list:
        # Check if TCP packet
        # TODO - Add dummy state data for UDP or other protocols for being compatible
        if not (parsed['protocol_type'] == 'TCP'):
            continue

        src_ip = parsed['src_ip']
        src_port = dpkt.ethernet.Ethernet(packet).data.data.sport
        dst_ip = parsed['dst_ip']
        dst_port = dpkt.ethernet.Ethernet(packet).data.data.dport

        if src_ip < dst_ip:
            smaller = src_ip
            smaller_port = src_port
            bigger = dst_ip
            bigger_port = dst_port
        else:
            smaller = dst_ip
            smaller_port = dst_port
            bigger = src_ip
            bigger_port = src_port

        if not (smaller in tmp_host_state):
            tmp_host_state[smaller] = dict()
            tmp_host_state[smaller][smaller_port] = dict()
        if not (bigger in tmp_host_state[smaller][smaller_port]):
            tmp_host_state[smaller][smaller_port][bigger] = dict()
            first_state = _grasp_first_tcp_state_context(packet)
            tmp_host_state[smaller][smaller_port][bigger][bigger_port] = dict()
            tmp_host_state[smaller][smaller_port][bigger][bigger_port]['state'] = first_state

            if tmp_host_state[smaller][smaller_port][bigger][bigger_port]['state'] == 'INIT':
                tmp_host_state[smaller][smaller_port][bigger][bigger_port]['client_ip'] = src_ip
                tmp_host_state[smaller][smaller_port][bigger][bigger_port]['server_ip'] = dst_ip
            else:
                raise NotImplementedError

        server_ip = tmp_host_state[smaller][smaller_port][bigger][bigger_port]['server_ip']
        client_ip = tmp_host_state[smaller][smaller_port][bigger][bigger_port]['client_ip']
        prev_state = tmp_host_state[smaller][smaller_port][bigger][bigger_port]['state']
        curr_state = _grasp_tcp_state_context(packet, prev_state, server_ip, client_ip)

        parsed['tcp_state'] = (prev_state, curr_state)
        tmp_host_state[smaller][smaller_port][bigger][bigger_port]['state'] = curr_state
        # del tmp_host_state[smaller]

        # print(src_ip)
        # print(dst_ip)
    pass


def _extract_advanced_features():
    packet_parsed_list = zip(Packet_list, Parsed_list)
    packet_parsed_in_time_window_sec = list()

    time_window_sec_stat = dict()
    time_window_sec_stat['forward'] = dict()    # dict['forward'][IP]['port'][src_port] = int
                                            # dict['forward'][IP]['dst_IP'][IP][dst_port] = int
    time_window_sec_stat['backward'] = dict()    # dict['backward'][IP] = [src_IP1, src_IP2, ...]

    for packet, parsed in packet_parsed_list:
        _extract_time_window_features(time_window_sec_stat, packet, parsed)
        packet_parsed_in_time_window_sec.append((packet, parsed))

        head_ts = packet_parsed_in_time_window_sec[0][1]['timestamp']
        tail_ts = parsed['timestamp']
        while tail_ts - head_ts > TIME_WINDOW_SIZE_SEC:
            head_src_ip = packet_parsed_in_time_window_sec[0][1]['src_ip']
            head_dst_ip = packet_parsed_in_time_window_sec[0][1]['dst_ip']
            head_src_port = packet_parsed_in_time_window_sec[0][1]['src_port']
            head_dst_port = packet_parsed_in_time_window_sec[0][1]['dst_port']

            # Clean up Source info and Destination info from stat
            time_window_sec_stat['forward'][head_src_ip]['ports'][head_src_port] -= 1
            if time_window_sec_stat['forward'][head_src_ip]['ports'][head_src_port] <= 0:
                del time_window_sec_stat['forward'][head_src_ip]['ports'][head_src_port]

            time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip][head_dst_port] -= 1
            if time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip][head_dst_port] <= 0:
                del time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip][head_dst_port]

                if len(time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]) == 0:
                    del time_window_sec_stat['forward'][head_src_ip]['dst_ips'][head_dst_ip]

                    time_window_sec_stat['backward'][head_dst_ip].remove(head_src_ip)
                    if len(time_window_sec_stat['backward'][head_dst_ip]) == 0:
                        del time_window_sec_stat['backward'][head_dst_ip]

                    if len(time_window_sec_stat['forward'][head_src_ip]['dst_ips']) == 0:
                        assert len(time_window_sec_stat['forward'][head_src_ip]['ports']) == 0
                        del time_window_sec_stat['forward'][head_src_ip]

            # Clean up the head of the time window
            del packet_parsed_in_time_window_sec[0]
            head_ts = packet_parsed_in_time_window_sec[0][1]['timestamp']

        src_ip = parsed['src_ip']
        dst_ip = parsed['dst_ip']
        src_port = parsed['src_port']
        dst_port = parsed['dst_port']

        if src_ip not in time_window_sec_stat['forward']:
            time_window_sec_stat['forward'][src_ip] = dict()
            time_window_sec_stat['forward'][src_ip]['ports'] = dict()
            time_window_sec_stat['forward'][src_ip]['ports'][src_port] = 1
            time_window_sec_stat['forward'][src_ip]['dst_ips'] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip] = dict()
            time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip][dst_port] = 1
        else:
            if src_port not in time_window_sec_stat['forward'][src_ip]['ports']:
                time_window_sec_stat['forward'][src_ip]['ports'][src_port] = 1
            else:
                time_window_sec_stat['forward'][src_ip]['ports'][src_port] += 1

            if dst_ip not in time_window_sec_stat['forward'][src_ip]['dst_ips']:
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip] = dict()
                time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip][dst_port] = 1
            else:
                if dst_port not in time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip]:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip][dst_port] = 1
                else:
                    time_window_sec_stat['forward'][src_ip]['dst_ips'][dst_ip][dst_port] += 1
        if dst_ip not in time_window_sec_stat['backward']:
            time_window_sec_stat['backward'][dst_ip] = set()
        time_window_sec_stat['backward'][dst_ip].add(src_ip)

    del packet_parsed_in_time_window_sec
    # Not developed yet
    # _extract_state_transition()
    pass


def parse_file(read_instance):
    _extract_basic_features(read_instance)
    _extract_advanced_features()


read_pcap_instance = load_and_read_pcap(Src_file_name)
parse_file(read_pcap_instance)

packet_parsed_list = zip(Packet_list, Parsed_list)
for _, parsed in packet_parsed_list:
    print(parsed)
