import dpkt

"""
Src_file_name = 'D:\\tasks\\Projects\\KISA IoT 2년차 (2019년 1월 ~)' \
                '\\네트워크패킷수집\\EZVIZ_dump_from_n604s\\refresh.pcap'
"""
Src_file_name = 'D:\\VM\\shared\\00_frag_udp.pcapng'
# Src_file_name = 'D:\\VM\\shared\\00_frag.pcapng'
Packet_parsed_list = list()

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

Feature_list = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 'serror_rate',
                'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'dst_host_count',
                'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

Symbol_fields = ['protocol_type', 'service', 'flag']
Field_symbol = dict()
Field_symbol['protocol_type'] = ['tcp', 'udp', 'icmp']
Field_symbol['service'] = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain',
                          'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data',
                          'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001',
                          'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp',
                          'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp',
                          'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i',
                          'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat',
                          'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet',
                          'whois', 'X11', 'Z39_50']
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

    """
    for ts, buf in read_instance:
        new_dict = dict()
        new_dict['ts'] = ts
        new_dict['pkt'] = buf
        Packet_list.append(new_dict)
    """
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
    except:
        result = ip_packet.data.__len__()

    return result


def _get_past_2_seconds(curr_time):
    pass


def _reassemble_packet(frag_id):
    assembled_packet = None
    for frag in Fragment_buffer[frag_id]['packets']:
        if assembled_packet is None:
            assembled_packet = bytes(frag)
        else:
            assembled_packet += bytes(dpkt.ethernet.Ethernet(frag).data.data)

    tmp_assembled_packet = dpkt.ethernet.Ethernet(assembled_packet)
    print(tmp_assembled_packet)
    print(tmp_assembled_packet.data)

    # ip_level.data.len = bytes(Fragment_buffer[frag_id]['tot_len'] + ip_level.data.hl * 4)

    Fragment_buffer[frag_id]['reassembled'] = assembled_packet


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
            assert(ip_level.len - ip_level.hl * 4 == ip_level.data.__len__())
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
    global Packet_parsed_list

    packet_idx = 0
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
            converted_src_addr = _convert_addr(ip_level.src, 'IPv4')
            converted_dst_addr = _convert_addr(ip_level.dst, 'IPv4')
        elif ether_level.type == ETH_TYPE_IP6:
            converted_src_addr = _convert_addr(ip_level.src, 'IPv6')
            converted_dst_addr = _convert_addr(ip_level.dst, 'IPv6')
        else:
            print("### Warning - this packet is not an IP packet. ###")
            print("\tIndex: %d" % packet_idx)
            print("\tEthernet type: 0x%04x" % ether_level.type)
            continue

        protocol_type = _extract_protocol_type(ip_level)
        service = _extract_service()
        ctrl_flag = _extract_ctrl_flag(ip_level)
        num_of_frags = _get_num_of_frags(ip_level)
        if num_of_frags > 0:    # Fragmentation
            tl_data_len = Fragment_buffer[ip_level.id]['tot_len']
            whole_packet = Fragment_buffer[ip_level.id]['reassembled']
            del Fragment_buffer[ip_level.id]
        else:                   # Not Fragmentation
            tl_data_len = _extract_transport_layer_data_len(ip_level)
            whole_packet = buf

        # print(whole_packet)
        # print(len(whole_packet))
        new_dict_features['idx'] = packet_idx
        # new_dict_features['timestamp'] = ts
        # new_dict_features['src_addr'] = converted_src_addr
        # new_dict_features['dst_addr'] = converted_dst_addr

        new_dict_features['protocol_type'] = protocol_type
        new_dict_features['tl_data_len'] = tl_data_len
        new_dict_features['service'] = service
        new_dict_features['flag'] = ctrl_flag

        new_dict_features['num_of_frags'] = num_of_frags

        new_packet_parsed = dict()
        new_packet_parsed['ts'] = ts
        new_packet_parsed['packet'] = whole_packet
        new_packet_parsed['parsed'] = new_dict_features
        Packet_parsed_list.append(new_packet_parsed)


def _extract_tcp_state():
    return 'None', "None"


def _extract_advanced_features():
    global Packet_parsed_list

    for single_dict in Packet_parsed_list:
        ts = single_dict['ts']
        packet = single_dict['packet']
        parsed = single_dict['parsed']

        print(dpkt.ethernet.Ethernet(packet))

        # ether_level = dpkt.ethernet.Ethernet(packet)
        # print(ether_level.data)
        # ip_level = ether_level.data
        # print(ip_level.data)

        """
        new_dict_features = dict()
        prev_state, curr_state = _extract_tcp_state()
        new_dict_features['curr_state'] = curr_state
        """
        pass


def parse_file(read_instance):
    _extract_basic_features(read_instance)
    _extract_advanced_features()


read_instance = load_and_read_pcap(Src_file_name)
parse_file(read_instance)

for single_dict in Packet_parsed_list:
    print(single_dict['parsed'])
