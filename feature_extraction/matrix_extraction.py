from .features_filter import *
from .packet_process import *
from .utils import *

def _extract_and_process_features_internal(file, features):
    feature_json = get_features_json(file_path=file, feature_list=features)
    feature_value_array = extract_packet_layer_values(feature_json)
    return feature_value_array


def get_arp_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_arp_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_llc_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_llc_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]


def get_ip_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_ip_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_icmp_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_icmp_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]


def get_icmpv6_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_icmpv6_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_eapol_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_eapol_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_tcp_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_tcp_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_udp_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_udp_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_http_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_http_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_tls_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_tls_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_dhcp_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_dhcp_protocol_feature_list()
    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_bootp_matrix(file, max_packet_analyze):
    # feature = get_tshark_valid_bootp_protocol_feature_list()
    # feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    # return feature_value_array[:max_packet_analyze]
    return get_feture_packet_no_by_filter(file, "udp.port eq 67 or udp.port eq 68")[:max_packet_analyze]

def get_ntp_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_ntp_protocol_feature_list()

    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_mmdns_matrix(file, max_packet_analyze):
    return get_feture_packet_no_by_filter(file, "dns and udp.port eq 5353")[:max_packet_analyze]

def get_ip_option_padding_matrix(file, max_packet_analyze):
    feature = get_ip_option_padding_feature_list()

    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_ip_option_router_alert_matrix(file, max_packet_analyze):
    feature = get_ip_option_router_alert_feature_list()

    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]

def get_packet_size_matrix(file, max_packet_analyze):
    tshark_command = f'tshark -r {file} -T fields -e frame.len'

    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    resp.remove('')
   
    for i in range(len(resp)):
        resp[i] = int(resp[i])
    
    return resp[:max_packet_analyze]


def get_raw_data_matrix(file, max_packet_analyze):
    tshark_command = f'tshark -r {file} -T fields -e data'

    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    result = []
    for i in range(len(resp)):
        if resp[i] == '':
            result.append(0)
        else:
            result.append(1)
    
    return result[:max_packet_analyze]

def get_destination_ip_count(file, max_packet_analyze):

    tshark_command = f'tshark -r {file} -T fields -e ip.dst'

    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    result = []
    dst_ips = []
    for i in range(max_packet_analyze):
        if resp[i] != '':
            dst_ips.append(resp[i])
       
        result.append(len(set(dst_ips)))
    
    return result[:max_packet_analyze]

def get_src_port_class(file, max_packet_analyze):
    ports = []

    # tcp ports
    tshark_command = f'tshark -r {file} -T fields -e tcp.srcport'
    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    for i in range(max_packet_analyze):
        ports.append(resp[i])

    # udp ports
    tshark_command = f'tshark -r {file} -T fields -e udp.srcport'
    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    for i in range(max_packet_analyze):
        ports[i] = resp[i]

    for i in range(len(ports)):
        current_port = ports[i]

        # get class
        if current_port == '':
            ports[i] = 0
        elif 0 <= int(current_port) <= 1023:
            ports[i] = 1
        elif 1024 <= int(current_port) <= 49151:
            ports[i] = 2
        elif 49152 <= int(current_port) <= 65535:
            ports[i] = 3
       

    return ports


def get_dst_port_class(file, max_packet_analyze):
    ports = []

    # tcp ports
    tshark_command = f'tshark -r {file} -T fields -e tcp.dstport'
    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    for i in range(max_packet_analyze):
        ports.append(resp[i])

    # udp ports
    tshark_command = f'tshark -r {file} -T fields -e udp.dstport'
    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    for i in range(max_packet_analyze):
        ports[i] = resp[i]

    for i in range(len(ports)):
        current_port = ports[i]

        # get class
        if current_port == '':
            ports[i] = 0
        elif 0 <= int(current_port) <= 1023:
            ports[i] = 1
        elif 1024 <= int(current_port) <= 49151:
            ports[i] = 2
        elif 49152 <= int(current_port) <= 65535:
            ports[i] = 3
       

    return ports

def get_ssdp_matrix(file, max_packet_analyze):
    return get_feture_packet_no_by_filter(file, "udp.dstport eq 1900")[:max_packet_analyze]


def get_dns_matrix(file, max_packet_analyze):
    feature = get_tshark_valid_dns_protocol_feature_list()

    feature_value_array = _extract_and_process_features_internal(file=file, features=feature)
    return feature_value_array[:max_packet_analyze]