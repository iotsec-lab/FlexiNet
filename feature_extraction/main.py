from .utils import *
from .features_filter import *
from .packet_process import *
from .matrix_extraction import *
import random
import time
import csv
from multiprocessing import Process
import pandas as pd
import numpy as np

import glob

# max_packet_analyze = 12


row_header = ["arp", "llc", "ip", "icmp", "icmpv6", "eapol", "tcp", "udp", "http", "https", "dhcp", "bootp", "ssdp", "dns", "mdns", "ntp", "padding", "router_alert", "size", "raw_data", "destination_ip_counter", "source", "destination"]
def prepare_feature_matrix(file, max_packet_analyze):
    # ARP
    arp_matrix = get_arp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    llc_matrix = get_llc_matrix(file=file, max_packet_analyze=max_packet_analyze)
    ip_matrix = get_ip_matrix(file=file, max_packet_analyze=max_packet_analyze)
    icmp_matrix = get_icmp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    icmpv6_matrix = get_icmpv6_matrix(file=file, max_packet_analyze=max_packet_analyze)
    eapol_matrix = get_eapol_matrix(file=file, max_packet_analyze=max_packet_analyze)
    udp_matrix = get_udp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    http_matrix = get_http_matrix(file=file, max_packet_analyze=max_packet_analyze)
    https_matrix = get_tls_matrix(file=file, max_packet_analyze=max_packet_analyze)
    dhcp_matrix = get_dhcp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    bootp_matrix = get_bootp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    ntp_matrix = get_ntp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    mdns_matrix = get_mmdns_matrix(file=file, max_packet_analyze=max_packet_analyze)
    ip_option_paddding_matrix = get_ip_option_padding_matrix(file=file, max_packet_analyze=max_packet_analyze)
    ip_option_router_alert_matrix = get_ip_option_router_alert_matrix(file=file, max_packet_analyze=max_packet_analyze)
    packet_size_matrix = get_packet_size_matrix(file=file, max_packet_analyze=max_packet_analyze)
    raw_data_matrix = get_raw_data_matrix(file=file, max_packet_analyze=max_packet_analyze)
    destination_ip_count = get_destination_ip_count(file=file, max_packet_analyze=max_packet_analyze)
    src_port_class = get_src_port_class(file=file, max_packet_analyze=max_packet_analyze)
    dst_port_class = get_dst_port_class(file=file, max_packet_analyze=max_packet_analyze)
    ssdp_matrix = get_ssdp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    dns_matrix = get_dns_matrix(file=file, max_packet_analyze=max_packet_analyze)
    tcp_matrix = get_tcp_matrix(file=file, max_packet_analyze=max_packet_analyze)
    return [
        arp_matrix,
        llc_matrix,
        ip_matrix,
        icmp_matrix,
        icmpv6_matrix,
        eapol_matrix,
        tcp_matrix,
        udp_matrix,
        http_matrix,
        https_matrix,
        dhcp_matrix,
        bootp_matrix,
        ssdp_matrix,
        dns_matrix,
        mdns_matrix,
        ntp_matrix,
        ip_option_paddding_matrix,
        ip_option_router_alert_matrix,
        packet_size_matrix,
        raw_data_matrix,
        destination_ip_count,
        src_port_class,
        dst_port_class
    ]

    # print("ARP")
    # print(arp_matrix)
    # print(llc_matrix)
    # print(ip_matrix)
    # print(icmp_matrix)
    # print(icmpv6_matrix)
    # print(eapol_matrix)
    # print(udp_matrix)
    # print(http_matrix)
    # print(https_matrix)
    # print(dhcp_matrix)
    # print(bootp_matrix)
    # print(ntp_matrix)
    # print(mdns_matrix)
    # print(ip_option_paddding_matrix)
    # print(ip_option_router_alert_matrix)
    # print(packet_size_matrix)
    # print(raw_data_matrix)
    # print(destination_ip_count)
    # print(src_port_class)
    # print(dst_port_class)
    # print(ssdp_matrix)
    # print(dns_matrix)

# def write_row_to_column(csv_writer, mat):
#     for row in mat:


class IoTSentinelDataset:
    
    def __init__(self, max_packet_analyze=12, device_list=[i for i in range(1, 32)], train_test_split_ratio=0.8, location="F"):
        self.max_packet_analyze = max_packet_analyze
        self.device_list = device_list
        self.device_pcap_mapping = dict()
        self.train_test_split_ratio=train_test_split_ratio
        self.location = location
    
    def load(self):
        for device in self.device_list:
            device_pcaps = get_files_by_device_number(device)
            self.device_pcap_mapping[device] = device_pcaps
    
    def shuffle(self):
        for key in self.device_pcap_mapping:
            random.shuffle(self.device_pcap_mapping[key])
        
    def get_train_X_y(self):
        train_x = []
        train_y = []
        for dev in self.device_list:
            path = os.path.abspath("iotsentinel/matrix/train")
            
            current_dev_files = glob.glob(f'{path}/{dev}_*.csv')
            # print(f'{path}/{dev}_*.csv')

            for file in current_dev_files:
                df = pd.read_csv(file)
                df_list = df.values.tolist()
                df_list_flatten = list(np.concatenate(df_list).flat)
                train_x.append(df_list_flatten)
                train_y.append(dev)
        
        return train_x, train_y



        

    def generate_all_matrix(self):

        print(self.device_pcap_mapping)
        for dev in self.device_pcap_mapping:
            current_device_pcaps = self.device_pcap_mapping[dev]

            no_of_train_x = len(current_device_pcaps)
           
            start_time = time.time()
            
            # Extract F
            
            for i in range(no_of_train_x):
                print("iter no ", i)
                mat = prepare_feature_matrix(current_device_pcaps[i])
                print(mat)
                csv_train_file = open(f'iotsentinel/matrix/F/{dev}_{i+1}.csv', 'w')
                csv_train_writer = csv.writer(csv_train_file)
                csv_train_writer.writerow(row_header)
                
                rows = list(map(list, zip(*mat)))
                # rows = zip(mat)
                for row in rows:
                    csv_train_writer.writerow(row)
                
                csv_train_file.close()
     
            
            # Extract test
            print("test extract")
            cnt = 1
            for i in range(no_of_train_x, no_of_train_x):

                print("iter no ", i)
                mat = prepare_feature_matrix(current_device_pcaps[i], self.max_packet_analyze)
                # print(mat)
                csv_train_file = open(f'iotsentinel/matrix/F_prime/{dev}_{cnt}.csv', 'w')
                csv_train_writer = csv.writer(csv_train_file)
                csv_train_writer.writerow(row_header)
                
                rows = list(map(list, zip(*mat)))
                # rows = zip(mat)
                for row in rows:
                    csv_train_writer.writerow(row)
                
                csv_train_file.close()
                cnt += 1


            # csv_train_writer.wer
            print("--- Dev %s took %s seconds ---" % (dev, time.time() - start_time))
            


        


def gen_matrix(device_no):
    dset = IoTSentinelDataset(device_list = [device_no], train_test_split_ratio=1.0)
    dset.load()
    dset.shuffle()
    dset.generate_all_matrix()


# def main():
#     dset = IoTSentinelDataset(device_list = [i for i in range(1, 32)])
#     X, y = dset.get_train_X_y()

#     print(len(X), len(y))
    # processes = []
    # for i in range(1, 32):
    #     p = Process(target=gen_matrix, args=(i,))
    #     processes.append(p)
    #     p.start()
    
    # for p in processes:
    #     p.join()

    

    # dset = IoTSentinelDataset(device_list = [i for i in range(10, 31)])
    # dset.load()
    # dset.shuffle()
    # dset.get_train_x_y()
 
    

    # dev_one_files = get_files_by_device_number(1)
    # # feature_json = get_features_json(file_path=dev_one_files[0], feature_list=get_tshark_valid_arp_protocol_feature_list())
    # # print(extract_packet_layer_values(feature_json))

    # prepare_feature_matrix(dev_one_files[0])
    # print(get_feture_packet_no_by_filter(dev_one_files[0], "arp", 12))






# main()