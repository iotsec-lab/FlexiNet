import os

import json

def get_features_json(file_path, feature_list):
    tshark_command = f"tshark -r {file_path} -T json "
    for fet in feature_list:
        tshark_command += f' -e {fet}'

    resp = os.popen(tshark_command).read()
    resp = resp.replace("\n", "")

    json_resp = json.loads(resp)
    return json_resp


def get_feture_packet_no_by_filter(file_path, filter):
    tshark_command = 'tshark -r ' + file_path + ' "' + filter + '"' + " | awk " + "'{print $1}'"
    count_packets = f'tshark -r {file_path} | wc -l'
    count_packets = os.popen(count_packets).read()
    count_packets = int(count_packets.replace('\n', ''))
    resp = os.popen(tshark_command).read()
    resp = resp.split("\n")
    resp.remove('')
   
    for i in range(len(resp)):
        resp[i] = int(resp[i])
    result = [0 for _ in range(count_packets)]
    for i in resp:
        if resp == '':
            continue
        
        result[int(i) - 1] = 1

    return result

def get_files_by_device_number(dev_no):
    files = []
    for sample_no in range(1, 23):
        current_file = f'dataset/IPMAC-{dev_no}-{sample_no}.pcap'
        if os.path.isfile(current_file):
            files.append(os.path.abspath(current_file))
    return files


