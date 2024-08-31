def extract_packet_layer_values(json_data):
    packet_no = 1
    extracted_data = []
    for d in json_data:
        # try:
        current_data = []
        current_data.append(packet_no)
    
                
        val = d.get('_source', None).get('layers')
        extracted_data.append(int(bool(val)))

        packet_no += 1
    return extracted_data



def get_feature_vector_numeric(max_packet, value_array):
    result = []
    for i in range(max_packet):
        current_row = value_array[i]
        current_result = 0
        for i in range(1, len(current_row)):
            if current_row[i] > 0:
                current_result = 1
                break
        
        result.append(current_result)
    
    return result
