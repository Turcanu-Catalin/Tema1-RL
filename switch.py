#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

mac_table = {}
vlan_table = {} 
ports = {}
interfaces_vlan = {}

def is_unicast(addr):
    manageable = int(addr.split(':')[0], 16)
    return (manageable & 0x01) == 0

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def read_config(switch_id):
    file = f'configs/switch{switch_id}.cfg'
    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines[1:]:  
            parts = line.strip().split(' ')
            interface = parts[0]
            vlan_table[interface] = parts[1]

def create_stp_frame(root_bridge_id, root_path_cost, sender_bridge_id):
    bpdu_config = struct.pack('!QQQ', root_bridge_id, root_path_cost, sender_bridge_id)
    bdpu_header = struct.pack('!HBB', 0x0000, 0x00, 0x00)
    llc_header = struct.pack('!3s', b'\x42\x42\x03')
    length = len(bpdu_config) + len(bdpu_header) + len(llc_header)
    ethernet_header = struct.pack('!6s6sH', b'\x01\x80\xc2\x00\x00\x00', get_switch_mac(), length)
    frame = ethernet_header + llc_header + bdpu_header + bpdu_config
    length = len(frame)
    return frame, length

def parse_stp_frame(data):
    bdpu_padding = 14 + 4 + 3
    bdpu_config = data[bdpu_padding: bdpu_padding + 24]
    root_bridge_id, root_path_cost, sender_bridge_id = struct.unpack('!QQQ', bdpu_config)
    return root_bridge_id, root_path_cost, sender_bridge_id

def send_bdpu_every_sec():
        # TODO Send BDPU every second if necessary
        while True:
            if is_root:
                for i in interfaces:
                    if (vlan_table[get_interface_name(i)] == "T"):
                        frame , length = create_stp_frame(root_bridge_id, root_path_cost, switch_priority_value)
                        send_to_link(i, length, frame)
            time.sleep(1)


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    global interfaces
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    file = f'configs/switch{switch_id}.cfg'
    with open(file) as f:
        lines = f.readlines()

    global is_root
    global root_bridge_id
    global root_path_cost
    global root_path_cost
    global root_port
    global switch_priority_value
    is_root = True
    root_path_cost = 0
    switch_priority_value = int(lines[0].strip())
    root_bridge_id = switch_priority_value

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    read_config(switch_id)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))
        ports[i] = "DESIGNATED"

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        mac_table[src_mac] = interface
        interface_name = get_interface_name(interface)
        
        if dest_mac != "01:80:C2:00:00:00":
            if (vlan_table[interface_name] == "T"):
                data = data[:12] + data[16:]
                length -= 4
            else:
                vlan_id = int(vlan_table[interface_name])

        if is_unicast(dest_mac):
            if dest_mac in mac_table:
                dest_port = mac_table[dest_mac]
                if (vlan_table[get_interface_name(dest_port)] == "T"):
                    data = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                    #length += 4
                    send_to_link(dest_port, length + 4, data)
                else:
                    if (int(vlan_table[get_interface_name(dest_port)]) ==  vlan_id):
                        send_to_link(dest_port, length, data)

            else:
                for i in interfaces:
                    if i != interface:
                        if (vlan_table[get_interface_name(i)] == "T"):
                            data = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                            #length += 4
                            send_to_link(i, length + 4, data)
                        else:
                            if (int(vlan_table[get_interface_name(i)]) ==  vlan_id):
                                send_to_link(i, length, data)
                        
        else:
            if dest_mac != "01:80:C2:00:00:00":
                for i in interfaces:
                    if i != interface:
                        if (vlan_table[get_interface_name(i)] == "T"):
                            data = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                            #length += 4
                            send_to_link(i, length + 4, data)
                        else:
                            if (int(vlan_table[get_interface_name(i)]) ==  vlan_id):
                                send_to_link(i, length, data)
                   
        # TODO: Implement STP support
            else:
                bpdu_root_bridge_id, bpdu_root_path_cost, bdpu_sender_bridge_id = parse_stp_frame(data)
                if (bpdu_root_bridge_id < root_bridge_id):
                    root_bridge_id =  bpdu_root_bridge_id
                    root_path_cost = bpdu_root_path_cost + 10
                   
                    if root_port == None:
                        for port in ports:
                            if (vlan_table[get_interface_name(port)] == "T"):
                                ports[port] = "BLOCKING"
                        ports[interface] = "DESIGNATED"

                    root_port = interface

                    for i in interfaces:
                        if (i != interface):
                            if (vlan_table[get_interface_name(i)] == "T"):
                                frame , length = create_stp_frame(root_bridge_id, root_path_cost, switch_priority_value)
                                send_to_link(i, length, frame)
        
                else:
                    if (bpdu_root_bridge_id == root_bridge_id):
                        if (interface == root_port and bpdu_root_path_cost + 10 < root_path_cost):
                            root_path_cost = bpdu_root_path_cost + 10
                        else: 
                            if (interface != root_port and bpdu_root_path_cost > root_path_cost):
                                ports[interface] = "DESIGNATED"
                                

        if (root_bridge_id == switch_priority_value):
            is_root = True
            for port in ports:
                ports[port] = "DESIGNATED"
            root_port = None
            root_path_cost = 0
        else:
            is_root = False    

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
