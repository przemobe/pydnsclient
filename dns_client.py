#!/usr/bin/env python3

#  Copyright 2022 Przemyslaw Bereski https://github.com/przemobe/

#  Python DNS Client
#  A simple DNS client similar to 'nslookup' or 'host'.
#  Does not use any DNS libraries.
#  Reference: RFC1035, RFC3596

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#


import sys
import socket
import struct  # For constructing and destructing the DNS packet.


DNS_RECORD_TYPE_A = 1  # a host address
DNS_RECORD_TYPE_NS = 2  # an authoritative name server
DNS_RECORD_TYPE_MD = 3  # a mail destination (Obsolete - use MX)
DNS_RECORD_TYPE_MF = 4  # a mail forwarder (Obsolete - use MX)
DNS_RECORD_TYPE_CNAME = 5  # the canonical name for an alias
DNS_RECORD_TYPE_SOA = 6  # marks the start of a zone of authority
DNS_RECORD_TYPE_MB = 7  # a mailbox domain name (EXPERIMENTAL)
DNS_RECORD_TYPE_MG = 8  # a mail group member (EXPERIMENTAL)
DNS_RECORD_TYPE_MR = 9  # a mail rename domain name (EXPERIMENTAL)
DNS_RECORD_TYPE_NULL = 10  # a null RR (EXPERIMENTAL)
DNS_RECORD_TYPE_WKS = 11  # a well known service description
DNS_RECORD_TYPE_PTR = 12  # a domain name pointer
DNS_RECORD_TYPE_HINFO = 13  # host information
DNS_RECORD_TYPE_MINFO = 14  # mailbox or mail list information
DNS_RECORD_TYPE_MX = 15  # mail exchange
DNS_RECORD_TYPE_TXT = 16  # text strings
DNS_RECORD_TYPE_AAAA = 28  # IP6 Address

DNS_CLASS_IN = 1  # the Internet
DNS_CLASS_CS = 2  # the CSNET class
DNS_CLASS_CH = 3  # the CHAOS class
DNS_CLASS_HS = 4  # Hesiod [Dyer 87]

DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMATERROR = 1
DNS_RCODE_SERVERFAILURE = 2
DNS_RCODE_NONEXISTENTDOMAIN = 3
DNS_RCODE_NOTIMPLEMENTED = 4
DNS_RCODE_REFUSED = 5

DNS_MSG_SIZEMAX = 512

DNS_MSG_HDR_FMT = '!HHHHHH'
DNS_MSG_HDR_SIZE = 12

DNS_MSG_HDR_FLAGS_QR = 0x8000 # query (0), response (1)
DNS_MSG_HDR_FLAGS_OP = 0x7800 # op. code
DNS_MSG_HDR_FLAGS_OP_QUERY = 0 << 11
DNS_MSG_HDR_FLAGS_OP_IQUERY = 1 << 11
DNS_MSG_HDR_FLAGS_OP_STATUS = 2 << 11
DNS_MSG_HDR_FLAGS_AA = 0x0400 # Authoritative Answer
DNS_MSG_HDR_FLAGS_TC = 0x0200 # TrunCation
DNS_MSG_HDR_FLAGS_RD = 0x0100 # Recursion Desired
DNS_MSG_HDR_FLAGS_RA = 0x0080 # Recursion Available
DNS_MSG_HDR_FLAGS_RC = 0x000F # Response code


def fill_query(tx_buff, host_name, identifier, q_type=DNS_RECORD_TYPE_A):
    tx_msg = memoryview(tx_buff)

    idx = 0

    # Header
    hdr_flags = DNS_MSG_HDR_FLAGS_OP_QUERY | DNS_MSG_HDR_FLAGS_RD
    hdr_qdcount = 1
    hdr_ancount = 0
    hdr_nscount = 0
    hdr_arcount = 0
    struct.pack_into(
        DNS_MSG_HDR_FMT,
        tx_msg,
        idx,
        identifier,
        hdr_flags,
        hdr_qdcount,
        hdr_ancount,
        hdr_nscount,
        hdr_arcount)
    idx += DNS_MSG_HDR_SIZE

    # Construct the QNAME:
    # size|label|size|label|size|...|label|0x00
    for label in host_name.split("."):
        label_bytes = label.strip().encode()
        label_len = len(label_bytes)
        tx_msg[idx] = label_len
        idx += 1
        tx_msg[idx: idx + label_len] = label_bytes
        idx += label_len
    tx_msg[idx] = 0
    idx += 1

    # QTYPE + QCLASS
    struct.pack_into('!HH', tx_msg, idx, q_type, DNS_CLASS_IN)
    idx += 4

    return idx


def process_name(data, idx):
    name_chunks = []
    while True:
        label_len = data[idx]
        idx += 1
        if 0xC0 == (label_len & 0xC0):
            pointer = ((label_len & 0x3F) << 8) | data[idx]
            idx += 1
            _, pname = process_name(data, pointer)
            name_chunks.append(pname)
            break  # after a pointer there is no more labels
        elif 0 != label_len:
            label = bytes(data[idx: idx + label_len]).decode()
            name_chunks.append(label)
            idx += label_len
        else:
            break  # 0 indicates last label
    return idx, '.'.join(n for n in name_chunks)


def process_response(rx_buff):
    rx_msg = memoryview(rx_buff)

    # Process Header
    hdr_id, hdr_flags, hdr_qdcount, hdr_ancount, hdr_nscount, hdr_arcount = struct.unpack_from(
        DNS_MSG_HDR_FMT, rx_msg)
    idx = DNS_MSG_HDR_SIZE
    #print('DBG header: id=0x{:04x} flags=0x{:04x} qd_cnt={} an_cnt={} ns_cnt={} ar_cnt={}'.format(hdr_id, hdr_flags, hdr_qdcount, hdr_ancount, hdr_nscount, hdr_arcount))
    response_code = hdr_flags & DNS_MSG_HDR_FLAGS_RC
    result = {'response_code': response_code}

    # Process Question section
    for q_idx in range(hdr_qdcount):
        idx, q_name = process_name(rx_msg, idx)
        q_type, q_class = struct.unpack_from('!HH', rx_msg, idx)
        idx += 4

    # Process Record sections
    for section_name, section_count in [
            ('answer', hdr_ancount), ('authority', hdr_nscount), ('additional', hdr_arcount)]:
        if section_count:
            result[section_name] = []

        for elem_idx in range(section_count):
            idx, rr_name = process_name(rx_msg, idx)
            rr_type, rr_class, rr_ttl, rr_rd_length = struct.unpack_from(
                '!HHIH', rx_msg, idx)
            idx += 10
            rr_data = rx_msg[idx: idx + rr_rd_length]
            idx += rr_rd_length
            result[section_name].append(
                {'name': rr_name, 'type': rr_type, 'class': rr_class, 'ttl': rr_ttl})
            if DNS_RECORD_TYPE_A == rr_type:
                result[section_name][-1]['ip'] = '.'.join(
                    '{}'.format(c) for c in rr_data)
            elif DNS_RECORD_TYPE_AAAA == rr_type:
                result[section_name][-1]['ip6'] = ':'.join(
                    '{:x}'.format(c) for c in struct.unpack_from('!8H', rr_data))
            else:
                result[section_name][-1]['data'] = bytes(rr_data)

    return result


def decode_response_code(rcode):
    if DNS_RCODE_NOERROR == rcode:
        return 'No Error'
    elif DNS_RCODE_FORMATERROR == rcode:
        return 'Format Error'
    elif DNS_RCODE_SERVERFAILURE == rcode:
        return 'Server Failure'
    elif DNS_RCODE_NONEXISTENTDOMAIN == rcode:
        return 'Non-Existent Domain'
    elif DNS_RCODE_NOTIMPLEMENTED == rcode:
        return 'Not Implemented'
    elif DNS_RCODE_REFUSED == rcode:
        return 'Query Refused'
    else:
        return 'Unknown Error Code({})'.format(rcode)


def resolve_host_name(host_name, dns_ip='8.8.8.8', dns_port=53, q_type=DNS_RECORD_TYPE_A):
    # Queries the DNS A record for the given host name and returns the result.

    tx_buff = bytearray(DNS_MSG_SIZEMAX)
    tx_msg = memoryview(tx_buff)
    tx_len = fill_query(tx_buff, host_name, 0xa1b2, q_type)

    # Send the packet off to the server.
    dns_address = (dns_ip, dns_port)  # Tuple needed by sendto.
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.

    # Send the DNS packet to the server using the port.
    client.sendto(tx_msg[0:tx_len], dns_address)
    #print('DBG tx: ', ":".join("{:02x}".format(ord(chr(c))) for c in tx_msg[0:tx_len]))

    # Get the response DNS packet back.
    rx_buff, address = client.recvfrom(DNS_MSG_SIZEMAX)
    #print('DBG rx: ', ":".join("{:02x}".format(c) for c in rx_buff))

    ret = process_response(rx_buff)
    return ret


if __name__ == "__main__":
    # Get the host name from the command line.

    if len(sys.argv) < 2:
        print("No host name specified.")
        sys.exit(0)

    dns_ip = "8.8.8.8"
    if len(sys.argv) > 2:
        dns_ip = sys.argv[2]

    host_name = sys.argv[1]

    result = resolve_host_name(host_name, dns_ip, q_type=DNS_RECORD_TYPE_A)

    print("\nServer IP:", dns_ip)
    print("Response: ", decode_response_code(result['response_code']))

    for section_name in ['answer', 'authority', 'additional']:
        if section_name in result:
            print(section_name + ':')
            for ans in result[section_name]:
                print(ans)
