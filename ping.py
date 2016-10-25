"""
    A pure python ping implementation.
	Must be run with root/administrator privileges.

    Some snippets are from:
        https://github.com/samuel/python-ping/blob/master/ping.py
        http://www.binarytides.com/raw-socket-programming-in-python-linux

    RFC791/RFC3260 IP-Header:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |   DSCP    |ECN|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    RFC792 ICMP Echo-Request/Reply:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-


    Example Windows: ping -n 10 ietf.org

    Pinging ietf.org [4.31.198.44] with 32 bytes of data:
    Reply from 4.31.198.44: bytes=32 time=198ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=198ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=326ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=194ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=193ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=193ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=198ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=194ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=195ms TTL=57
    Reply from 4.31.198.44: bytes=32 time=197ms TTL=57

    Ping statistics for 4.31.198.44:
        Packets: Sent = 10, Received = 10, Lost = 0 (0% loss),
    Approximate round trip times in milli-seconds:
        Minimum = 193ms, Maximum = 326ms, Average = 208ms
"""
import argparse
import collections
import os
import select
import socket
import struct
import time


IPHeader = collections.namedtuple("IPHeader", ["ver", "ihl", "ttl", "proto", "src", "dst"])
ICMPHeader = collections.namedtuple("ICMPHeader", ["type", "code", "checksum", "id", "seq", "payload"])
PingResult = collections.namedtuple("PingResult",
                                    ["send", "received", "lost", "loss_per", "min", "max", "avg", "raw_times"])

DEFAULT_COUNT = 5
DEFAULT_TIMEOUT = 2
DEFAULT_PAYLOAD_SIZE = 32


def checksum(data) -> int:
    """
    Found on: http://www.binarytides.com/raw-socket-programming-in-python-linux/. Modified to work in python 3.
    The checksum is the 16-bit ones's complement of the one's complement sum
    of the ICMP message starting with the ICMP Type (RFC 792).

    :param data: data to built checksum from.
    :return: 16-bit int checksum
    """
    s = 0
    for i in range(0, len(data), 2):
        tmp = data[i]
        if i + 1 < len(data):
            tmp += (data[i + 1] << 8)
        s += tmp
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    s = ~s & 0xffff
    return s


def make_icmp_packet(*, p_id: int=0, p_seq: int=0, payload_size: int=DEFAULT_PAYLOAD_SIZE):
    """
    Builds a ICMP Echo-Request packet according to RFC 792.

    :param p_id: id of packet (default: 0)
    :param p_seq: sequence number of packet (default: 0)
    :param payload_size: size of payload
    :return: a ICMP packet represented as byte string
    """
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = p_id
    icmp_seq = p_seq

    tmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    # payl_size = payload_size + (payload_size % 2)
    payload = []
    for i in range(payload_size):
        payload.append(i & 0xFF)
    payload = bytes(payload)

    icmp_checksum = socket.htons(checksum(tmp_header + payload))
    header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    packet = header + payload

    return packet


def unpack_icmp_packet(packet, debug: bool) -> (IPHeader, ICMPHeader):
    """
    Takes a byte string representing a ip/ICMP packet and splits it into its values.

    :param packet: byte string of ip/ICMP packet.
    :param debug: print extra info about received packets.
    :return: a IPHeader (["ver", "ihl", "ttl", "proto", "src", "dst"])
             and ICMPHeader (["type", "code", "checksum", "id", "seq", "payload"]) tuple.
    """
    ip_header = packet[:20]
    ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header)

    tmp_ihl = ip_header[0]
    ip_version = tmp_ihl >> 4
    ip_ihl = tmp_ihl & 0xF

    ip_packet_length = ip_ihl * 4

    ip_ttl = ip_header[5]
    ip_protocol = ip_header[6]
    ip_src = socket.inet_ntoa(ip_header[8])
    ip_dst = socket.inet_ntoa(ip_header[9])

    ip_header = IPHeader(ip_version, ip_ihl, ip_ttl, ip_protocol, ip_src, ip_dst)

    icmp_header = packet[ip_packet_length:ip_packet_length + 8]
    icmp_header = struct.unpack("!BBHHH", icmp_header)
    icmp_type = icmp_header[0]
    icmp_code = icmp_header[1]
    icmp_checksum = socket.htons(icmp_header[2])
    icmp_id = icmp_header[3]
    icmp_seq = icmp_header[4]
    icmp_payload = packet[ip_packet_length + 8:]

    icmp_header = ICMPHeader(icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq, icmp_payload)

    if debug:
        print("Version: {} |IP-Header-Len: {} |TTL: {} |Protocol: {} |SRC-IP: {} |DST-IP: {}".format(
            str(ip_version), str(ip_ihl), str(ip_ttl), str(ip_protocol), str(ip_src), str(ip_dst))
        )
        print("Type: {} |Code: {} |Checksum: {} |ID: {} |SEQ: {} |Data: {}".format(
            str(icmp_type), str(icmp_code), str(icmp_checksum), str(icmp_id), str(icmp_seq), str(icmp_payload))
        )

    return ip_header, icmp_header


def send_one_ping(socket_: socket.socket, host: str, *, packet_id: int=0,
                  packet_seq: int=0, payload_size: int=DEFAULT_PAYLOAD_SIZE):
    """
    Sends one ICMP packet to the specified host.

    :param socket_: socket to send packet.
    :param host: address to send packet to.
    :param packet_id: id of ICMP packet.
    :param packet_seq: sequence nr. of ICMP packet.
    :param payload_size: size of ICMP payload.
    :return: timestamp of transmission (time.perf_counter()) or None.
    """
    packet = make_icmp_packet(p_id=packet_id, p_seq=packet_seq, payload_size=payload_size)

    socket_.sendto(packet, (host, 1))
    send_time = time.perf_counter()

    return send_time


def receive_one_ping(socket_: socket.socket, packet_id: int, packet_seq: int, timeout: float, debug: bool):
    """
    Waits for ICMP packet and then checks if it is valid. Checks as long as packet is not valid and timeout is left.

    :param socket_: socket to listen on.
    :param packet_id: expected ICMP packet id.
    :param packet_seq: expected ICMP packet sequence number.
    :param timeout: how long to look for packets.
    :param debug: print extra info about received packets.
    :return: timestamp of receipt (time.perf_counter()) or None.
    """
    time_left = timeout

    while True:
        started_select = time.perf_counter()
        tmp = select.select([socket_], [], [], time_left)
        sek_in_select = time.perf_counter() - started_select
        if not tmp[0]:
            return None, 0, 0, 0

        start_receive = time.perf_counter()

        rec_packet, addr = socket_.recvfrom(2048)

        ip_header, icmp_header = unpack_icmp_packet(rec_packet, debug)

        if icmp_header.id == packet_id and icmp_header.seq == packet_seq and icmp_header.code == icmp_header.type == 0:
            return start_receive, len(icmp_header.payload), ip_header.src, ip_header.ttl

        time_left -= sek_in_select
        if time_left <= 0:
            return None, 0, 0, 0


def ping(host: str, *, payload_size: int=DEFAULT_PAYLOAD_SIZE, count: int=DEFAULT_COUNT,
         timeout: float=DEFAULT_TIMEOUT, quiet: bool=False, debug: bool=False) -> PingResult:
    """
    Pings specified host for count amount of times and if not quiet prints results.

    :param host: host to ping.
    :param payload_size: size of ICMP packet payload.
    :param count: amount of times to ping.
    :param timeout: how long to wait for each response.
    :param quiet: if False prints results.
    :param debug: print extra info about received packets.
    :return: PingResults (["send", "received", "lost", "loss_per", "min", "max", "avg", "raw_times"])
    """
    if count <= 0:
        print("Count must be greater then 0")
        return

    socket_ = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    id_ = os.getpid() & 0xFFFF
    times = []

    fqdn = socket.getfqdn(host)
    ip = socket.gethostbyname(host)

    if not quiet:
        print("Pinging %s [%s] with %i bytes of data:" % (host, "/".join([fqdn, ip]), payload_size))

    for x in range(count):
        send_time = send_one_ping(socket_, host, packet_id=id_, packet_seq=x, payload_size=payload_size)

        if send_time is None:
            return

        receive, receive_payload_size, receive_ip_src, receive_ttl = receive_one_ping(socket_, id_, x, timeout, debug)

        if receive:
            rtt = (receive - send_time) * 1000
            if not quiet:
                send_payload = " (sent %i)" % payload_size if payload_size != receive_payload_size else ""
                print("%i bytes%s from %s: icmp_seq=%i ttl=%i time=%0.2fms" % (
                    receive_payload_size, send_payload, str(receive_ip_src), x, receive_ttl, rtt))
            times.append(rtt)
        else:
            if not quiet:
                print("Error: Packet [%i/%i] timed out!" % (id_, x))
            times.append(None)

    received_times = [x for x in times if x is not None]
    nr_received = len(received_times)
    nr_dropped = count - nr_received
    loss_perc = (nr_dropped * 100) / count

    if nr_received > 0:
        min_rtt = min(received_times)
        max_rtt = max(received_times)
        avg_rtt = sum(received_times) / nr_received
    else:
        min_rtt = max_rtt = avg_rtt = 0

    if not quiet:
        print("\nPing statistics for %s:\n\tPackets: Sent = %i, Received = %i, Lost = %i (%0.0f%% loss),"
              % (ip, count, nr_received, nr_dropped, loss_perc))
        print("Approximate round trip times in milli-seconds:\n\tMin = %0.2fms, Max = %0.2fms, Average = %0.2fms"
              % (min_rtt, max_rtt, avg_rtt))

    return PingResult(count, nr_received, nr_dropped, loss_perc, min_rtt, max_rtt, avg_rtt, times)


def main():
    parser = argparse.ArgumentParser(description="A implementation of ping in python")
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='don\'t print to console')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='print extra info about received packets')
    parser.add_argument('-c', '--count', type=int, default=DEFAULT_COUNT,
                        help=('number of packets to be sent '
                              '(default: %(default)s)'))
    parser.add_argument('-t', '--timeout', type=float, default=DEFAULT_TIMEOUT,
                        help=('time to wait for a response in seconds '
                              '(default: %(default)s)'))
    parser.add_argument('-s', '--payload-size', type=int, default=DEFAULT_PAYLOAD_SIZE,
                        help=('number of data bytes to be sent, should be even '
                              '(default: %(default)s)'))
    parser.add_argument('target_name')
    args = parser.parse_args()

    try:
        ping(args.target_name, payload_size=args.payload_size, count=args.count,
             timeout=args.timeout, quiet=args.quiet, debug=args.debug)
    except socket.gaierror as e:
        print("Unknown Host %s - aborted [%s]" % (args.target_name, e.args[1]))
    except socket.error as e:
        print("Error during sending - aborted [%s]" % e.args[1])


if __name__ == '__main__':
    main()
