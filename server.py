import socket

from builder import Builder, Record
from dns_parser import DNSParser
from resolver import Resolver

HOST = '127.0.0.1'
PORT = 53

def multiply(name: str) -> bytes | None:
    labels = name.lower().split('.')
    if 'multiply' not in labels[1:]:
        return None

    result = 1
    for label in labels[:labels.index('multiply')]:
        if label.isdigit():
            result *= int(label)
    return bytes([127, 0, 0, result % 256])

def handle(data: bytes) -> bytes:
    request = DNSParser(data)
    request.parse()

    rcode = 0
    answers: list[Record] = []
    authority: list[Record] = []

    ip = multiply(request.question_name)
    if ip is not None:
        if request.question_type == 1:
            answers = [{'name': request.question_name, 'type': 1, 'ttl': 0, 'data': ip, 'value': ''}]
    else:
        try:
            response = Resolver.resolve(request.question_name, request.question_type)
            if response is not None:
                rcode = response.rcode
                answers = response.answers
                authority = response.authority
        except Exception as e:
            print(e)

    if rcode != 3:
        rcode = 0

    flags = 0x8000 | (request.flags & 0x0100) | 0x0080 | rcode
    builder = Builder()
    return builder.build_response(request.id, flags, request.question_name, request.question_type,
                                  answers, authority)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST, PORT))
print(f'DNS server on {HOST}:{PORT}')

while True:
    try:
        data, address = s.recvfrom(4096)
        s.sendto(handle(data), address)
    except Exception as e:
        print(e)
