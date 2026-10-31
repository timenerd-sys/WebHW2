import random
from typing import TypedDict


class Record(TypedDict):
    name: str
    type: int
    ttl: int
    data: bytes
    value: str


class Builder:
    def __init__(self):
        self.id: bytes = b''
        self.flags: bytes = b'\x00\x00'
        self.question: bytes = b''

    def build_query(self, name: str, qtype: int):
        self.id = random.randint(0, 65535).to_bytes(2, 'big')
        self.question = self.add_question(name, qtype)

        answer = b''
        answer += self.id
        answer += self.flags
        answer += b'\x00\x01'
        answer += b'\x00\x00'
        answer += b'\x00\x00'
        answer += b'\x00\x00'
        answer += self.question

        return answer


    def add_question(self, name: str, qtype: int):
        # имя + QTYPE + QCLASS = 1 (IN, других на практике нет)
        return self.add_name(name) + qtype.to_bytes(2, 'big') + b'\x00\x01'

    @staticmethod
    def add_name(name: str):
        answer = b''
        for label in name.split('.'):
            if len(label) == 0:
                continue
            answer += bytes([len(label)]) + label.encode()
        return answer + b'\x00'

    def build_response(self, request_id: bytes, flags: int, name: str, qtype: int,
                       answers: list[Record], authority: list[Record]):
        answer = b''
        answer += request_id
        answer += flags.to_bytes(2, 'big')
        answer += b'\x00\x01'
        answer += len(answers).to_bytes(2, 'big')
        answer += len(authority).to_bytes(2, 'big')
        answer += b'\x00\x00'
        answer += self.add_question(name, qtype)
        for record in answers + authority:
            answer += self.add_record(record)

        return answer

    def add_record(self, record: Record):
        answer = b''
        answer += self.add_name(record['name'])
        answer += record['type'].to_bytes(2, 'big')
        answer += b'\x00\x01'
        answer += record['ttl'].to_bytes(4, 'big')
        answer += len(record['data']).to_bytes(2, 'big')
        answer += record['data']
        return answer
