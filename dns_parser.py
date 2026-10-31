from builder import Builder, Record


class DNSParser:
    def __init__(self, data: bytes):
        self.data: bytes = data
        self.position: int = 0

        self.id: bytes = b''
        self.flags: int = 0
        self.rcode: int = 0
        self.counts: list[int] = []
        self.question_name: str = ''
        self.question_type: int = 0

        self.answers: list[Record] = []
        self.authority: list[Record] = []
        self.additional: list[Record] = []

    def parse(self) -> None:
        self.read_header()
        self.read_question()
        self.answers = self.read_records(self.counts[1])
        self.authority = self.read_records(self.counts[2])
        self.additional = self.read_records(self.counts[3])

    def read_header(self) -> None:
        self.id = self.data[0:2]
        self.flags = int.from_bytes(self.data[2:4], 'big')
        self.rcode = self.flags & 0x0F
        for i in range(4):
            self.counts.append(int.from_bytes(self.data[4 + 2 * i:6 + 2 * i], 'big'))
        self.position = 12

    def read_question(self) -> None:
        self.question_name, self.position = self.read_name(self.position)
        self.question_type = int.from_bytes(self.data[self.position:self.position + 2], 'big')
        self.position += 4

    def read_records(self, count: int) -> list[Record]:
        records: list[Record] = []
        for i in range(count):
            records.append(self.read_record())
        return records

    def read_record(self) -> Record:
        name, self.position = self.read_name(self.position)
        record_type = int.from_bytes(self.data[self.position:self.position + 2], 'big')
        # пропускаем класс
        ttl = int.from_bytes(self.data[self.position + 4:self.position + 8], 'big')
        length = int.from_bytes(self.data[self.position + 8:self.position + 10], 'big')
        self.position += 10

        data, value = self.read_data(record_type, self.position, length)
        self.position += length

        return {'name': name, 'type': record_type, 'ttl': ttl, 'data': data, 'value': value}

    def read_data(self, record_type: int, start: int, length: int) -> tuple[bytes, str]:
        raw = self.data[start:start + length]

        if record_type == 1: # A
            return raw, '.'.join(str(byte) for byte in raw)

        if record_type in (2, 5, 12): # NS, CNAME, PTR
            name, _ = self.read_name(start)
            return Builder.add_name(name), name

        if record_type == 15: # MX
            name, end = self.read_name(start + 2)
            return raw[0:2] + Builder.add_name(name), name

        if record_type == 6: # SOA
            primary, end = self.read_name(start)
            mailbox, end = self.read_name(end)
            return Builder.add_name(primary) + Builder.add_name(mailbox) + self.data[end:end + 20], primary

        return raw, ''

    def read_name(self, position: int) -> tuple[str, int]:
        labels: list[str] = []
        end: int | None = None

        while True:
            length = self.data[position]

            if length == 0:
                position += 1
                break

            if length >= 0xC0:
                pointer = ((length & 0x3F) << 8) | self.data[position + 1]
                if pointer >= position:
                    raise ValueError('bad pointer')
                if end is None:
                    end = position + 2
                position = pointer
                continue

            labels.append(self.data[position + 1:position + 1 + length].decode())
            position += 1 + length

        if end is None:
            return '.'.join(labels), position
        return '.'.join(labels), end
