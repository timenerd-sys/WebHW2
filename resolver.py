import socket

from builder import Builder
from dns_parser import DNSParser


ROOT_SERVERS = ['198.41.0.4', '192.33.4.12', '199.7.91.13', '192.5.5.241', '193.0.14.129']

class Resolver:
    @staticmethod
    def query(server: str, name: str, qtype: int) -> DNSParser | None:
        builder = Builder()
        request = builder.build_query(name, qtype)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(request, (server, 53))
            while True:
                response, address = s.recvfrom(4096)
                if response[0:2] == builder.id:
                    break
            parser = DNSParser(response)
            parser.parse()
            return parser
        except Exception:
            return None
        finally:
            s.close()

    @staticmethod
    def ask(servers: list[str], name: str, qtype: int) -> DNSParser | None:
        for server in servers:
            print(f'{name} {qtype} -> {server}')
            response = Resolver.query(server, name, qtype)
            if response is not None:
                return response
        return None

    @staticmethod
    def resolve(name: str, qtype: int, depth: int = 0) -> DNSParser | None:
        if depth > 5:
            return None
        servers = ROOT_SERVERS

        for step in range(20):
            response = Resolver.ask(servers, name, qtype)
            if response is None:
                return None

            if response.rcode == 3:
                return response

            if len(response.answers) > 0:
                return Resolver.follow_cname(response, qtype, depth)

            ns_names = [record['value'] for record in response.authority
                        if record['type'] == 2]
            if len(ns_names) == 0:
                return response

            servers = [record['value'] for record in response.additional
                       if record['type'] == 1 and record['name'] in ns_names]
            if len(servers) == 0:
                servers = Resolver.resolve_servers(ns_names, depth)
            if len(servers) == 0:
                return None

        return None

    @staticmethod
    def resolve_servers(ns_names: list[str], depth: int) -> list[str]:
        for ns_name in ns_names:
            response = Resolver.resolve(ns_name, 1, depth + 1)
            if response is None:
                continue
            servers = [record['value'] for record in response.answers
                       if record['type'] == 1]
            if len(servers) > 0:
                return servers
        return []

    @staticmethod
    def follow_cname(response: DNSParser, qtype: int, depth: int) -> DNSParser | None:
        types = [record['type'] for record in response.answers]
        if qtype == 5 or qtype in types or 5 not in types:
            return response

        cnames = [record for record in response.answers
                  if record['type'] == 5]
        result = Resolver.resolve(cnames[-1]['value'], qtype, depth + 1)
        if result is None:
            return response

        result.answers = response.answers + result.answers
        return result
