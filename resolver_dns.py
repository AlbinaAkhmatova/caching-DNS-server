import socket
from typing import List, Optional
from dataclasses import dataclass

import pack_data
import json_dependencies
from parse_data import DNSPacket, DNSClass, DNSRecordType

# Загрузка конфигурации
server_config = json_dependencies.load_server_configs()


@dataclass
class DNSResolver:
    """DNS-ресолвер с рекурсивными запросами"""

    request_size: int = server_config["request_size"]
    root_server_ip: str = server_config["root_server_ip"]
    root_server_port: int = server_config["root_server_port"]

    def recursive_resolve(
            self,
            dns_query: bytes,
            target_server_ip: str = None,
            target_server_port: int = 53
    ) -> Optional[DNSPacket]:
        """Выполняет рекурсивное разрешение DNS-запроса"""
        target_server_ip = target_server_ip or self.root_server_ip
        target_server_port = target_server_port or self.root_server_port

        response = self._query_dns_server(dns_query, target_server_ip, target_server_port)
        response_packet = DNSPacket(response)

        # Если есть прямые ответы - возвращаем их
        if response_packet.header.answers_count > 0:
            return response_packet

        # Обработка authoritative записей
        if response_packet.header.authority_count > 0:
            return self._handle_authoritative_records(dns_query, response_packet)

        return None

    def _handle_authoritative_records(
            self,
            dns_query: bytes,
            response_packet: DNSPacket
    ) -> Optional[DNSPacket]:
        """Обрабатывает authoritative записи для продолжения рекурсивного разрешения"""
        for auth_record in response_packet.authority_records:
            # Проверяем дополнительные записи на наличие IP
            for additional_record in response_packet.additional_records:
                if additional_record.record_type == DNSRecordType.A:
                    return self.recursive_resolve(dns_query, additional_record.data)

            # Если в дополнительных записях нет IP, разрешаем имя authoritative сервера
            resolved_ips = self._resolve_name_to_ips(
                response_packet.header.packet_id,
                auth_record.data
            )
            if resolved_ips:
                return self.recursive_resolve(dns_query, resolved_ips[0])

        return None

    def _resolve_name_to_ips(
            self,
            query_id: int,
            domain_name: str
    ) -> Optional[List[str]]:
        """Разрешает доменное имя в список IP-адресов"""
        query = pack_data.build_query_packet(
            query_id,
            domain_name,
            DNSRecordType.A,
            DNSClass.IN,
        )

        response = self.recursive_resolve(query)
        if response:
            return [answer.data for answer in response.answers]
        return None

    def _query_dns_server(
            self,
            request: bytes,
            server_ip: str,
            server_port: int = 53
    ) -> bytes:
        """Отправляет запрос DNS-серверу и возвращает ответ"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.connect((server_ip, server_port))
            sock.send(request)
            return sock.recv(self.request_size)