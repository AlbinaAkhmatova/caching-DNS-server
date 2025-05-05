import struct
from typing import List, Tuple
from parse_data import DNSRecordType, DNSClass, DNSHeader, DNSQuestion, DNSResourceRecord


def create_error_response(request_id: bytes) -> bytes:
    """Создает DNS-ответ с ошибкой 'Not Implemented' (код 4)"""
    return request_id + struct.pack(
        "!5H",
        (1 << 15) | (4 << 8),  # QR=1 (ответ), RCODE=4 (Not Implemented)
        0,  # Нет вопросов
        0,  # Нет ответов
        0,  # Нет authoritative записей
        0  # Нет additional записей
    )


def build_response_packet(
        request_header: DNSHeader,
        questions: List[DNSQuestion],
        answer_records: List[DNSResourceRecord],
) -> bytes:
    """Собирает DNS-ответный пакет"""
    # Формируем заголовок ответа
    header = struct.pack(
        "!6H",
        request_header.packet_id,
        (1 << 15) | (1 << 8),  # QR=1 (ответ), RD=1 (рекурсия)
        len(questions),
        len(answer_records),
        0,  # Нет authoritative записей
        0  # Нет additional записей
    )

    # Добавляем вопросы
    for question in questions:
        _, domain_bytes = encode_domain_name(question.domain)
        header += domain_bytes + struct.pack(
            "!HH", question.record_type, question.record_class
        )

    # Добавляем ответы
    for record in answer_records:
        _, domain_bytes = encode_domain_name(record.domain)
        header += (
                domain_bytes +
                struct.pack("!HHI", record.record_type, record.record_class, record.ttl) +
                encode_record_data(record.record_type, record.data_length, record.data)
        )

    return header


def encode_record_data(record_type: DNSRecordType, length: int, data: str) -> bytes:
    """Кодирует данные ресурсной записи в DNS-формат"""
    if record_type == DNSRecordType.A:
        # IPv4 адрес (4 байта)
        octets = list(map(int, data.split(".")))
        return struct.pack(f"!H4B", length, *octets)

    elif record_type in (DNSRecordType.NS, DNSRecordType.PTR):
        # Доменное имя (NS или PTR запись)
        encoded_length, encoded_data = encode_domain_name(data)
        return struct.pack("!H", encoded_length) + encoded_data

    elif record_type == DNSRecordType.AAAA:
        # IPv6 адрес (16 байт)
        hextets = [int(octet, 16) for octet in data.split(":")]
        return struct.pack(f"!H8H", length, *hextets)

    raise ValueError(f"Unsupported record type: {record_type}")


def encode_domain_name(domain: str) -> Tuple[int, bytes]:
    """Кодирует доменное имя в DNS-формат"""
    encoded = bytes()
    total_length = 0

    for label in domain.split("."):
        label_len = len(label)
        encoded += struct.pack(f"!B{label_len}s", label_len, label.encode())
        total_length += label_len + 1  # +1 для байта длины

    encoded += b"\x00"  # Конец имени
    total_length += 1

    return total_length, encoded


def build_query_packet(
        query_id: int,
        domain: str,
        record_type: DNSRecordType,
        record_class: DNSClass = DNSClass.IN,
) -> bytes:
    """Создает DNS-запросный пакет"""
    # Заголовок запроса
    header = struct.pack(
        "!6H",
        query_id,
        0x0100,  # Стандартные флаги запроса (RD=1)
        1,  # Один вопрос
        0, 0, 0  # Нет ответов и дополнительных записей
    )

    # Добавляем вопрос
    _, encoded_domain = encode_domain_name(domain)
    question = encoded_domain + struct.pack("!HH", record_type, record_class)

    return header + question
