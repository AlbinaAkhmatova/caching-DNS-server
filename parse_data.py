import struct
from dataclasses import dataclass
from enum import Enum
from typing import List


class DNSRecordType(int, Enum):
    """Типы DNS-записей"""
    A = 1  # IPv4 адрес
    NS = 2  # Сервер имен
    PTR = 12  # Обратная запись
    AAAA = 28  # IPv6 адрес


class DNSClass(int, Enum):
    """Классы DNS-записей"""
    IN = 1  # Интернет


@dataclass
class DNSHeader:
    """Заголовок DNS-пакета"""
    packet_id: int  # Id пакета
    flags: int  # Флаги
    questions_count: int  # Количество вопросов
    answers_count: int  # Количество ответов
    authority_count: int  # Количество записей о серверах имен
    additional_count: int  # Количество дополнительных записей


@dataclass
class DNSQuestion:
    """DNS-запрос"""
    domain: str  # Доменное имя
    record_type: DNSRecordType  # Тип записи
    record_class: DNSClass  # Класс записи


@dataclass
class DNSResourceRecord:
    """DNS-запись (ресурсная запись)"""
    domain: str  # Доменное имя
    record_type: DNSRecordType  # Тип записи
    record_class: DNSClass  # Класс записи
    ttl: int  # Время жизни (секунды)
    data_length: int  # Длина данных
    data: str  # Данные записи


@dataclass
class DNSPacket:
    """Полный DNS-пакет"""
    raw_data: bytes
    _position: int = 0
    header: DNSHeader = None
    questions: List[DNSQuestion] = None
    answers: List[DNSResourceRecord] = None
    authority_records: List[DNSResourceRecord] = None
    additional_records: List[DNSResourceRecord] = None

    def __post_init__(self):
        """Инициализация пакета - парсинг всех частей"""
        self.questions = []
        self.answers = []
        self.authority_records = []
        self.additional_records = []
        self._parse_header()
        self._parse_questions()
        self._parse_all_records()

    def _parse_header(self):
        """Парсинг заголовка DNS-пакета"""
        header_size = 12  # Размер заголовка в байтах
        self.header = DNSHeader(*struct.unpack("!6H", self.raw_data[:header_size]))
        self._position += header_size

    def _parse_questions(self):
        """Парсинг секции вопросов"""
        question_size = 4  # Размер вопроса в байтах
        for _ in range(self.header.questions_count):
            self.questions.append(
                DNSQuestion(
                    self._read_domain_name(),
                    *struct.unpack(
                        "!HH", self.raw_data[self._position: self._position + question_size]
                    ),
                )
            )
            self._position += question_size

    def _parse_all_records(self):
        """Парсинг всех секций с записями"""
        record_sections = (
            (self.answers, self.header.answers_count),
            (self.authority_records, self.header.authority_count),
            (self.additional_records, self.header.additional_count),
        )
        for records, count in record_sections:
            self._parse_record_section(records, count)

    def _parse_record_section(self, records, count):
        """Парсинг одной секции записей (ответы, authority или additional)"""
        record_header_size = 10  # Размер заголовка записи
        for _ in range(count):
            domain = self._read_domain_name()
            r_type, r_class, ttl, data_len = struct.unpack(
                "!HHIH", self.raw_data[self._position: self._position + record_header_size]
            )
            self._position += record_header_size
            record_data = self._parse_record_data(r_type, data_len)
            records.append(
                DNSResourceRecord(domain, r_type, r_class, ttl, data_len, record_data)
            )

    def _read_domain_name(self):
        """Читает доменное имя из DNS-пакета с учетом сжатия"""
        name_parts = []
        current_pos = self._position
        compression_offset = None  # позиция после указателя укорочения

        while True:
            byte = self.raw_data[current_pos]

            # Проверка на сжатие (первые 2 бита = 11)
            if (byte & 0xC0) == 0xC0:
                if compression_offset is None:
                    compression_offset = current_pos + 2

                # смещение (14 младших битов)
                offset = ((byte & 0x3F) << 8) | self.raw_data[current_pos + 1]
                if offset >= len(self.raw_data):
                    raise ValueError("Invalid compression offset")

                current_pos = offset
                continue

            # Мы уже обработали сжатие (192-255), поэтому сюда попадём только при 64-191
            if byte > 63:
                raise ValueError(f"Invalid label length: {byte}")

            if byte == 0:
                if compression_offset is None:
                    self._position = current_pos + 1
                else:
                    self._position = compression_offset
                break

            label_length = byte
            current_pos += 1
            label_end = current_pos + label_length

            if label_end > len(self.raw_data):
                raise ValueError("Label exceeds packet bounds")

            name_parts.append(self.raw_data[current_pos:label_end])
            current_pos = label_end

        try:
            return ".".join(part.decode('ascii') for part in name_parts)
        except UnicodeDecodeError:
            raise ValueError("Invalid ASCII in domain name")


    def _parse_record_data(self, record_type, data_length):
        """Парсинг данных записи в зависимости от типа"""
        if record_type == DNSRecordType.A.value:
            # IPv4 адрес (4 байта)
            octets = struct.unpack(
                f"!{data_length}B",
                self.raw_data[self._position: self._position + data_length],
            )
            self._position += data_length
            return ".".join(str(octet) for octet in octets)

        elif record_type == DNSRecordType.NS.value or record_type == DNSRecordType.PTR.value:
            # Доменное имя (NS или PTR запись)
            return self._read_domain_name()

        elif record_type == DNSRecordType.AAAA.value:
            # IPv6 адрес (16 байт)
            hextets = struct.unpack(
                f"!{data_length // 2}H",
                self.raw_data[self._position: self._position + data_length],
            )
            self._position += data_length
            return ":".join(f"{hextet:04x}" for hextet in hextets)

        else:
            raise ValueError(f"Unsupported record type: {record_type}")