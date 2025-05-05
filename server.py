import signal
import socket
from typing import List

import pack_data
import json_dependencies
import resolver_dns
from cache_dns import DNSCache
from parse_data import DNSPacket, DNSQuestion, DNSResourceRecord, DNSRecordType, DNSClass


class Server:
    def __init__(self):
        self.settings = json_dependencies.load_server_configs()
        self._server_socket = None
        self._cacher = None
        self._resolver = None
        self._handle_flag = True
        self._initialize()

    def _initialize(self):
        """Инициализация всех компонентов сервера"""
        self._init_socket()
        self._init_cacher()
        self._init_resolver()
        signal.signal(signal.SIGINT, self._close)

    def _init_socket(self):
        """Инициализация серверного сокета"""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.bind((self.settings["server_ip"], self.settings["server_port"]))

    def _init_cacher(self):
        """Инициализация кэша DNS записей"""
        self._cacher = DNSCache(
            self.settings["cache_filepath"],
            self.settings["clean_period"]
        )
        self._cacher.initialize_cache()
        self._cacher.start_cleanup_process()

    def _init_resolver(self):
        """Инициализация DNS резолвера"""
        self._resolver = resolver_dns.DNSResolver(
            request_size=self.settings["request_size"],
            root_server_ip=self.settings["root_server_ip"],
            root_server_port=self.settings["root_server_port"]
        )

    def run(self):
        """Основной цикл обработки запросов"""
        print(f"Server started on {self.settings['server_ip']}:{self.settings['server_port']}")
        while self._handle_flag:
            try:
                request, address = self._server_socket.recvfrom(self.settings["request_size"])
                self._handle_client(request, address)
            except socket.error as e:
                if self._handle_flag:
                    print(f"Socket error: {e}")

    def _handle_client(self, request: bytes, address: tuple):
        """Обработка запроса от клиента"""
        try:
            request_package = DNSPacket(request)
            total_a_records = []

            for question in request_package.questions:
                records = self._process_question(
                    question=question,
                    packet_id=request_package.header.packet_id
                )
                total_a_records.extend(records)

            response = pack_data.build_response_packet(
                request_package.header,
                request_package.questions,
                total_a_records
            )
            self._server_socket.sendto(response, address)

        except Exception as e:
            print(f"Error handling request: {e}")
            print("tut")
            error_response = pack_data.create_error_response(request[:2])
            self._server_socket.sendto(error_response, address)

    def _process_question(self, question: DNSQuestion, packet_id: int) -> List[DNSResourceRecord]:
        """Обработка одного DNS вопроса"""
        # if question.domain == "whoami.dns":
        #     print(f"[DEBUG] Это мой сервер! Запрос от {question.domain}")
        #     # Возвращаем фиктивную запись
        #     return [DNSResourceRecord(
        #         domain="whoami.dns",
        #         record_type=DNSRecordType.A,
        #         record_class=DNSClass.IN,
        #         ttl=60,
        #         data_length=4,
        #         data="127.0.0.1"
        #     )]
        # Проверка кэша
        cached_records = self._cacher.get_records(question.domain, question.record_type)
        if cached_records is not None:
            print(f"[Cache] Found records for {question.domain}")
            return cached_records[1]  # Возвращаем список записей

        # Рекурсивное разрешение, если нет в кэше
        print(f"[Resolver] Resolving {question.domain}")
        q_request = pack_data.build_query_packet(
            packet_id,
            question.domain,
            question.record_type,
            question.record_class,
        )

        try:
            answer = self._resolver.recursive_resolve(q_request)
            if answer and answer.answers:
                self._cacher.add_records(question.domain, question.record_type, answer.answers)
                return answer.answers
        except Exception as e:
            print(f"Resolution error for {question.domain}: {e}")

        return []

    def _close(self, signum=None, frame=None):
        """Корректное завершение работы сервера"""
        print("\nShutting down server...")
        self._handle_flag = False
        if self._server_socket:
            self._server_socket.close()
        if self._cacher:
            self._cacher.save()
            self._cacher.close()