import os
import pickle
import time
from datetime import datetime
from threading import Lock, Thread
from typing import Dict, List, Optional, Tuple

from parse_data import DNSResourceRecord, DNSRecordType


class DNSCache:
    """Кэш DNS-записей с периодической очисткой и сохранением на диск"""

    def __init__(self, cache_file_path: str, cleanup_interval: int):
        self.cache_file = cache_file_path
        self.cache_data: Dict[str, Dict[DNSRecordType, Tuple[datetime, List[DNSResourceRecord]]]]= {}
        self.cleanup_thread = Thread(target=self._run_cache_cleanup,
                                     args=(cleanup_interval,),
                                     daemon=True)
        self.lock = Lock()

    def initialize_cache(self) -> None:
        """Загружает кэш из файла при инициализации"""
        try:
            if os.path.getsize(self.cache_file) > 0:
                with open(self.cache_file, "rb") as file:
                    self.cache_data = pickle.load(file)
        except FileNotFoundError:
            open(self.cache_file, "a").close()
            print(f"Created new cache file: {self.cache_file}")

    def start_cleanup_process(self) -> None:
        """Запускает фоновый процесс очистки кэша"""
        self.cleanup_thread.start()

    def add_records(
            self,
            domain_name: str,
            query_type: DNSRecordType,
            records: List[DNSResourceRecord],
    ) -> None:
        """Добавляет записи в кэш"""
        with self.lock:
            if domain_name not in self.cache_data:
                self.cache_data[domain_name] = {}

            if query_type not in self.cache_data[domain_name]:
                self.cache_data[domain_name][query_type] = (datetime.now(), records)

    def get_records(
            self,
            domain_name: str,
            query_type: DNSRecordType
    ) -> Optional[List[DNSResourceRecord]]:
        """Получает записи из кэша, если они еще актуальны"""
        if domain_name in self.cache_data and query_type in self.cache_data[domain_name]:
            if self._records_expired(domain_name, query_type):
                self._remove_expired_records(domain_name, query_type)
                return None
            return self.cache_data[domain_name][query_type][1]
        return None

    def _run_cache_cleanup(self, interval: int) -> None:
        """Фоновый процесс очистки устаревших записей"""
        while True:
            for domain in list(self.cache_data.keys()):
                for q_type in list(self.cache_data[domain].keys()):
                    if self._records_expired(domain, q_type):
                        self._remove_expired_records(domain, q_type)
            time.sleep(interval)

    def _remove_expired_records(self, domain: str, query_type: DNSRecordType) -> None:
        """Удаляет устаревшие записи из кэша"""
        with self.lock:
            self.cache_data[domain].pop(query_type)
            if not self.cache_data[domain]:
                self.cache_data.pop(domain)

    def _records_expired(self, domain: str, query_type: DNSRecordType) -> bool:
        """Проверяет, устарели ли записи"""
        cached_time, records = self.cache_data[domain][query_type]
        time_elapsed = (datetime.now() - cached_time).seconds

        return any(time_elapsed >= record.ttl for record in records)

    def save_cache(self) -> None:
        """Сохраняет кэш"""
        pickle.dump(
                self.buffer, open(self.path, "wb"), protocol=pickle.HIGHEST_PROTOCOL
            )
    def shutdown(self) -> None:
        """Корректно завершает работу кэша"""
        self.cleanup_thread.join(timeout=1)
        self.save_cache()