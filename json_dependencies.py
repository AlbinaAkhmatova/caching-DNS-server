import json


# Получение конфигураций для сервера
def load_server_configs() -> dict:
    with open("config.json", "r") as j_file:
        configs = json.load(j_file)
    return configs
