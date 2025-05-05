Описание:

Кеширующий DNS-сервер. Прослушивая 53 порт, сервер обрабатывает запросы клиента, сохраняя ответы в кеш. Кеш регулярно актуализируется: удаляются старые записи с истекшим сроком действия. При штатном выключении сервера, кеш сериализуется для восстановления при следующем запуске

Особенности
- Кэширование DNS-записей (A, AAAA, NS, PTR)
- Автоматическое обновление TTL
- Сохранение кэша на диск (`cache.pkl`)
- Асинхронная обработка запросов через `selectors`
- Корректная обработка Ctrl+C (SIGINT)

Первый запуск:

[Cache] No cache file found. Starting with empty cache

DNS server running on port 53

Второй запуск:

[Cache] Initial loaded records: 1

[Cache] Loaded 1 valid records (0 expired records removed)

DNS server running on port 53
