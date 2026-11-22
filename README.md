# BAT-PACKET-SNIFFER

Визуальный инспектор сетевых соединений, процессов и внешних серверов в реальном времени (macOS / Windows / Linux) — 100% на стандартной библиотеке Python без сторонних пакетов.

---

## Возможности

* **100% Zero-Dependency Python Stdlib:** работает без `pip`, `psutil` и `scapy`. Парсит системные таблицы сокетов (`lsof` на macOS/Linux, `netstat -ano` + `tasklist` на Windows) и делает параллельный Reverse DNS.
* **Определение сервисов и провайдеров:** автоматически распознаёт трафик Telegram, Valve/Steam, Cloudflare, Google, GitHub, Apple, AWS, Yandex и локальной сети.
* **Эвристика аномалий и контроль процессов:** подсвечивает коннекты на нестандартные порты и прямые обращения к внешним IP без DNS-имени, позволяет в один клик скопировать команду блокировки IP для системного фаервола (`pfctl` / `netsh` / `iptables`) или завершить подозрительный процесс.

---

## Быстрый старт

### macOS
```bash
chmod +x scripts/start_mac.sh
./scripts/start_mac.sh
```

### Windows
Дважды кликните по файлу `scripts/start_windows.bat`.

