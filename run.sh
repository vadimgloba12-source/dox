#!/bin/bash
echo "=== OSINT Dox Bot ==="

# Проверить Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 не найден. Установите: sudo apt install python3 python3-pip"
    exit 1
fi

# Установить зависимости
echo "Устанавливаю зависимости..."
pip3 install -r requirements.txt -q

# Проверить .env
if [ ! -f ".env" ]; then
    echo "[WARN] Файл .env не найден. Создаю из шаблона..."
    cp .env.example .env
    echo "[!] Заполните .env файл и запустите снова!"
    exit 1
fi

# Запустить бота
echo "Запускаю бота..."
python3 bot.py
