@echo off
echo === OSINT Dox Bot ===

:: Проверить Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python не найден. Скачайте с https://python.org
    pause
    exit /b 1
)

:: Установить зависимости
echo Устанавливаю зависимости...
pip install -r requirements.txt --quiet

:: Проверить .env
if not exist ".env" (
    echo [WARN] Файл .env не найден. Создаю из шаблона...
    copy .env.example .env
    echo [!] Заполните .env файл перед запуском!
    notepad .env
    pause
    exit /b 1
)

:: Запустить бота
echo Запускаю бота...
python bot.py
pause
