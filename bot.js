/**
 * OSINT Dox Bot — Production build
 * Features: IP · Phone · ФИО · Photos · Address · Kompromat · Email · Username · WHOIS
 * Engine: Google Search via searchapi.io
 */

const { Telegraf, Markup } = require('telegraf');
const axios       = require('axios');
const NodeCache   = require('node-cache');
const sqlite3     = require('sqlite3').verbose();
const { spawn }   = require('child_process');
require('dotenv').config();

// ─── SpiderFoot ───────────────────────────────────────────────────────────────
const SF_HOST = '127.0.0.1';
const SF_PORT = 5001;
const SF_BASE = `http://${SF_HOST}:${SF_PORT}`;
let   sfAvailable = false;

async function startSpiderFoot() {
    // Проверяем, уже запущен ли
    try {
        await axios.get(`${SF_BASE}/ping`, { timeout: 2000 });
        sfAvailable = true;
        console.log('✅ SpiderFoot уже запущен');
        return;
    } catch (_) {}

    console.log('🕷 Запускаю SpiderFoot...');
    const sf = spawn('python3', ['/tmp/spiderfoot/sf.py', '-l', `${SF_HOST}:${SF_PORT}`, '-d'], {
        detached: true, stdio: 'ignore',
    });
    sf.unref();

    // Ждём запуска (до 30 сек)
    for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 1000));
        try {
            await axios.get(`${SF_BASE}/ping`, { timeout: 1500 });
            sfAvailable = true;
            console.log('✅ SpiderFoot запущен');
            return;
        } catch (_) {}
    }
    console.error('❌ SpiderFoot не ответил за 30 сек');
}

// Определить тип цели для SpiderFoot
function detectTargetType(target) {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target))     return 'IP_ADDRESS';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target))  return 'EMAILADDR';
    if (/^[\+7-8][\d\s\-\(\)]{9,15}$/.test(target)) return 'PHONE_NUMBER';
    if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(target)) return 'INTERNET_NAME';
    return 'USERNAME';
}

// Модули по типу цели (только бесплатные, без API-ключей)
const SF_MODULES = {
    IP_ADDRESS:    'sfp_whois,sfp_dnsresolve,sfp_ipinfo,sfp_dnsneighbor,sfp_company,sfp_countryname',
    INTERNET_NAME: 'sfp_whois,sfp_dnsresolve,sfp_dnsraw,sfp_crt,sfp_email,sfp_emailformat,sfp_bingsearch,sfp_googlemaps,sfp_company,sfp_github,sfp_hashes',
    EMAILADDR:     'sfp_emailformat,sfp_gravatar,sfp_pgp,sfp_bingsearch,sfp_github,sfp_accounts',
    USERNAME:      'sfp_accounts,sfp_github,sfp_bingsearch,sfp_socialprofiles',
    PHONE_NUMBER:  'sfp_phone,sfp_bingsearch,sfp_googlemaps',
};

// Запустить сканирование и дождаться результатов
async function runSFScan(target, maxSecs = 90) {
    const targetType = detectTargetType(target);
    const modules    = SF_MODULES[targetType] || SF_MODULES.USERNAME;
    const scanName   = `bot_${Date.now()}`;

    const form = new URLSearchParams({
        scanname: scanName, scantarget: target,
        typelist: targetType, modulelist: modules, usecase: 'all',
    });

    await axios.post(`${SF_BASE}/startscan`, form.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        maxRedirects: 5, validateStatus: s => s < 500,
    });

    // Находим ID свежесозданного скана
    await new Promise(r => setTimeout(r, 1000));
    const list   = await axios.get(`${SF_BASE}/scanlist`);
    const scan   = list.data.find(s => s[1] === scanName);
    if (!scan) throw new Error('Scan not found in list');
    const scanId = scan[0];

    // Ждём завершения
    const deadline = Date.now() + maxSecs * 1000;
    while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 5000));
        const st = await axios.get(`${SF_BASE}/scanstatus/${scanId}`);
        const status = st.data[5] || st.data[6];
        if (['FINISHED', 'ERROR', 'ABORTED'].includes(status)) break;
    }

    // Получаем результаты
    const res = await axios.get(`${SF_BASE}/scaneventresults/${scanId}/ALL`);
    return { scanId, targetType, results: res.data };
}

// Иконки для типов событий SpiderFoot
const SF_ICONS = {
    EMAILADDR:                        '📧',
    PHONE_NUMBER:                     '📞',
    INTERNET_NAME:                    '🌐',
    IP_ADDRESS:                       '🌍',
    IPV6_ADDRESS:                     '🌍',
    ACCOUNT_EXTERNAL_OWNED:           '👤',
    ACCOUNT_EXTERNAL_OWNED_COMPROMISED: '🔓',
    PHYSICAL_ADDRESS:                 '📍',
    HUMAN_NAME:                       '👤',
    COMPANY_NAME:                     '🏢',
    AFFILIATE_EMAILADDR:              '📧',
    DOMAIN_WHOIS:                     '📋',
    DOMAIN_REGISTRAR:                 '🏢',
    USERNAME:                         '👾',
    URL_STATIC:                       '🔗',
    URL_FORM:                         '📝',
    SOCIAL_MEDIA:                     '📱',
    GEOINFO:                          '🗺',
    SSL_CERTIFICATE_ISSUED:           '🔒',
    WEB_ANALYTICS_ID:                 '📊',
    SOFTWARE_USED:                    '💾',
    TCP_PORT_OPEN:                    '🔌',
    TCP_PORT_OPEN_BANNER:             '🔌',
    VULNERABILITY_CVE_HIGH:           '🚨',
    VULNERABILITY_CVE_CRITICAL:       '🚨',
    LEAKSITE_CONTENT:                 '🔓',
    DARKWEB_MENTION:                  '🌑',
    PGP_KEY:                          '🔑',
    HASH:                             '#️⃣',
    PROVIDER_MAIL:                    '📮',
    PROVIDER_DNS:                     '🖥',
};

// Группировать и форматировать результаты SpiderFoot
function formatSFResults(results, targetType) {
    const important = [
        'ACCOUNT_EXTERNAL_OWNED','ACCOUNT_EXTERNAL_OWNED_COMPROMISED',
        'EMAILADDR','PHONE_NUMBER','PHYSICAL_ADDRESS','HUMAN_NAME',
        'COMPANY_NAME','DOMAIN_WHOIS','SOCIAL_MEDIA','USERNAME',
        'PGP_KEY','LEAKSITE_CONTENT','DARKWEB_MENTION',
        'VULNERABILITY_CVE_HIGH','VULNERABILITY_CVE_CRITICAL',
        'TCP_PORT_OPEN','WEB_ANALYTICS_ID','SSL_CERTIFICATE_ISSUED',
        'IP_ADDRESS','INTERNET_NAME','GEOINFO','AFFILIATE_EMAILADDR',
    ];

    const groups = {};
    for (const r of results) {
        const type = r[10] || r[r.length - 1];
        if (!important.includes(type)) continue;
        if (!groups[type]) groups[type] = new Set();
        const val = r[1];
        if (val && val.length < 300) groups[type].add(val.trim());
    }

    const parts = [];
    for (const type of important) {
        const vals = groups[type];
        if (!vals || vals.size === 0) continue;
        const icon  = SF_ICONS[type] || '▪️';
        const label = type.replace(/_/g, ' ');
        const items = [...vals].slice(0, 8).map(v => `  • ${v.slice(0, 120)}`).join('\n');
        parts.push(`${icon} <b>${label}:</b>\n${items}`);
    }
    return parts;
}

// ─── Database ────────────────────────────────────────────────────────────────
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        phone TEXT,
        stars INTEGER DEFAULT 0,
        allowed BOOLEAN DEFAULT 0,
        banned BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    // Миграция: добавить колонку banned если её нет (игнорируем ошибку если уже есть)
    db.run(`ALTER TABLE users ADD COLUMN banned BOOLEAN DEFAULT 0`, () => {});
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        telegram_id INTEGER UNIQUE,
        is_super BOOLEAN DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        query TEXT,
        cost INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// ─── Config ──────────────────────────────────────────────────────────────────
const BOT_TOKEN    = process.env.BOT_TOKEN;
const ADMIN_ID     = process.env.ADMIN_ID;
const SEARCHAPI_KEY = process.env.SEARCHAPI_KEY || '3U2BbwQzCxKvRzeaAATjeRz6';

if (!BOT_TOKEN) {
    console.error('❌  BOT_TOKEN не указан в .env файле');
    console.error('    Создайте бота у @BotFather и добавьте токен в .env');
    process.exit(1);
}

// Costs in stars
const COSTS = {
    ip_lookup:        5,
    phone_lookup:    10,
    person_search:   15,
    photo_search:    10,
    address_search:  15,
    kompromat:       20,
    email_search:    10,
    username_search: 10,
    whois_lookup:     5,
    reverse_image:   25,  // Google Lens — определить личность по фото
    telegram_lookup: 10,  // Telegram профиль по нику/ID
    car_lookup:      15,  // Пробив авто по гос.номеру
    connections:     20,  // Связи и окружение человека
    doc_search:      20,  // Поиск по документам / паспорту
    spiderfoot:      30,  // глубокое автосканирование SpiderFoot (230 модулей)
    full_dossier:    45,  // всё сразу (экономия 35⭐)
};

const bot = new Telegraf(BOT_TOKEN);

// ─── Caches ──────────────────────────────────────────────────────────────────
const searchCache  = new NodeCache({ stdTTL: 600 });   // cache search results 10 min
const ipCache      = new NodeCache({ stdTTL: 3600 });  // cache IP results 1 hour
const rateLimiter  = new NodeCache({ stdTTL: 3600 });  // rate limit window 1 hour

// ─── User state machine ──────────────────────────────────────────────────────
const userStates = new Map(); // userId → { action }

// ─── Rate limiting ───────────────────────────────────────────────────────────
const RATE_LIMIT = 30; // max requests per hour per user

function checkRateLimit(userId) {
    const key  = `rl_${userId}`;
    const count = rateLimiter.get(key) || 0;
    if (count >= RATE_LIMIT) return false;
    rateLimiter.set(key, count + 1);
    return true;
}

// ─── Input validators ────────────────────────────────────────────────────────
const RE_IP    = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_PHONE = /^[\+7-8][\d\s\-\(\)]{9,15}$/;
const RE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RE_DOMAIN = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

function validateInput(action, text) {
    switch (action) {
        case 'ip_lookup':    return RE_IP.test(text.trim())    || 'Неверный формат IP. Пример: 8.8.8.8';
        case 'phone_lookup': return RE_PHONE.test(text.trim()) || 'Неверный формат телефона. Пример: +79001234567';
        case 'email_search': return RE_EMAIL.test(text.trim()) || 'Неверный формат email. Пример: user@mail.ru';
        case 'whois_lookup': return (RE_DOMAIN.test(text.trim()) || RE_IP.test(text.trim())) || 'Введите домен (example.com) или IP-адрес';
        default: return text.trim().length >= 2 || 'Слишком короткий запрос.';
    }
}

// ─── DB helpers ──────────────────────────────────────────────────────────────
function getUser(telegramId) {
    return new Promise((resolve, reject) =>
        db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (e, r) => e ? reject(e) : resolve(r))
    );
}

function updateStars(telegramId, delta) {
    return new Promise((resolve, reject) =>
        db.run('UPDATE users SET stars = stars + ? WHERE telegram_id = ?', [delta, telegramId], function(e) {
            e ? reject(e) : resolve(this.changes);
        })
    );
}

function logRequest(userId, type, query, cost) {
    db.run('INSERT INTO requests (user_id, type, query, cost) VALUES (?, ?, ?, ?)', [userId, type, query, cost]);
}

function notifyAdmins(message, extra = {}) {
    db.all('SELECT telegram_id FROM admins', (err, rows) => {
        if (err) return;
        rows.forEach(r => bot.telegram.sendMessage(r.telegram_id, message, extra).catch(() => {}));
    });
}

// ─── Admin guard ─────────────────────────────────────────────────────────────
function isAdmin(ctx, next) {
    db.get('SELECT * FROM admins WHERE telegram_id = ?', [ctx.from.id], (err, row) => {
        if (err || !row) return ctx.reply('⛔ У вас нет прав администратора.');
        next();
    });
}

// ─── Keyboards ───────────────────────────────────────────────────────────────
function mainMenuKeyboard() {
    return Markup.inlineKeyboard([
        [Markup.button.callback('📋 Полное досье', 'full_dossier')],
        [
            Markup.button.callback('🌐 IP-адрес',  'ip_lookup'),
            Markup.button.callback('📞 Телефон',   'phone_lookup'),
        ],
        [
            Markup.button.callback('👤 ФИО',       'person_search'),
            Markup.button.callback('📸 Фото',      'photo_search'),
        ],
        [
            Markup.button.callback('🏠 Адрес',     'address_search'),
            Markup.button.callback('🕵️ Компромат', 'kompromat'),
        ],
        [
            Markup.button.callback('📧 Email',     'email_search'),
            Markup.button.callback('👾 Ник',       'username_search'),
        ],
        [
            Markup.button.callback('🔍 WHOIS',         'whois_lookup'),
            Markup.button.callback('✈️ Telegram',       'telegram_lookup'),
        ],
        [
            Markup.button.callback('📷 Поиск по фото', 'reverse_image'),
            Markup.button.callback('🚗 Пробив авто',   'car_lookup'),
        ],
        [
            Markup.button.callback('🔗 Связи/окружение', 'connections'),
            Markup.button.callback('📄 Документы',        'doc_search'),
        ],
        [Markup.button.callback('🕷 SpiderFoot — глубокий скан', 'spiderfoot')],
        [
            Markup.button.callback('⭐ Купить звёзды', 'buy_stars'),
            Markup.button.callback('💰 Баланс',        'show_balance'),
        ],
        [Markup.button.callback('📜 История запросов', 'show_history')],
    ]);
}

function adminMenuKeyboard() {
    return Markup.inlineKeyboard([
        [Markup.button.callback('📋 Ожидающие', 'adm_pending')],
        [Markup.button.callback('👥 Все пользователи', 'adm_users')],
        [Markup.button.callback('📊 Статистика', 'adm_stats')],
        [Markup.button.callback('📢 Рассылка', 'adm_broadcast')],
    ]);
}

function relatedKeyboard(query) {
    const enc = encodeURIComponent(query);
    return Markup.inlineKeyboard([
        [Markup.button.callback('📸 Найти фото', `quick_photo:${query}`.slice(0, 64))],
        [Markup.button.callback('🕵️ Компромат',  `quick_komp:${query}`.slice(0, 64))],
        [Markup.button.callback('🏠 Адрес',      `quick_addr:${query}`.slice(0, 64))],
    ]);
}

// ─── /start ──────────────────────────────────────────────────────────────────
bot.start(async (ctx) => {
    const userId = ctx.from.id;
    const name   = ctx.from.first_name;

    db.get('SELECT * FROM users WHERE telegram_id = ?', [userId], (err, row) => {
        if (err) return ctx.reply('Ошибка. Попробуйте позже.');

        if (!row) {
            return ctx.reply(
                `👋 <b>Привет, ${name}!</b>\n\n` +
                '🤖 <b>OSINT Dox Bot</b> — инструмент для разведки по открытым источникам.\n\n' +
                '<b>Возможности:</b>\n' +
                '🌐 IP-адрес — геолокация, провайдер, карта\n' +
                '📞 Телефон — оператор + поиск владельца\n' +
                '👤 ФИО — биография, соцсети, деловые базы\n' +
                '📸 Фото — поиск фотографий человека\n' +
                '🏠 Адрес — поиск места проживания\n' +
                '🕵️ Компромат — суды, долги, новости\n' +
                '📧 Email — утечки, аккаунты, история\n' +
                '👾 Ник — поиск по всем соцсетям\n' +
                '🔍 WHOIS — информация о домене\n' +
                '📋 Полное досье — всё сразу\n\n' +
                '📱 <b>Для начала работы отправьте номер телефона:</b>',
                {
                    parse_mode: 'HTML',
                    ...Markup.keyboard([Markup.button.contactRequest('📱 Отправить номер')]).resize(),
                }
            );
        }

        if (row.banned) return ctx.reply('⛔ Ваш аккаунт заблокирован.');
        if (!row.allowed) return ctx.reply('⏳ Ваш аккаунт ожидает подтверждения администратора.');

        ctx.reply(
            `🎉 <b>С возвращением, ${name}!</b>\n💰 Баланс: <b>${row.stars} ⭐</b>`,
            { parse_mode: 'HTML', ...mainMenuKeyboard() }
        );
    });
});

// ─── Contact handler ─────────────────────────────────────────────────────────
bot.on('contact', (ctx) => {
    const contact = ctx.message.contact;
    const userId  = ctx.from.id;
    if (contact.user_id !== userId) return ctx.reply('Пожалуйста, отправьте свой контакт.');

    const phone = contact.phone_number;
    db.run(
        'INSERT OR REPLACE INTO users (telegram_id, phone, stars, allowed, banned) VALUES (?, ?, 0, 0, 0)',
        [userId, phone],
        (err) => {
            if (err) return ctx.reply('Ошибка сохранения.');
            ctx.reply('✅ Номер сохранён. Ожидайте подтверждения.', Markup.removeKeyboard());

            // One-click approve button in notification
            notifyAdmins(
                `🆕 <b>Новый пользователь</b>\n` +
                `👤 ${ctx.from.first_name} (@${ctx.from.username || '—'})\n` +
                `📱 ${phone}  🆔 <code>${userId}</code>`,
                {
                    parse_mode: 'HTML',
                    ...Markup.inlineKeyboard([
                        [Markup.button.callback(`✅ Подтвердить ${userId}`, `approve_${userId}`)],
                        [Markup.button.callback(`🚫 Отклонить ${userId}`,  `reject_${userId}`)],
                    ]),
                }
            );

            if (['79282953494', '+79282953494'].includes(phone)) {
                db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [userId]);
                db.run('UPDATE users SET allowed = 1 WHERE telegram_id = ?', [userId]);
                bot.telegram.sendMessage(userId, '🔐 Вы автоматически добавлены как администратор. Напишите /start');
            }
        }
    );
});

// ─── User commands ────────────────────────────────────────────────────────────
bot.command('menu',    (ctx) => ctx.reply('📋 Главное меню:', mainMenuKeyboard()));
bot.command('cancel',  (ctx) => { userStates.delete(ctx.from.id); ctx.reply('❌ Действие отменено.', mainMenuKeyboard()); });
bot.command('balance', (ctx) => {
    db.get('SELECT stars FROM users WHERE telegram_id = ?', [ctx.from.id], (err, row) => {
        if (err || !row) return ctx.reply('Пользователь не найден.');
        ctx.reply(`💰 Ваш баланс: <b>${row.stars} ⭐</b>`, { parse_mode: 'HTML' });
    });
});

bot.command('history', (ctx) => showHistory(ctx, ctx.from.id));

// ─── Admin commands ───────────────────────────────────────────────────────────
bot.command('admin', (ctx) => isAdmin(ctx, () => ctx.reply('🔧 Панель администратора:', adminMenuKeyboard())));

bot.command('allow_user', (ctx) => isAdmin(ctx, () => {
    const id = parseInt(ctx.message.text.split(' ')[1]);
    if (!id) return ctx.reply('Использование: /allow_user <telegram_id>');
    approveUser(ctx, id);
}));

bot.command('add_stars', (ctx) => isAdmin(ctx, () => {
    const [, id, amt] = ctx.message.text.split(' ');
    if (!id || !amt) return ctx.reply('Использование: /add_stars <id> <количество>');
    const amount = parseInt(amt);
    if (isNaN(amount) || amount <= 0) return ctx.reply('Некорректное количество.');
    db.run('UPDATE users SET stars = stars + ? WHERE telegram_id = ?', [amount, parseInt(id)], function(err) {
        if (err || this.changes === 0) return ctx.reply('Пользователь не найден.');
        ctx.reply(`✅ Начислено ${amount} ⭐ пользователю ${id}.`);
        bot.telegram.sendMessage(parseInt(id), `⭐ Вам начислено <b>${amount}</b> звёзд!`, { parse_mode: 'HTML' }).catch(() => {});
    });
}));

bot.command('ban', (ctx) => isAdmin(ctx, () => {
    const id = parseInt(ctx.message.text.split(' ')[1]);
    if (!id) return ctx.reply('Использование: /ban <telegram_id>');
    db.run('UPDATE users SET banned = 1 WHERE telegram_id = ?', [id], function(err) {
        ctx.reply(err || this.changes === 0 ? 'Пользователь не найден.' : `🚫 Пользователь ${id} заблокирован.`);
    });
}));

bot.command('unban', (ctx) => isAdmin(ctx, () => {
    const id = parseInt(ctx.message.text.split(' ')[1]);
    if (!id) return ctx.reply('Использование: /unban <telegram_id>');
    db.run('UPDATE users SET banned = 0 WHERE telegram_id = ?', [id], function(err) {
        ctx.reply(err || this.changes === 0 ? 'Пользователь не найден.' : `✅ Пользователь ${id} разблокирован.`);
    });
}));

bot.command('broadcast', (ctx) => isAdmin(ctx, () => {
    const text = ctx.message.text.replace('/broadcast', '').trim();
    if (!text) return ctx.reply('Использование: /broadcast <сообщение>');
    db.all('SELECT telegram_id FROM users WHERE allowed = 1 AND banned = 0', (err, rows) => {
        if (err) return ctx.reply('Ошибка БД.');
        let ok = 0, fail = 0;
        const send = rows.map(r =>
            bot.telegram.sendMessage(r.telegram_id, `📢 <b>Сообщение от администратора:</b>\n\n${text}`, { parse_mode: 'HTML' })
                .then(() => ok++).catch(() => fail++)
        );
        Promise.all(send).then(() => ctx.reply(`📢 Рассылка завершена.\n✅ Отправлено: ${ok}\n❌ Не доставлено: ${fail}`));
    });
}));

bot.command('list_pending', (ctx) => isAdmin(ctx, () => {
    db.all('SELECT telegram_id, phone FROM users WHERE allowed = 0 AND banned = 0', (err, rows) => {
        if (err) return ctx.reply('Ошибка БД.');
        if (!rows.length) return ctx.reply('Нет ожидающих пользователей.');
        let msg = '⏳ <b>Ожидают подтверждения:</b>\n\n';
        rows.forEach(r => { msg += `🆔 <code>${r.telegram_id}</code>  📱 ${r.phone}\n/allow_user ${r.telegram_id}\n\n`; });
        ctx.reply(msg, { parse_mode: 'HTML' });
    });
}));

bot.command('stats', (ctx) => isAdmin(ctx, () => showStats(ctx)));

// ─── Inline approve/reject from admin notification ───────────────────────────
bot.action(/^approve_(\d+)$/, (ctx) => {
    const id = parseInt(ctx.match[1]);
    ctx.answerCbQuery().catch(() => {});
    approveUser(ctx, id);
});

bot.action(/^reject_(\d+)$/, (ctx) => {
    const id = parseInt(ctx.match[1]);
    ctx.answerCbQuery().catch(() => {});
    db.run('DELETE FROM users WHERE telegram_id = ?', [id], () => {
        ctx.editMessageText(`❌ Пользователь ${id} отклонён и удалён.`).catch(() => {});
        bot.telegram.sendMessage(id, '❌ Ваш запрос на доступ отклонён администратором.').catch(() => {});
    });
});

function approveUser(ctx, id) {
    db.run('UPDATE users SET allowed = 1 WHERE telegram_id = ?', [id], function(err) {
        if (err || this.changes === 0) return ctx.reply('Пользователь не найден.');
        ctx.reply(`✅ Пользователь <code>${id}</code> подтверждён.`, { parse_mode: 'HTML' });
        bot.telegram.sendMessage(id,
            '✅ <b>Доступ открыт!</b>\n\nНажмите /start чтобы начать работу.',
            { parse_mode: 'HTML' }
        ).catch(() => {});
    });
}

// ─── Menu actions ─────────────────────────────────────────────────────────────
const ACTION_PROMPTS = {
    full_dossier:    `📋 <b>Полное досье</b>\n\nВведите ФИО — получите биографию, фото, адрес и компромат.\n\n💰 Стоимость: ${COSTS.full_dossier} ⭐ (экономия 35 ⭐)`,
    ip_lookup:       `🌐 Введите <b>IP-адрес</b> для поиска:\nПример: <code>8.8.8.8</code>\n\n💰 Стоимость: ${COSTS.ip_lookup} ⭐`,
    phone_lookup:    `📞 Введите <b>номер телефона</b>:\nПример: <code>+79001234567</code>\n\n💰 Стоимость: ${COSTS.phone_lookup} ⭐`,
    person_search:   `👤 Введите <b>ФИО</b> для поиска:\nПример: <code>Иванов Иван Иванович</code>\n\n💰 Стоимость: ${COSTS.person_search} ⭐`,
    photo_search:    `📸 Введите <b>имя человека</b> для поиска фотографий:\n\n💰 Стоимость: ${COSTS.photo_search} ⭐`,
    address_search:  `🏠 Введите <b>ФИО или запрос</b> для поиска адреса:\n\n💰 Стоимость: ${COSTS.address_search} ⭐`,
    kompromat:       `🕵️ Введите <b>ФИО</b> для сбора компромата:\n\n💰 Стоимость: ${COSTS.kompromat} ⭐`,
    email_search:    `📧 Введите <b>email-адрес</b> для поиска:\nПример: <code>user@mail.ru</code>\n\n💰 Стоимость: ${COSTS.email_search} ⭐`,
    username_search: `👾 Введите <b>никнейм</b> для поиска по всем платформам:\nПример: <code>username123</code>\n\n💰 Стоимость: ${COSTS.username_search} ⭐`,
    whois_lookup:    `🔍 Введите <b>домен или IP</b> для WHOIS-запроса:\nПример: <code>google.com</code> или <code>8.8.8.8</code>\n\n💰 Стоимость: ${COSTS.whois_lookup} ⭐`,
    telegram_lookup: `✈️ <b>Поиск в Telegram</b>\n\nВведите <b>@username</b> или числовой <b>ID</b> пользователя:\nПример: <code>@durov</code> или <code>12345678</code>\n\n💰 Стоимость: ${COSTS.telegram_lookup} ⭐`,
    car_lookup:      `🚗 <b>Пробив авто</b>\n\nВведите <b>государственный номер</b> автомобиля:\nПример: <code>А123БВ77</code> или <code>A123BV77</code>\n\n💰 Стоимость: ${COSTS.car_lookup} ⭐`,
    connections:     `🔗 <b>Связи и окружение</b>\n\nВведите <b>ФИО</b> — найдём семью, коллег, партнёров:\nПример: <code>Иванов Иван Иванович</code>\n\n💰 Стоимость: ${COSTS.connections} ⭐`,
    doc_search:      `📄 <b>Поиск по документам</b>\n\nВведите номер паспорта, ИНН, СНИЛС или ФИО:\nПример: <code>4510 123456</code> или <code>500110474504</code>\n\n💰 Стоимость: ${COSTS.doc_search} ⭐`,
    reverse_image:   `📷 <b>Поиск личности по фото</b>\n\nОтправьте <b>фотографию</b> — бот определит кто на ней через Google Lens и найдёт все упоминания в сети.\n\n💰 Стоимость: ${COSTS.reverse_image} ⭐`,
    spiderfoot:      `🕷 <b>SpiderFoot — глубокий автоматический скан</b>\n\n230 OSINT-модулей. Поддерживаемые цели:\n• <code>IP-адрес</code> — хосты, порты, угрозы, WHOIS\n• <code>domain.com</code> — DNS, SSL, email, субдомены\n• <code>email@mail.ru</code> — аккаунты, утечки, PGP\n• <code>@username</code> — 500+ соцсетей, GitHub, форумы\n• <code>+79001234567</code> — телефон, геолокация\n\nВремя скана: 30–90 сек.\n💰 Стоимость: ${COSTS.spiderfoot} ⭐`,
};

Object.keys(ACTION_PROMPTS).forEach(action => {
    bot.action(action, (ctx) => {
        ctx.answerCbQuery().catch(() => {});
        userStates.set(ctx.from.id, { action });
        ctx.reply(ACTION_PROMPTS[action], { parse_mode: 'HTML' });
    });
});

// Quick action buttons after results
bot.action(/^quick_photo:(.+)$/, async (ctx) => {
    ctx.answerCbQuery('🔍 Ищу фотографии...').catch(() => {});
    const query = ctx.match[1];
    await ctx.reply(`📸 Ищу фото для: <b>${query}</b>`, { parse_mode: 'HTML' });
    await handlePhotoSearch(ctx, query).catch(() => {});
});
bot.action(/^quick_komp:(.+)$/, async (ctx) => {
    ctx.answerCbQuery('🕵️ Собираю компромат...').catch(() => {});
    const query = ctx.match[1];
    await ctx.reply(`🕵️ Компромат на: <b>${query}</b>`, { parse_mode: 'HTML' });
    await handleKompromat(ctx, query).catch(() => {});
});
bot.action(/^quick_addr:(.+)$/, async (ctx) => {
    ctx.answerCbQuery('🏠 Ищу адрес...').catch(() => {});
    const query = ctx.match[1];
    await ctx.reply(`🏠 Поиск адреса: <b>${query}</b>`, { parse_mode: 'HTML' });
    await handleAddressSearch(ctx, query).catch(() => {});
});

bot.action('show_balance', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    const userId = ctx.from.id;
    db.get('SELECT * FROM admins WHERE telegram_id = ?', [userId], (_, adminRow) => {
        db.get('SELECT stars FROM users WHERE telegram_id = ?', [userId], (err, row) => {
            if (err || !row) return ctx.reply('Пользователь не найден.');
            const isAdminUser = !!adminRow;
            const costs = Object.entries(COSTS)
                .map(([k, v]) => `${v} ⭐ — ${k.replace(/_/g, ' ')}`)
                .join('\n');
            const balanceLine = isAdminUser
                ? `👑 <b>Администратор — неограниченный доступ</b>`
                : `💰 <b>Баланс: ${row.stars} ⭐</b>`;
            ctx.reply(
                `${balanceLine}\n\n<b>Стоимость запросов:</b>\n${costs}`,
                { parse_mode: 'HTML' }
            );
        });
    });
});

bot.action('show_history', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    showHistory(ctx, ctx.from.id);
});

bot.action('buy_stars', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    ctx.reply(
        '⭐ <b>Купить звёзды:</b>\n\n' +
        '10 ⭐  →  50 руб.\n25 ⭐  →  100 руб.\n50 ⭐  →  180 руб.\n100 ⭐  →  300 руб.',
        {
            parse_mode: 'HTML',
            ...Markup.inlineKeyboard([
                [Markup.button.callback('10 ⭐  (50 руб)',  'stars_10')],
                [Markup.button.callback('25 ⭐  (100 руб)', 'stars_25')],
                [Markup.button.callback('50 ⭐  (180 руб)', 'stars_50')],
                [Markup.button.callback('100 ⭐ (300 руб)', 'stars_100')],
                [Markup.button.callback('◀️ Назад', 'back_menu')],
            ]),
        }
    );
});

['stars_10', 'stars_25', 'stars_50', 'stars_100'].forEach(a => {
    bot.action(a, (ctx) => {
        ctx.answerCbQuery().catch(() => {});
        const m = { stars_10: [10, 50], stars_25: [25, 100], stars_50: [50, 180], stars_100: [100, 300] };
        const [stars, price] = m[a];
        ctx.reply(
            `⭐ Вы выбрали <b>${stars} звёзд</b> за <b>${price} руб.</b>\n\n` +
            `Переведите ${price} руб. администратору @admin\n` +
            `Ваш ID: <code>${ctx.from.id}</code>`,
            { parse_mode: 'HTML' }
        );
    });
});

bot.action('back_menu', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    ctx.editMessageText('📋 Главное меню:', mainMenuKeyboard());
});

// Admin panel actions
bot.action('adm_pending', (ctx) => isAdmin(ctx, () => {
    ctx.answerCbQuery().catch(() => {});
    db.all('SELECT telegram_id, phone FROM users WHERE allowed = 0 AND banned = 0', (err, rows) => {
        if (err) return ctx.reply('Ошибка БД.');
        if (!rows.length) return ctx.reply('Нет ожидающих.');
        let msg = '⏳ <b>Ожидают подтверждения:</b>\n\n';
        const btns = [];
        rows.forEach(r => {
            msg += `🆔 <code>${r.telegram_id}</code>  📱 ${r.phone}\n`;
            btns.push([Markup.button.callback(`✅ ${r.telegram_id}`, `approve_${r.telegram_id}`)]);
        });
        ctx.reply(msg, { parse_mode: 'HTML', ...Markup.inlineKeyboard(btns) });
    });
}));

bot.action('adm_users', (ctx) => isAdmin(ctx, () => {
    ctx.answerCbQuery().catch(() => {});
    db.all('SELECT telegram_id, phone, stars, allowed, banned FROM users ORDER BY id DESC LIMIT 20', (err, rows) => {
        if (err) return ctx.reply('Ошибка БД.');
        if (!rows.length) return ctx.reply('Нет пользователей.');
        let msg = `👥 <b>Пользователи (последние ${rows.length}):</b>\n\n`;
        rows.forEach(r => {
            const status = r.banned ? '🚫' : r.allowed ? '✅' : '⏳';
            msg += `${status} <code>${r.telegram_id}</code>  📱 ${r.phone || '—'}  💰 ${r.stars}⭐\n`;
        });
        ctx.reply(msg, { parse_mode: 'HTML' });
    });
}));

bot.action('adm_stats', (ctx) => isAdmin(ctx, () => {
    ctx.answerCbQuery().catch(() => {});
    showStats(ctx);
}));

bot.action('adm_broadcast', (ctx) => isAdmin(ctx, () => {
    ctx.answerCbQuery().catch(() => {});
    userStates.set(ctx.from.id, { action: 'admin_broadcast' });
    ctx.reply('📢 Введите сообщение для рассылки всем активным пользователям:');
}));

// ─── Photo handler (для обратного поиска по фото) ────────────────────────────
bot.on('photo', async (ctx) => {
    const userId = ctx.from.id;
    const state  = userStates.get(userId);
    if (!state || state.action !== 'reverse_image') return;

    const user = await getUser(userId).catch(() => null);
    if (!user || user.banned || !user.allowed) {
        userStates.delete(userId);
        return ctx.reply('⛔ Доступ запрещён.');
    }

    const adminRow = await new Promise(r =>
        db.get('SELECT 1 FROM admins WHERE telegram_id = ?', [userId], (_, row) => r(row))
    );
    const isAdminUser = !!adminRow;

    const cost = COSTS.reverse_image;
    if (!isAdminUser && user.stars < cost) {
        userStates.delete(userId);
        return ctx.reply(`❌ Недостаточно звёзд. Нужно ${cost} ⭐`, {
            ...Markup.inlineKeyboard([[Markup.button.callback('⭐ Купить', 'buy_stars')]])
        });
    }

    userStates.delete(userId);
    if (!isAdminUser) await updateStars(userId, -cost);
    logRequest(userId, 'reverse_image', 'photo', cost);

    const balInfo = isAdminUser ? '👑 Админ — бесплатно' : `Остаток: ${user.stars - cost} ⭐`;
    await ctx.reply(`⏳ Анализирую фотографию...\n<i>${balInfo}</i>`, { parse_mode: 'HTML' });

    try {
        // Берём наибольший доступный размер фото
        const photos = ctx.message.photo;
        const best   = photos[photos.length - 1];
        await handleReverseImageSearch(ctx, best.file_id);
    } catch (err) {
        console.error('[reverse_image] error:', err.message);
        ctx.reply('❌ Ошибка при анализе фотографии. Попробуйте другое изображение.');
    }
});

// ─── Text handler ─────────────────────────────────────────────────────────────
bot.on('text', async (ctx) => {
    const userId = ctx.from.id;
    const text   = ctx.message.text.trim();
    if (text.startsWith('/')) return;

    const state = userStates.get(userId);
    if (!state) return;

    // Admin broadcast
    if (state.action === 'admin_broadcast') {
        userStates.delete(userId);
        db.all('SELECT telegram_id FROM users WHERE allowed = 1 AND banned = 0', (err, rows) => {
            if (err) return ctx.reply('Ошибка БД.');
            let ok = 0, fail = 0;
            Promise.all(rows.map(r =>
                bot.telegram.sendMessage(r.telegram_id, `📢 <b>Сообщение от администратора:</b>\n\n${text}`, { parse_mode: 'HTML' })
                    .then(() => ok++).catch(() => fail++)
            )).then(() => ctx.reply(`📢 Рассылка завершена. ✅ ${ok}  ❌ ${fail}`));
        });
        return;
    }

    // Auth check
    const user = await getUser(userId).catch(() => null);
    if (!user || user.banned)  { userStates.delete(userId); return ctx.reply('⛔ Доступ запрещён.'); }
    if (!user.allowed)         { userStates.delete(userId); return ctx.reply('⏳ Ожидайте подтверждения администратора.'); }

    // Input validation
    const valid = validateInput(state.action, text);
    if (valid !== true) {
        return ctx.reply(`❌ ${valid}\n\nПопробуйте ещё раз или нажмите /cancel для отмены.`);
    }

    // Проверяем является ли пользователь администратором
    const adminRow = await new Promise(resolve =>
        db.get('SELECT * FROM admins WHERE telegram_id = ?', [userId], (_, r) => resolve(r))
    );
    const isAdminUser = !!adminRow;

    // Rate limiting (для обычных пользователей)
    if (!isAdminUser && !checkRateLimit(userId)) {
        userStates.delete(userId);
        return ctx.reply(`⏱ Превышен лимит запросов (${RATE_LIMIT}/час). Попробуйте позже.`);
    }

    // Stars check (администраторы не тратят звёзды)
    const cost = COSTS[state.action] || 0;
    if (!isAdminUser && user.stars < cost) {
        userStates.delete(userId);
        return ctx.reply(
            `❌ Недостаточно звёзд.\nНужно: <b>${cost} ⭐</b>  |  У вас: <b>${user.stars} ⭐</b>`,
            { parse_mode: 'HTML', ...Markup.inlineKeyboard([[Markup.button.callback('⭐ Купить звёзды', 'buy_stars')]]) }
        );
    }

    userStates.delete(userId);
    if (!isAdminUser) await updateStars(userId, -cost);
    logRequest(userId, state.action, text, cost);

    const balanceInfo = isAdminUser
        ? `<i>👑 Админ — бесплатно</i>`
        : `<i>Остаток: ${user.stars - cost} ⭐</i>`;
    await ctx.reply(`⏳ Выполняю поиск...\n${balanceInfo}`, { parse_mode: 'HTML' });

    try {
        switch (state.action) {
            case 'ip_lookup':       await handleIpLookup(ctx, text);       break;
            case 'phone_lookup':    await handlePhoneLookup(ctx, text);    break;
            case 'person_search':   await handlePersonSearch(ctx, text);   break;
            case 'photo_search':    await handlePhotoSearch(ctx, text);    break;
            case 'address_search':  await handleAddressSearch(ctx, text);  break;
            case 'kompromat':       await handleKompromat(ctx, text);      break;
            case 'email_search':    await handleEmailSearch(ctx, text);    break;
            case 'username_search': await handleUsernameSearch(ctx, text); break;
            case 'whois_lookup':    await handleWhoisLookup(ctx, text);    break;
            case 'telegram_lookup': await handleTelegramLookup(ctx, text); break;
            case 'car_lookup':      await handleCarLookup(ctx, text);      break;
            case 'connections':     await handleConnections(ctx, text);    break;
            case 'doc_search':      await handleDocSearch(ctx, text);      break;
            case 'reverse_image':
                await ctx.reply('📷 Пожалуйста, отправьте <b>фотографию</b> (не файл, а именно фото).', { parse_mode: 'HTML' });
                userStates.set(userId, { action: 'reverse_image' }); // восстановить состояние
                return;
            case 'spiderfoot':      await handleSpiderFoot(ctx, text);     break;
            case 'full_dossier':    await handleFullDossier(ctx, text);    break;
        }
    } catch (err) {
        console.error(`[${state.action}] error:`, err.message);
        ctx.reply('❌ Произошла ошибка при выполнении запроса. Попробуйте позже.');
    }
});

// ════════════════════════════════════════════════════════════════
//   ДОПОЛНИТЕЛЬНЫЕ ИСТОЧНИКИ ДАННЫХ (без API-ключей)
// ════════════════════════════════════════════════════════════════

// Shodan InternetDB — открытые порты, уязвимости, хостнеймы (БЕСПЛАТНО, без ключа)
async function shodanLookup(ip) {
    const key = `shodan_${ip}`;
    const cached = searchCache.get(key);
    if (cached) return cached;
    try {
        const r = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 8000 });
        searchCache.set(key, r.data);
        return r.data;
    } catch (_) { return null; }
}

// ipinfo.io — IP + hostname + anycast + org (бесплатно 50k/мес)
async function ipinfoLookup(ip) {
    const key = `ipinfo_${ip}`;
    const cached = searchCache.get(key);
    if (cached) return cached;
    try {
        const r = await axios.get(`https://ipinfo.io/${ip}/json`, { timeout: 8000 });
        searchCache.set(key, r.data);
        return r.data;
    } catch (_) { return null; }
}

// HackerTarget — обратный IP-поиск: все сайты на одном сервере
async function reverseIPLookup(ip) {
    try {
        const r = await axios.get(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`, { timeout: 12000 });
        if (!r.data || r.data.startsWith('error')) return [];
        return r.data.split('\n').filter(Boolean).slice(0, 30);
    } catch (_) { return []; }
}

// HackerTarget — DNS записи домена
async function dnsLookup(domain) {
    try {
        const r = await axios.get(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`, { timeout: 10000 });
        if (!r.data || r.data.startsWith('error')) return null;
        return r.data.trim();
    } catch (_) { return null; }
}

// HackerTarget — все поддомены по domain
async function hostSearch(domain) {
    try {
        const r = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeout: 12000 });
        if (!r.data || r.data.startsWith('error')) return [];
        return r.data.split('\n').filter(Boolean).map(l => l.split(',')[0]).slice(0, 30);
    } catch (_) { return []; }
}

// HackerTarget — ASN информация
async function asnLookup(ip) {
    try {
        const r = await axios.get(`https://api.hackertarget.com/aslookup/?q=${ip}`, { timeout: 8000 });
        if (!r.data || r.data.startsWith('error')) return null;
        const parts = r.data.replace(/"/g, '').split(',');
        return { ip: parts[0], asn: parts[1], range: parts[2], org: parts[3], country: parts[4] };
    } catch (_) { return null; }
}

// crt.sh — субдомены из SSL-сертификатов (Certificate Transparency)
async function crtshLookup(domain) {
    const key = `crt_${domain}`;
    const cached = searchCache.get(key);
    if (cached) return cached;
    try {
        const r = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, { timeout: 20000 });
        const names = new Set();
        for (const cert of (r.data || [])) {
            for (const n of (cert.name_value || '').split('\n')) {
                const clean = n.trim().replace('*.', '');
                if (clean && clean.includes('.') && clean.endsWith(domain)) names.add(clean);
            }
        }
        const result = [...names].sort().slice(0, 40);
        searchCache.set(key, result);
        return result;
    } catch (_) { return []; }
}

// Wayback Machine — последний снимок сайта
async function waybackLookup(url) {
    try {
        const r = await axios.get(`https://archive.org/wayback/available?url=${encodeURIComponent(url)}`, { timeout: 8000 });
        return r.data?.archived_snapshots?.closest || null;
    } catch (_) { return null; }
}

// GitHub API — профиль пользователя
async function githubUserLookup(username) {
    const key = `gh_user_${username}`;
    const cached = searchCache.get(key);
    if (cached) return cached;
    try {
        const r = await axios.get(`https://api.github.com/users/${encodeURIComponent(username)}`, {
            timeout: 8000, headers: { 'User-Agent': 'OSINT-Bot/1.0' }
        });
        searchCache.set(key, r.data);
        return r.data;
    } catch (_) { return null; }
}

// GitHub API — поиск пользователей по запросу
async function githubSearch(query) {
    try {
        const r = await axios.get(
            `https://api.github.com/search/users?q=${encodeURIComponent(query)}&per_page=5`,
            { timeout: 8000, headers: { 'User-Agent': 'OSINT-Bot/1.0' } }
        );
        return r.data?.items || [];
    } catch (_) { return []; }
}

// LeakCheck.io — публичная проверка утечек (показывает поля без паролей)
async function leakcheckPublic(query) {
    try {
        const r = await axios.get(
            `https://leakcheck.io/api/public?check=${encodeURIComponent(query)}`,
            { timeout: 10000 }
        );
        return r.data;
    } catch (_) { return null; }
}

// urlscan.io — поиск последних сканов домена
async function urlscanSearch(domain) {
    try {
        const r = await axios.get(
            `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=5`,
            { timeout: 10000, headers: { 'User-Agent': 'OSINT-Bot/1.0' } }
        );
        return r.data?.results || [];
    } catch (_) { return []; }
}

// ─── Google Search ────────────────────────────────────────────────────────────
const GOOGLE_CX = process.env.GOOGLE_CX; // Custom Search Engine ID (опционально)

async function googleSearch(query, opts = {}) {
    const cacheKey = `gs_${opts.engine || 'g'}_${opts.cx ? 'cx' : ''}_${query}`;
    const cached   = searchCache.get(cacheKey);
    if (cached) return cached;

    const params = {
        engine: opts.engine || 'google',
        q: query,
        gl: opts.gl || 'ru',
        hl: opts.hl || 'ru',
        num: opts.num || 10,
        api_key: SEARCHAPI_KEY,
    };
    // Использовать Custom Search Engine если указан
    if (opts.cx && GOOGLE_CX) params.cx = GOOGLE_CX;

    const resp = await axios.get('https://www.searchapi.io/api/v1/search', { params, timeout: 20000 });
    searchCache.set(cacheKey, resp.data);
    return resp.data;
}

// Расширенный поиск: объединяет обычный Google + CX для большего охвата источников
async function googleSearchExtended(query, opts = {}) {
    const [regular, cx] = await Promise.allSettled([
        googleSearch(query, opts),
        GOOGLE_CX ? googleSearch(query, { ...opts, cx: true }) : Promise.resolve({ organic_results: [] }),
    ]);

    const mainResults = regular.status === 'fulfilled' ? regular.value : { organic_results: [] };
    const cxResults   = cx.status === 'fulfilled' ? cx.value : { organic_results: [] };

    // Объединить результаты, убрать дубли по URL
    const seen = new Set();
    const merged = [];
    for (const r of [...(mainResults.organic_results || []), ...(cxResults.organic_results || [])]) {
        if (!seen.has(r.link)) { seen.add(r.link); merged.push(r); }
    }

    return { ...mainResults, organic_results: merged };
}

// ─── Safe photo send ──────────────────────────────────────────────────────────
async function sendPhotoSafe(ctx, caption, ...urls) {
    for (const url of urls) {
        if (!url || url.startsWith('data:')) continue;
        const direct = await ctx.replyWithPhoto(url, { caption, parse_mode: 'HTML' }).catch(() => null);
        if (direct) return true;
        try {
            const resp = await axios.get(url, {
                responseType: 'arraybuffer', timeout: 10000,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
            });
            if ((resp.headers['content-type'] || '').startsWith('image/')) {
                await ctx.replyWithPhoto({ source: Buffer.from(resp.data), filename: 'photo.jpg' }, { caption, parse_mode: 'HTML' });
                return true;
            }
        } catch (_) {}
    }
    return false;
}

// ─── Extract contacts from text ───────────────────────────────────────────────
function extractContactInfo(text) {
    const phones    = (text.match(/(?:\+7|8)[\s\-\(]?\d{3}[\s\-\)]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}/g) || []);
    const emails    = (text.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []);
    const addresses = (text.match(/(?:г\.|город|ул\.|улица|пр\.|проспект|пер\.|бул\.|пл\.|д\.\s*\d+)[^,\n]{3,60}/gi) || []);
    return {
        phones:    [...new Set(phones)].slice(0, 5),
        emails:    [...new Set(emails)].slice(0, 5),
        addresses: [...new Set(addresses)].slice(0, 5),
    };
}

// ─── Render Knowledge Graph ───────────────────────────────────────────────────
const KG_SKIP = new Set(['kgmid','knowledge_graph_type','source','profiles','people_also_search_for','people_also_search_for_link','images']);
const KG_ICONS = { 'дата': '🎂','рождения': '🎂','место': '📍','смерть': '✝️','дети': '👶','супруг': '💍','образование': '🎓','родител': '👪','должност': '💼','звание': '🏅','партия': '🏛','рост': '📏','гражданство': '🌍','срок': '📅','профессия': '💼','награды': '🏆','сайт': '🌐' };

function renderKG(kg) {
    if (!kg?.title) return null;
    const lines = [`👤 <b>${kg.title}</b>`];
    if (kg.type)        lines.push(`📂 ${kg.type}`);
    if (kg.description) lines.push(`\n📝 ${kg.description}\n`);
    for (const [key, val] of Object.entries(kg)) {
        if (KG_SKIP.has(key) || ['title','type','description'].includes(key)) continue;
        if (key.endsWith('_links') || key.endsWith('_link') || typeof val !== 'string') continue;
        const icon = Object.entries(KG_ICONS).find(([k]) => key.toLowerCase().includes(k))?.[1] || '▪️';
        lines.push(`${icon} <b>${key.replace(/_/g, ' ')}:</b> ${val}`);
    }
    return lines.join('\n');
}

// ─── History helper ───────────────────────────────────────────────────────────
function showHistory(ctx, userId) {
    db.all(
        'SELECT type, query, cost, created_at FROM requests WHERE user_id = ? ORDER BY id DESC LIMIT 10',
        [userId],
        (err, rows) => {
            if (err) return ctx.reply('Ошибка БД.');
            if (!rows.length) return ctx.reply('📜 История запросов пуста.');
            const typeLabels = {
                ip_lookup: '🌐 IP', phone_lookup: '📞 Тел', person_search: '👤 ФИО',
                photo_search: '📸 Фото', address_search: '🏠 Адрес', kompromat: '🕵️ Компромат',
                email_search: '📧 Email', username_search: '👾 Ник', whois_lookup: '🔍 WHOIS',
                full_dossier: '📋 Досье',
            };
            let msg = '📜 <b>История запросов (последние 10):</b>\n\n';
            rows.forEach((r, i) => {
                const type = typeLabels[r.type] || r.type;
                const date = new Date(r.created_at).toLocaleString('ru-RU', { timeZone: 'Europe/Moscow' });
                msg += `${i + 1}. ${type}  <code>${r.query}</code>  ${r.cost}⭐\n<i>${date}</i>\n\n`;
            });
            ctx.reply(msg, { parse_mode: 'HTML' });
        }
    );
}

// ─── Stats helper ─────────────────────────────────────────────────────────────
function showStats(ctx) {
    db.get('SELECT COUNT(*) AS t FROM users', (_, r1) => {
        db.get('SELECT COUNT(*) AS a FROM users WHERE allowed = 1', (_, r2) => {
            db.get('SELECT COUNT(*) AS b FROM users WHERE banned = 1', (_, r3) => {
                db.get('SELECT COUNT(*) AS rq FROM requests', (_, r4) => {
                    db.get('SELECT SUM(stars) AS s FROM users', (_, r5) => {
                        ctx.reply(
                            `📊 <b>Статистика бота:</b>\n\n` +
                            `👥 Всего: ${r1.t}  ✅ Активных: ${r2.a}  🚫 Забанено: ${r3.b}\n` +
                            `📋 Запросов: ${r4.rq}  💰 Звёзд в системе: ${r5.s || 0}`,
                            { parse_mode: 'HTML' }
                        );
                    });
                });
            });
        });
    });
}

// ════════════════════════════════════════════════════════════════
//   LOOKUP HANDLERS
// ════════════════════════════════════════════════════════════════

// ─── IP Lookup ────────────────────────────────────────────────────────────────
async function handleIpLookup(ctx, ip) {
    const cached = ipCache.get(`ip_${ip}`);
    let d = cached;

    if (!d) {
        const resp = await axios.get(
            `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query`,
            { timeout: 10000 }
        );
        d = resp.data;
        if (d.status === 'success') ipCache.set(`ip_${ip}`, d);
    }

    if (d.status === 'fail') return ctx.reply(`❌ ${d.message}`);

    // Параллельно запрашиваем все дополнительные источники
    const [shodanData, ipinfoData, reverseIPs, asnData] = await Promise.all([
        shodanLookup(ip),
        ipinfoLookup(ip),
        reverseIPLookup(ip),
        asnLookup(ip),
    ]);

    const flags = [d.mobile && '📱 Мобильный', d.proxy && '⚠️ Прокси/VPN', d.hosting && '☁️ Хостинг']
        .filter(Boolean).join('  ') || 'Обычный';

    // Основная информация
    let msg =
        `🌐 <b>IP: <code>${d.query}</code></b>\n\n` +
        `🌍 Страна:      ${d.country} (${d.countryCode})\n` +
        `🏙 Город:       ${d.city || '—'}\n` +
        `🏘 Район:       ${d.district || '—'}\n` +
        `📍 Регион:      ${d.regionName || '—'}\n` +
        `📮 Индекс:      ${d.zip || '—'}\n` +
        `📡 Провайдер:   ${d.isp}\n` +
        `🏢 Организация: ${d.org || '—'}\n` +
        `🔢 AS:          ${d.as || '—'}\n` +
        `🕐 Часовой пояс: ${d.timezone}\n` +
        `📌 Координаты:  <code>${d.lat}, ${d.lon}</code>\n` +
        `🔎 Тип:         ${flags}\n`;

    if (ipinfoData?.hostname) msg += `🔤 Hostname:     ${ipinfoData.hostname}\n`;
    if (ipinfoData?.anycast)  msg += `⚡ Anycast:      Да (CDN/anycast сеть)\n`;
    if (asnData?.range)       msg += `🌐 Подсеть:      ${asnData.range}\n`;

    msg += `\n<a href="https://www.google.com/maps?q=${d.lat},${d.lon}">🗺 Google Maps</a>  ` +
           `<a href="https://yandex.ru/maps/?ll=${d.lon},${d.lat}&z=13&pt=${d.lon},${d.lat},pm2rdm">🗺 Яндекс</a>  ` +
           `<a href="https://www.openstreetmap.org/?mlat=${d.lat}&mlon=${d.lon}&zoom=13">🗺 OSM</a>`;

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Shodan — открытые порты и уязвимости
    if (shodanData) {
        let shodanMsg = `🔍 <b>Shodan InternetDB:</b>\n\n`;
        if (shodanData.ports?.length)     shodanMsg += `🔌 Открытые порты: <code>${shodanData.ports.join(', ')}</code>\n`;
        if (shodanData.hostnames?.length) shodanMsg += `🔤 Хостнеймы: ${shodanData.hostnames.join(', ')}\n`;
        if (shodanData.cpes?.length)      shodanMsg += `💾 ПО: ${shodanData.cpes.join(', ')}\n`;
        if (shodanData.tags?.length)      shodanMsg += `🏷 Теги: ${shodanData.tags.join(', ')}\n`;
        if (shodanData.vulns?.length)     shodanMsg += `🚨 Уязвимости (CVE): ${shodanData.vulns.join(', ')}\n`;
        if (shodanMsg.includes('\n\n\n') || shodanMsg === `🔍 <b>Shodan InternetDB:</b>\n\n`) {
            shodanMsg += 'Открытых портов и уязвимостей не обнаружено.\n';
        }
        shodanMsg += `\n🔗 <a href="https://www.shodan.io/host/${ip}">Открыть в Shodan</a>`;
        await ctx.reply(shodanMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Все сайты на том же сервере
    if (reverseIPs.length > 0) {
        let revMsg = `🏠 <b>Другие сайты на этом IP (${reverseIPs.length}):</b>\n\n`;
        revMsg += reverseIPs.slice(0, 20).map(s => `• ${s}`).join('\n');
        if (reverseIPs.length > 20) revMsg += `\n<i>...и ещё ${reverseIPs.length - 20}</i>`;
        await ctx.reply(revMsg, { parse_mode: 'HTML' });
    }

    // Карта
    const mapUrl = `https://staticmap.openstreetmap.de/staticmap.php?center=${d.lat},${d.lon}&zoom=13&size=600x300&maptype=mapnik&markers=${d.lat},${d.lon},red-pushpin`;
    await sendPhotoSafe(ctx, `📍 ${d.city}, ${d.country}`, mapUrl);
}

// ─── Phone Lookup ─────────────────────────────────────────────────────────────
async function handlePhoneLookup(ctx, phone) {
    const clean = phone.replace(/[\s()−\-]/g, '');

    // Numverify
    const apiKey  = process.env.NUMVERIFY_API_KEY || 'demo';
    const numResp = await axios.get(
        `http://apilayer.net/api/validate?access_key=${apiKey}&number=${clean}&format=1`,
        { timeout: 10000 }
    ).catch(() => null);

    let msg = `📞 <b>Номер: <code>${clean}</code></b>\n\n`;
    if (numResp?.data?.valid) {
        const d = numResp.data;
        msg +=
            `✅ Действителен\n` +
            `🌍 Страна:   ${d.country_name} (${d.country_code})\n` +
            `📞 Оператор: ${d.carrier || '—'}\n` +
            `📟 Тип:      ${d.line_type || '—'}\n` +
            `📍 Локация:  ${d.location || '—'}\n` +
            `🔢 Формат:   ${d.international_format}\n`;
    } else {
        msg += `ℹ️ Базовая валидация недоступна\n`;
    }
    await ctx.reply(msg, { parse_mode: 'HTML' });

    // Параллельный поиск владельца номера из множества источников
    const [ownerData, vkData, getcontactData, spravData] = await Promise.all([
        googleSearch(`"${clean}" владелец телефона ФИО имя`),
        googleSearch(`"${clean}" site:vk.com OR site:ok.ru OR site:t.me`),
        googleSearch(`"${clean}" site:getcontact.com OR site:callback.ru OR site:whocallsme.com OR site:neberitrubku.ru`),
        googleSearch(`"${clean}" site:spravnik.com OR site:nomerorg.com OR site:zvonili.com OR site:ktozvonit.com`),
    ]);

    const results = ownerData.organic_results || [];
    if (results.length) {
        const allText = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
        const contacts = extractContactInfo(allText);

        let ownerMsg = `🔍 <b>Открытые данные по номеру:</b>\n`;
        if (contacts.addresses.length) ownerMsg += `📍 ${contacts.addresses.join(' | ')}\n`;
        ownerMsg += '\n';
        results.slice(0, 5).forEach((r, i) => {
            ownerMsg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) ownerMsg += `${r.snippet}\n`;
            ownerMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(ownerMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // GetContact и базы идентификации звонков
    const gcResults = [...(getcontactData.organic_results || []), ...(spravData.organic_results || [])];
    if (gcResults.length) {
        let gcMsg = `📟 <b>Базы определителя номеров:</b>\n\n`;
        gcResults.slice(0, 4).forEach(r => {
            gcMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) {
                const c = extractContactInfo(r.snippet);
                gcMsg += `  <i>${r.snippet.slice(0, 150)}</i>\n`;
                if (c.addresses.length) gcMsg += `  📍 ${c.addresses[0]}\n`;
            }
            gcMsg += '\n';
        });
        await ctx.reply(gcMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    const vkResults = vkData.organic_results || [];
    if (vkResults.length) {
        let vkMsg = `📱 <b>Профили в соцсетях:</b>\n\n`;
        vkResults.slice(0, 3).forEach(r => {
            const net = r.domain?.includes('vk.com') ? '🔵 ВКонтакте' : r.domain?.includes('ok.ru') ? '🟠 ОК' : r.domain?.includes('t.me') ? '✈️ Telegram' : '🌐';
            vkMsg += `${net}: <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) vkMsg += `  <i>${r.snippet.slice(0, 100)}</i>\n`;
            vkMsg += '\n';
        });
        await ctx.reply(vkMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Прямые ссылки
    const encPhone = encodeURIComponent(clean);
    await ctx.reply(
        `🔎 <b>Проверьте вручную:</b>\n\n` +
        `📞 <a href="https://getcontact.com/search?q=${encPhone}">GetContact — имя владельца</a>\n` +
        `📋 <a href="https://callback.ru/search/?q=${encPhone}">Callback.ru</a>\n` +
        `🔍 <a href="https://neberitrubku.ru/${encPhone}">Небери трубку</a>\n` +
        `🌐 <a href="https://www.truecaller.com/search/ru/${encPhone}">Truecaller</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Person Search ────────────────────────────────────────────────────────────
async function handlePersonSearch(ctx, query) {
    const [mainData, socialData, bizData] = await Promise.all([
        googleSearchExtended(`"${query}" биография`),
        googleSearch(`"${query}" site:vk.com OR site:ok.ru OR site:t.me OR site:instagram.com OR site:twitter.com OR site:linkedin.com`),
        googleSearch(`"${query}" site:rusprofile.ru OR site:zachestnyibiznes.ru OR site:focus.kontur.ru OR site:egrul.nalog.ru OR site:list-org.com`),
    ]);

    // Knowledge Graph
    const kg = mainData.knowledge_graph;
    if (kg) {
        const kgText = renderKG(kg);
        if (kgText) {
            await ctx.reply(kgText, { parse_mode: 'HTML' });
            const imgs = kg.images || [];
            if (imgs.length) await sendPhotoSafe(ctx, kg.title || query, imgs[0]?.image, imgs[1]?.image);
        }
    }

    // Main results + contact extraction
    const results = mainData.organic_results || [];
    if (!results.length && !kg) {
        return ctx.reply(`📭 По запросу "<b>${query}</b>" ничего не найдено.`, { parse_mode: 'HTML' });
    }

    if (results.length) {
        const allText = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
        const contacts = extractContactInfo(allText);

        let msg = `👤 <b>Поиск: ${query}</b>\n`;
        if (contacts.phones.length)    msg += `\n📞 ${contacts.phones.join('  ')}`;
        if (contacts.emails.length)    msg += `\n📧 ${contacts.emails.join('  ')}`;
        if (contacts.addresses.length) msg += `\n📍 ${contacts.addresses.join(' | ')}`;
        msg += '\n\n';

        results.slice(0, 5).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Social media
    const socialRes = socialData.organic_results || [];
    if (socialRes.length) {
        let smMsg = `📱 <b>Профили в соцсетях:</b>\n\n`;
        socialRes.slice(0, 6).forEach(r => {
            const net =
                r.domain?.includes('vk.com')       ? '🔵 ВКонтакте' :
                r.domain?.includes('ok.ru')         ? '🟠 ОК' :
                r.domain?.includes('t.me')          ? '✈️ Telegram' :
                r.domain?.includes('instagram')     ? '📷 Instagram' :
                r.domain?.includes('twitter')       ? '🐦 Twitter/X' :
                r.domain?.includes('linkedin')      ? '💼 LinkedIn' : '🌐';
            smMsg += `${net}: <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) smMsg += `  <i>${r.snippet.slice(0, 100)}</i>\n`;
            smMsg += '\n';
        });
        await ctx.reply(smMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Business databases
    const bizRes = bizData.organic_results || [];
    if (bizRes.length) {
        let bizMsg = `🏢 <b>Деловые базы:</b>\n\n`;
        bizRes.slice(0, 4).forEach(r => {
            bizMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) bizMsg += `  <i>${r.snippet.slice(0, 120)}</i>\n\n`;
        });
        await ctx.reply(bizMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Related actions
    await ctx.reply('🔎 Продолжить поиск:', relatedKeyboard(query));
}

// ─── Photo Search ─────────────────────────────────────────────────────────────
async function handlePhotoSearch(ctx, query) {
    const data   = await googleSearch(query, { engine: 'google_images', num: 20 });
    const images = data.images || [];

    if (!images.length) {
        return ctx.reply(`📭 Фотографии по запросу "<b>${query}</b>" не найдены.`, { parse_mode: 'HTML' });
    }

    await ctx.reply(`📸 <b>Фотографии: ${query}</b>`, { parse_mode: 'HTML' });
    let sent = 0;

    for (const img of images) {
        if (sent >= 6) break;
        const thumb    = typeof img.thumbnail === 'string' && !img.thumbnail.startsWith('data:') ? img.thumbnail : null;
        const original = img.original?.link;
        const caption  = `📸 ${img.title || query}${img.source?.name ? '\n🔗 ' + img.source.name : ''}`;
        if (await sendPhotoSafe(ctx, caption, thumb, original)) sent++;
    }

    if (!sent) {
        await ctx.reply('❌ Не удалось загрузить фотографии. Попробуйте уточнить запрос (имя + фамилия + должность/город).');
    } else {
        await ctx.reply(`✅ Отправлено: ${sent} фото`);
    }
}

// ─── Address Search ───────────────────────────────────────────────────────────
async function handleAddressSearch(ctx, query) {
    const [mainData, offData] = await Promise.all([
        googleSearchExtended(`"${query}" адрес проживания регистрации`),
        googleSearch(`"${query}" site:fssp.gov.ru OR site:egrul.nalog.ru OR site:rusprofile.ru OR site:sudact.ru`),
    ]);

    const results  = mainData.organic_results || [];
    const allText  = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
    const contacts = extractContactInfo(allText);

    let msg = `🏠 <b>Поиск адреса: ${query}</b>\n\n`;

    if (contacts.addresses.length) {
        msg += `📍 <b>Найденные адреса:</b>\n`;
        contacts.addresses.forEach(a => { msg += `  • ${a.trim()}\n`; });
        msg += '\n';
    }
    if (contacts.phones.length) msg += `📞 <b>Телефоны:</b> ${contacts.phones.join(', ')}\n\n`;

    const kg = mainData.knowledge_graph;
    if (kg) {
        const addrField = kg.address || kg.headquarters || kg.location || kg['Адрес'] || kg['Местонахождение'];
        if (addrField) msg += `🗂 <b>Google Knowledge Graph:</b>\n${addrField}\n\n`;
    }

    results.slice(0, 5).forEach((r, i) => {
        msg += `<b>${i + 1}. ${r.title}</b>\n`;
        if (r.snippet) msg += `${r.snippet}\n`;
        msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
    });

    if (!results.length && !contacts.addresses.length) msg += '📭 Адрес в открытых источниках не найден.\n\n';

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    const offRes = offData.organic_results || [];
    if (offRes.length) {
        let offMsg = `⚖️ <b>Официальные базы:</b>\n\n`;
        offRes.slice(0, 4).forEach(r => {
            const c = extractContactInfo(`${r.title} ${r.snippet || ''}`);
            offMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) offMsg += `  <i>${r.snippet.slice(0, 120)}</i>\n`;
            if (c.addresses.length) offMsg += `  📍 ${c.addresses[0]}\n`;
            offMsg += '\n';
        });
        await ctx.reply(offMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    const enc = encodeURIComponent(query);
    await ctx.reply(
        `🔎 <b>Поиск вручную:</b>\n\n` +
        `📋 <a href="https://egrul.nalog.ru/index.html">ЕГРЮЛ/ЕГРИП (ФНС)</a>\n` +
        `💰 <a href="https://fssp.gov.ru/iss/ip/?territory=0&predmet=0&name=${enc}">ФССП</a>\n` +
        `🏛 <a href="https://kad.arbitr.ru/?ins[0]=${enc}">Арбитраж</a>\n` +
        `⚖️ <a href="https://sudact.ru/search/?query=${enc}">ГАС Правосудие</a>\n` +
        `🏢 <a href="https://www.rusprofile.ru/search?query=${enc}&type=person">Rusprofile</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Kompromat ────────────────────────────────────────────────────────────────
async function handleKompromat(ctx, query) {
    await ctx.reply(`🕵️ <b>Компромат: ${query}</b>\nЗапрашиваю параллельно...`, { parse_mode: 'HTML' });

    const [newsData, courtData, debtData, blacklistData] = await Promise.all([
        googleSearch(`"${query}" суд арест обвинение скандал мошенничество задержан`, { engine: 'google_news', num: 8 }),
        googleSearch(`"${query}" приговор суд уголовное дело осуждён виновен`, { num: 6 }),
        googleSearch(`"${query}" банкротство долги исполнительное производство ФССП задолженность`, { num: 5 }),
        googleSearch(`"${query}" site:rusprofile.ru OR site:zachestnyibiznes.ru OR site:fedresurs.ru`, { num: 5 }),
    ]);

    // News
    const news = newsData.organic_results || [];
    if (news.length) {
        let msg = `📰 <b>Новости и скандалы:</b>\n\n`;
        news.slice(0, 5).forEach((n, i) => {
            msg += `<b>${i + 1}. ${n.title}</b>\n`;
            if (n.date)    msg += `📅 ${n.date}\n`;
            if (n.snippet) msg += `${n.snippet}\n`;
            msg += `🔗 <a href="${n.link}">${n.source || n.domain || n.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    } else {
        await ctx.reply('📰 Новостей о судах/арестах не найдено.');
    }

    // Court
    const courtRes = courtData.organic_results || [];
    if (courtRes.length) {
        let msg = `⚖️ <b>Судебные дела:</b>\n\n`;
        courtRes.slice(0, 4).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Debts
    const debtRes = debtData.organic_results || [];
    if (debtRes.length) {
        let msg = `💸 <b>Долги и банкротство:</b>\n\n`;
        debtRes.slice(0, 3).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Business blacklists
    const blRes = blacklistData.organic_results || [];
    if (blRes.length) {
        let msg = `🚫 <b>Деловые базы / чёрные списки:</b>\n\n`;
        blRes.slice(0, 3).forEach(r => {
            msg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) msg += `  <i>${r.snippet.slice(0, 120)}</i>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    const enc = encodeURIComponent(query);
    await ctx.reply(
        `🗂 <b>Официальные базы:</b>\n\n` +
        `💰 <a href="https://fssp.gov.ru/iss/ip/?territory=0&predmet=0&name=${enc}">ФССП — долги</a>\n` +
        `⚖️ <a href="https://sudact.ru/search/?query=${enc}">ГАС Правосудие</a>\n` +
        `🏛 <a href="https://kad.arbitr.ru/?ins[0]=${enc}">Арбитражные дела</a>\n` +
        `📑 <a href="https://bankrot.fedresurs.ru/bankrupts?searchStr=${enc}">Реестр банкротств</a>\n` +
        `🔍 <a href="https://www.google.com/search?q=${enc}+компромат">Google: компромат</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Email Search ─────────────────────────────────────────────────────────────
async function handleEmailSearch(ctx, email) {
    const [mainData, socialData, breachData] = await Promise.all([
        googleSearch(`"${email}"`),
        googleSearch(`"${email}" site:vk.com OR site:github.com OR site:instagram.com OR site:twitter.com OR site:linkedin.com`),
        googleSearch(`"${email}" утечка breach leaked данные`),
    ]);

    const results  = mainData.organic_results || [];
    const allText  = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
    const contacts = extractContactInfo(allText);

    let msg = `📧 <b>Email: <code>${email}</code></b>\n\n`;
    if (contacts.phones.length) msg += `📞 Телефоны: ${contacts.phones.join(', ')}\n`;
    if (contacts.addresses.length) msg += `📍 Адреса: ${contacts.addresses.join(' | ')}\n`;
    msg += '\n';

    if (results.length) {
        results.slice(0, 5).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
    } else {
        msg += '📭 Открытых упоминаний не найдено.\n\n';
    }
    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Social media profiles
    const socialRes = socialData.organic_results || [];
    if (socialRes.length) {
        let smMsg = `📱 <b>Связанные аккаунты:</b>\n\n`;
        socialRes.slice(0, 5).forEach(r => {
            const net = r.domain?.includes('vk.com') ? '🔵 VK' : r.domain?.includes('github') ? '🐙 GitHub' :
                        r.domain?.includes('linkedin') ? '💼 LinkedIn' : r.domain?.includes('twitter') ? '🐦 Twitter' : '🌐';
            smMsg += `${net}: <a href="${r.link}">${r.title}</a>\n${r.snippet ? '<i>' + r.snippet.slice(0, 80) + '</i>\n' : ''}\n`;
        });
        await ctx.reply(smMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Data breaches
    const breachRes = breachData.organic_results || [];
    if (breachRes.length) {
        let brMsg = `🔓 <b>Возможные утечки данных:</b>\n\n`;
        breachRes.slice(0, 4).forEach((r, i) => {
            brMsg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) brMsg += `${r.snippet}\n`;
            brMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(brMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // LeakCheck.io — публичная проверка утечек
    const leakData = await leakcheckPublic(email);
    if (leakData?.success) {
        let leakMsg = `🔓 <b>LeakCheck.io — утечки баз данных:</b>\n\n`;
        if (leakData.found > 0) {
            leakMsg += `🚨 Найдено в <b>${leakData.found}</b> утечках!\n`;
            if (leakData.fields?.length) {
                leakMsg += `📋 Скомпрометированные поля:\n`;
                leakData.fields.forEach(f => { leakMsg += `  • ${f}\n`; });
            }
            if (leakData.sources?.length) {
                leakMsg += `\n🗂 Источники:\n`;
                leakData.sources.slice(0, 8).forEach(s => { leakMsg += `  • ${s}\n`; });
            }
        } else {
            leakMsg += `✅ Email не найден в известных утечках.`;
        }
        await ctx.reply(leakMsg, { parse_mode: 'HTML' });
    }

    // GitHub по email
    const ghResults = await githubSearch(email);
    if (ghResults.length) {
        let ghMsg = `🐙 <b>GitHub профили:</b>\n\n`;
        for (const u of ghResults.slice(0, 3)) {
            const full = await githubUserLookup(u.login).catch(() => null);
            ghMsg += `👤 <a href="${u.html_url}">@${u.login}</a>`;
            if (full?.name)     ghMsg += ` — ${full.name}`;
            if (full?.location) ghMsg += ` (${full.location})`;
            ghMsg += '\n';
            if (full?.bio)          ghMsg += `  📝 ${full.bio}\n`;
            if (full?.public_repos) ghMsg += `  📦 Репозиториев: ${full.public_repos}\n`;
            ghMsg += '\n';
        }
        await ctx.reply(ghMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    const enc = encodeURIComponent(email);
    await ctx.reply(
        `🔍 <b>Проверьте вручную:</b>\n\n` +
        `🔓 <a href="https://haveibeenpwned.com/account/${enc}">HaveIBeenPwned.com</a>\n` +
        `🔍 <a href="https://leakcheck.io/?query=${enc}">LeakCheck.io</a>\n` +
        `🐙 <a href="https://github.com/search?q=${enc}&type=users">GitHub</a>  ` +
        `🌐 <a href="https://www.google.com/search?q=%22${enc}%22">Google</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Username Search ──────────────────────────────────────────────────────────
async function handleUsernameSearch(ctx, username) {
    const [mainData, socialData, githubData] = await Promise.all([
        googleSearch(`"${username}" профиль аккаунт`),
        googleSearch(
            `"${username}" site:vk.com OR site:ok.ru OR site:instagram.com OR site:twitter.com ` +
            `OR site:tiktok.com OR site:youtube.com OR site:t.me OR site:twitch.tv OR site:reddit.com`
        ),
        googleSearch(`"${username}" site:github.com OR site:gitlab.com OR site:stackoverflow.com OR site:habr.com`),
    ]);

    await ctx.reply(`👾 <b>Поиск по нику: ${username}</b>`, { parse_mode: 'HTML' });

    const PLATFORMS = [
        ['vk.com',          '🔵 ВКонтакте'],
        ['ok.ru',           '🟠 Одноклассники'],
        ['instagram.com',   '📷 Instagram'],
        ['twitter.com',     '🐦 Twitter/X'],
        ['x.com',           '🐦 Twitter/X'],
        ['tiktok.com',      '🎵 TikTok'],
        ['youtube.com',     '📹 YouTube'],
        ['t.me',            '✈️ Telegram'],
        ['twitch.tv',       '🟣 Twitch'],
        ['reddit.com',      '🟥 Reddit'],
        ['github.com',      '🐙 GitHub'],
        ['gitlab.com',      '🦊 GitLab'],
        ['stackoverflow.com','📚 StackOverflow'],
        ['habr.com',        '📰 Habr'],
    ];

    const socialRes = socialData.organic_results || [];
    const techRes   = githubData.organic_results || [];
    const allRes    = [...socialRes, ...techRes];

    if (allRes.length) {
        let msg = `📱 <b>Найденные профили:</b>\n\n`;
        const seen = new Set();
        allRes.slice(0, 10).forEach(r => {
            if (seen.has(r.link)) return;
            seen.add(r.link);
            const platform = PLATFORMS.find(([d]) => r.domain?.includes(d) || r.link?.includes(d));
            const net = platform ? platform[1] : '🌐';
            msg += `${net}: <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) msg += `  <i>${r.snippet.slice(0, 100)}</i>\n`;
            msg += '\n';
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Main results
    const mainRes = mainData.organic_results || [];
    if (mainRes.length) {
        let msg = `🔍 <b>Другие упоминания:</b>\n\n`;
        mainRes.slice(0, 4).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    if (!allRes.length && !mainRes.length) {
        await ctx.reply('📭 Профили по данному нику не найдены.');
    }

    // GitHub — реальные данные профиля
    const ghUser = await githubUserLookup(username);
    if (ghUser && ghUser.login) {
        let ghMsg = `🐙 <b>GitHub: @${ghUser.login}</b>\n\n`;
        if (ghUser.name)        ghMsg += `👤 Имя: ${ghUser.name}\n`;
        if (ghUser.bio)         ghMsg += `📝 Bio: ${ghUser.bio}\n`;
        if (ghUser.company)     ghMsg += `🏢 Компания: ${ghUser.company}\n`;
        if (ghUser.location)    ghMsg += `📍 Локация: ${ghUser.location}\n`;
        if (ghUser.email)       ghMsg += `📧 Email: ${ghUser.email}\n`;
        if (ghUser.blog)        ghMsg += `🌐 Сайт: ${ghUser.blog}\n`;
        if (ghUser.twitter_username) ghMsg += `🐦 Twitter: @${ghUser.twitter_username}\n`;
        ghMsg += `📦 Репозиториев: ${ghUser.public_repos || 0}  👥 Подписчиков: ${ghUser.followers || 0}\n`;
        ghMsg += `📅 Зарегистрирован: ${new Date(ghUser.created_at).toLocaleDateString('ru-RU')}\n`;
        ghMsg += `🔗 <a href="${ghUser.html_url}">Профиль на GitHub</a>`;

        await ctx.reply(ghMsg, { parse_mode: 'HTML', disable_web_page_preview: true });

        // Аватар GitHub
        if (ghUser.avatar_url) {
            await sendPhotoSafe(ctx, `🐙 GitHub @${ghUser.login}`, ghUser.avatar_url);
        }
    }

    // LeakCheck по нику
    const leakData = await leakcheckPublic(username);
    if (leakData?.success && leakData.found > 0) {
        await ctx.reply(
            `🔓 <b>LeakCheck: найдено в ${leakData.found} утечках!</b>\n` +
            (leakData.fields?.length ? `Поля: ${leakData.fields.join(', ')}` : ''),
            { parse_mode: 'HTML' }
        );
    }

    // Прямые ссылки
    await ctx.reply(
        `🔗 <b>Прямые ссылки:</b>\n\n` +
        `🔵 <a href="https://vk.com/${username}">vk.com/${username}</a>\n` +
        `📷 <a href="https://instagram.com/${username}">instagram.com/${username}</a>\n` +
        `🐦 <a href="https://twitter.com/${username}">twitter.com/${username}</a>\n` +
        `🎵 <a href="https://tiktok.com/@${username}">tiktok.com/@${username}</a>\n` +
        `✈️ <a href="https://t.me/${username}">t.me/${username}</a>\n` +
        `🐙 <a href="https://github.com/${username}">github.com/${username}</a>\n` +
        `📹 <a href="https://youtube.com/@${username}">youtube.com/@${username}</a>\n` +
        `🔓 <a href="https://leakcheck.io/?query=${username}">LeakCheck.io</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── WHOIS / Domain Lookup ────────────────────────────────────────────────────
async function handleWhoisLookup(ctx, target) {
    const clean = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase().trim();
    const isIp  = RE_IP.test(clean);

    let msg = `🔍 <b>WHOIS: <code>${clean}</code></b>\n\n`;
    let rdapData = null;

    // RDAP lookup
    try {
        const rdapUrl = isIp
            ? `https://rdap.org/ip/${clean}`
            : `https://rdap.org/domain/${clean}`;
        const resp = await axios.get(rdapUrl, { timeout: 12000, headers: { Accept: 'application/json' } });
        rdapData = resp.data;
    } catch (_) {}

    if (rdapData) {
        if (isIp) {
            // IP RDAP
            msg += `🌐 <b>IP RDAP:</b>\n`;
            if (rdapData.name)       msg += `📋 Имя: ${rdapData.name}\n`;
            if (rdapData.country)    msg += `🌍 Страна: ${rdapData.country}\n`;
            if (rdapData.startAddress) msg += `📡 Диапазон: ${rdapData.startAddress} — ${rdapData.endAddress}\n`;
            const entity = rdapData.entities?.[0];
            if (entity?.vcardArray) {
                const vcard = Object.fromEntries(
                    (entity.vcardArray[1] || []).map(v => [v[0], v[3]])
                );
                if (vcard.fn)  msg += `👤 Организация: ${vcard.fn}\n`;
                if (vcard.adr) msg += `📍 Адрес: ${Array.isArray(vcard.adr) ? vcard.adr.filter(Boolean).join(', ') : vcard.adr}\n`;
            }
        } else {
            // Domain RDAP
            msg += `🌐 <b>Домен:</b> ${rdapData.ldhName || clean}\n`;
            const status = (rdapData.status || []).join(', ');
            if (status) msg += `📊 Статус: ${status}\n`;

            const events = rdapData.events || [];
            events.forEach(e => {
                const d = new Date(e.eventDate).toLocaleDateString('ru-RU');
                if (e.eventAction === 'registration') msg += `📅 Зарегистрирован: ${d}\n`;
                if (e.eventAction === 'expiration')   msg += `⏳ Истекает: ${d}\n`;
                if (e.eventAction === 'last changed') msg += `🔄 Обновлён: ${d}\n`;
            });

            const ns = (rdapData.nameservers || []).map(n => n.ldhName).filter(Boolean);
            if (ns.length) msg += `🖥 NS: ${ns.join(', ')}\n`;

            const registrar = rdapData.entities?.find(e => e.roles?.includes('registrar'));
            if (registrar?.vcardArray) {
                const vcard = Object.fromEntries((registrar.vcardArray[1] || []).map(v => [v[0], v[3]]));
                if (vcard.fn) msg += `🏢 Регистратор: ${vcard.fn}\n`;
            }

            const registrant = rdapData.entities?.find(e => e.roles?.includes('registrant'));
            if (registrant?.vcardArray) {
                const vcard = Object.fromEntries((registrant.vcardArray[1] || []).map(v => [v[0], v[3]]));
                if (vcard.fn)    msg += `👤 Владелец: ${vcard.fn}\n`;
                if (vcard.email) msg += `📧 Email: ${vcard.email}\n`;
                if (vcard.tel)   msg += `📞 Тел: ${vcard.tel}\n`;
                if (vcard.adr)   msg += `📍 Адрес: ${Array.isArray(vcard.adr) ? vcard.adr.filter(Boolean).join(', ') : vcard.adr}\n`;
            }
        }
    } else {
        msg += `ℹ️ RDAP не ответил. Используйте ручной поиск ниже.\n`;
    }

    // IP details via ip-api if domain
    if (!isIp) {
        try {
            const ipResp = await axios.get(`http://ip-api.com/json/${clean}?fields=status,country,city,isp,org,query`, { timeout: 8000 });
            if (ipResp.data.status === 'success') {
                const d = ipResp.data;
                msg += `\n🌐 <b>IP домена:</b> <code>${d.query}</code>\n`;
                msg += `🌍 ${d.country} | 🏙 ${d.city} | 📡 ${d.isp}\n`;
            }
        } catch (_) {}
    }

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Дополнительные источники для домена
    if (!isIp) {
        const [subdomains, dnsData, hostsData, urlscans, wayback] = await Promise.all([
            crtshLookup(clean),
            dnsLookup(clean),
            hostSearch(clean),
            urlscanSearch(clean),
            waybackLookup(clean),
        ]);

        // DNS записи
        if (dnsData) {
            await ctx.reply(
                `📡 <b>DNS записи (HackerTarget):</b>\n\n<code>${dnsData}</code>`,
                { parse_mode: 'HTML' }
            );
        }

        // Субдомены из SSL-сертификатов
        if (subdomains.length > 0) {
            let subMsg = `🔒 <b>Субдомены из SSL-сертификатов (crt.sh): ${subdomains.length}</b>\n\n`;
            subMsg += subdomains.slice(0, 25).map(s => `• <code>${s}</code>`).join('\n');
            if (subdomains.length > 25) subMsg += `\n<i>...ещё ${subdomains.length - 25}</i>`;
            await ctx.reply(subMsg, { parse_mode: 'HTML' });
        }

        // Хосты на том же домене
        if (hostsData.length > 0) {
            let hostMsg = `🌐 <b>Хосты домена (HackerTarget): ${hostsData.length}</b>\n\n`;
            hostMsg += hostsData.slice(0, 20).map(h => `• <code>${h}</code>`).join('\n');
            await ctx.reply(hostMsg, { parse_mode: 'HTML' });
        }

        // urlscan.io — последние сканы
        if (urlscans.length > 0) {
            let scanMsg = `🔬 <b>urlscan.io — последние сканы:</b>\n\n`;
            urlscans.forEach(s => {
                const page = s.page || {};
                const verdict = s.verdicts?.overall || {};
                const date = new Date(s.task?.time || '').toLocaleDateString('ru-RU');
                scanMsg += `📅 ${date} — ${page.url?.slice(0, 60) || clean}\n`;
                if (verdict.malicious) scanMsg += `🚨 Вредоносный!\n`;
                if (page.server) scanMsg += `🖥 Сервер: ${page.server}\n`;
                scanMsg += `🔗 <a href="${s.result}">Подробнее</a>\n\n`;
            });
            await ctx.reply(scanMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
        }

        // Wayback Machine
        if (wayback?.url) {
            await ctx.reply(
                `📚 <b>Wayback Machine:</b>\n\n` +
                `📅 Последний снимок: ${wayback.timestamp?.replace(/(\d{4})(\d{2})(\d{2}).*/, '$1-$2-$3') || wayback.timestamp}\n` +
                `🔗 <a href="${wayback.url}">Открыть архив</a>`,
                { parse_mode: 'HTML', disable_web_page_preview: true }
            );
        }
    }

    // Ссылки для ручного поиска
    await ctx.reply(
        `🔗 <b>Проверьте вручную:</b>\n\n` +
        `🔍 <a href="https://who.is/whois/${clean}">who.is</a>  ` +
        `🌐 <a href="https://www.whois.com/whois/${clean}">whois.com</a>  ` +
        `📡 <a href="https://2ip.ru/whois/?ip=${clean}">2ip.ru</a>\n` +
        `🔒 <a href="https://crt.sh/?q=%.${clean}">crt.sh (SSL)</a>  ` +
        `🔬 <a href="https://urlscan.io/search/#domain:${clean}">urlscan.io</a>  ` +
        `📚 <a href="https://web.archive.org/web/*/${clean}">Wayback</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );

    // Google упоминания
    const domainSearch = await googleSearch(`"${clean}" владелец информация`);
    const domRes = domainSearch.organic_results || [];
    if (domRes.length) {
        let domMsg = `🔍 <b>Упоминания в сети:</b>\n\n`;
        domRes.slice(0, 4).forEach((r, i) => {
            domMsg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) domMsg += `${r.snippet}\n`;
            domMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(domMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }
}

// ─── Reverse Image Search (Google Lens) ──────────────────────────────────────
async function handleReverseImageSearch(ctx, fileId) {
    // Получаем прямую ссылку на файл через Telegram
    const fileLink = await bot.telegram.getFileLink(fileId);
    const imageUrl = fileLink.toString();

    // Google Lens поиск
    const lensData = await axios.get('https://www.searchapi.io/api/v1/search', {
        params: { engine: 'google_lens', url: imageUrl, api_key: SEARCHAPI_KEY },
        timeout: 30000,
    }).then(r => r.data).catch(() => null);

    const matches = lensData?.visual_matches || [];
    const kg      = lensData?.knowledge_graph;

    // Knowledge Graph — если Google распознал личность
    if (kg?.title) {
        const kgText = renderKG(kg);
        if (kgText) await ctx.reply(kgText, { parse_mode: 'HTML' });
    }

    if (matches.length === 0) {
        // Fallback: Google Images reverse search
        const fallback = await googleSearch('', {
            engine: 'google_images',
            extra: { image_url: imageUrl, search_type: 'reverse' }
        }).catch(() => null);
        await ctx.reply('🔍 Google Lens не нашёл точных совпадений. Попробуйте Яндекс:\n' +
            `<a href="https://yandex.ru/images/search?rpt=imageview&url=${encodeURIComponent(imageUrl)}">🔍 Яндекс.Картинки — найти похожие</a>\n` +
            `<a href="https://images.google.com/searchbyimage?image_url=${encodeURIComponent(imageUrl)}">🔍 Google Images — найти похожие</a>`,
            { parse_mode: 'HTML', disable_web_page_preview: true });
        return;
    }

    let msg = `📷 <b>Результаты обратного поиска по фото:</b>\n\n`;
    msg += `🔢 Найдено совпадений: ${matches.length}\n\n`;

    matches.slice(0, 6).forEach((m, i) => {
        msg += `<b>${i + 1}. ${m.title || '—'}</b>\n`;
        if (m.source) msg += `🌐 ${m.source}\n`;
        msg += `🔗 <a href="${m.link}">${m.domain || m.link?.slice(0, 50)}</a>\n\n`;
    });

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Отправляем превью найденных фото
    let sent = 0;
    for (const m of matches.slice(0, 4)) {
        if (sent >= 3) break;
        const img = m.image?.link || m.thumbnail;
        if (img && !img.startsWith('data:')) {
            if (await sendPhotoSafe(ctx, m.title || '', img)) sent++;
        }
    }

    // Ссылки для ручной проверки
    await ctx.reply(
        `🔍 <b>Проверить вручную:</b>\n\n` +
        `<a href="https://yandex.ru/images/search?rpt=imageview&url=${encodeURIComponent(imageUrl)}">Яндекс.Картинки</a>  ` +
        `<a href="https://images.google.com/searchbyimage?image_url=${encodeURIComponent(imageUrl)}">Google Images</a>  ` +
        `<a href="https://www.tineye.com/search?url=${encodeURIComponent(imageUrl)}">TinEye</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Telegram User Lookup ─────────────────────────────────────────────────────
async function handleTelegramLookup(ctx, query) {
    const clean   = query.replace(/^@/, '').trim();
    const isId    = /^\d+$/.test(clean);

    await ctx.reply(`✈️ <b>Telegram поиск: ${query}</b>`, { parse_mode: 'HTML' });

    // Получаем публичный профиль через Telegram API
    let chatInfo = null;
    try {
        chatInfo = await bot.telegram.getChat(isId ? parseInt(clean) : `@${clean}`);
    } catch (e) {
        // Приватный аккаунт или не существует — продолжаем с Google-поиском
    }

    if (chatInfo) {
        let msg = `✈️ <b>Telegram профиль:</b>\n\n`;
        msg += `🆔 ID: <code>${chatInfo.id}</code>\n`;
        if (chatInfo.username)    msg += `👤 Username: @${chatInfo.username}\n`;
        if (chatInfo.first_name)  msg += `📛 Имя: ${chatInfo.first_name}`;
        if (chatInfo.last_name)   msg += ` ${chatInfo.last_name}`;
        if (chatInfo.first_name)  msg += '\n';
        if (chatInfo.title)       msg += `📢 Название: ${chatInfo.title}\n`;
        if (chatInfo.description) msg += `📝 Описание: ${chatInfo.description}\n`;
        if (chatInfo.bio)         msg += `📖 Bio: ${chatInfo.bio}\n`;
        if (chatInfo.member_count) msg += `👥 Участников: ${chatInfo.member_count}\n`;
        if (chatInfo.type)        msg += `📂 Тип: ${chatInfo.type}\n`;
        msg += `🔗 Ссылка: <a href="https://t.me/${chatInfo.username || clean}">t.me/${chatInfo.username || clean}</a>\n`;

        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

        // Получаем фото профиля
        try {
            const photos = await bot.telegram.getUserProfilePhotos(chatInfo.id, { limit: 1 });
            if (photos.total_count > 0) {
                const photoId = photos.photos[0][photos.photos[0].length - 1].file_id;
                const photoLink = await bot.telegram.getFileLink(photoId);
                await sendPhotoSafe(ctx, `📸 Фото профиля @${chatInfo.username || clean}`, photoLink.toString());
            }
        } catch (_) {}
    } else {
        await ctx.reply(`ℹ️ Профиль @${clean} приватный или не найден в Telegram. Ищу в открытых источниках...`);
    }

    // Google-поиск по юзернейму в Telegram
    const [googleData, socialData] = await Promise.all([
        googleSearch(`"@${clean}" OR "t.me/${clean}" Telegram`),
        googleSearch(`site:t.me "${clean}" OR "@${clean}"`),
    ]);

    const results = [...(googleData.organic_results || []), ...(socialData.organic_results || [])];
    const seen = new Set();
    const unique = results.filter(r => !seen.has(r.link) && seen.add(r.link));

    if (unique.length) {
        let msg = `🔍 <b>Упоминания в сети:</b>\n\n`;
        unique.slice(0, 5).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet.slice(0, 120)}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }
}

// ─── Car Lookup (Пробив авто) ─────────────────────────────────────────────────
async function handleCarLookup(ctx, plate) {
    const cleanPlate = plate.toUpperCase().replace(/\s/g, '');
    await ctx.reply(`🚗 <b>Пробив авто: ${cleanPlate}</b>\nИщу в базах данных...`, { parse_mode: 'HTML' });

    const [mainData, autoData, fineData] = await Promise.all([
        googleSearch(`"${cleanPlate}" автомобиль владелец`),
        googleSearch(`"${cleanPlate}" site:avtonomer.net OR site:avtocod.ru OR site:carteka.ru OR site:carinfo.ru OR site:gibdd-check.ru`),
        googleSearch(`"${cleanPlate}" штрафы ГИБДД нарушения`),
    ]);

    // Основные результаты + извлечение данных
    const allText = [...(mainData.organic_results || []), ...(autoData.organic_results || [])]
        .map(r => `${r.title} ${r.snippet || ''}`).join(' ');
    const contacts = extractContactInfo(allText);

    let msg = `🚗 <b>Автомобиль: ${cleanPlate}</b>\n\n`;
    if (contacts.phones.length)    msg += `📞 Телефоны: ${contacts.phones.join(', ')}\n`;
    if (contacts.addresses.length) msg += `📍 Адреса: ${contacts.addresses[0]}\n`;
    if (contacts.phones.length || contacts.addresses.length) msg += '\n';

    const mainRes = mainData.organic_results || [];
    if (mainRes.length) {
        mainRes.slice(0, 4).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
    } else {
        msg += '📭 Открытых данных по номеру не найдено.\n\n';
    }
    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Автобазы
    const autoRes = autoData.organic_results || [];
    if (autoRes.length) {
        let autoMsg = `📋 <b>Данные из автобаз:</b>\n\n`;
        autoRes.slice(0, 4).forEach(r => {
            autoMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) autoMsg += `  <i>${r.snippet.slice(0, 120)}</i>\n\n`;
        });
        await ctx.reply(autoMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Штрафы
    const fineRes = fineData.organic_results || [];
    if (fineRes.length) {
        let fineMsg = `🚔 <b>Штрафы и нарушения:</b>\n\n`;
        fineRes.slice(0, 3).forEach(r => {
            fineMsg += `• <a href="${r.link}">${r.title}</a>\n${r.snippet ? r.snippet.slice(0,100) + '\n' : ''}\n`;
        });
        await ctx.reply(fineMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Прямые ссылки на базы
    const enc = encodeURIComponent(cleanPlate);
    await ctx.reply(
        `🔎 <b>Проверьте вручную:</b>\n\n` +
        `🚗 <a href="https://avtocod.ru/check-auto?freeReportInput=${enc}">avtocod.ru — история авто</a>\n` +
        `🔍 <a href="https://carinfo.ru/">carinfo.ru — по VIN/номеру</a>\n` +
        `👮 <a href="https://xn--90adear.xn--p1ai/check/fines#${enc}">ГИБДД — штрафы</a>\n` +
        `📋 <a href="https://www.autocode.ru/app/cars/${enc}/">autocode.ru</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Connections (Связи и окружение) ─────────────────────────────────────────
async function handleConnections(ctx, query) {
    await ctx.reply(`🔗 <b>Связи и окружение: ${query}</b>\nАнализирую...`, { parse_mode: 'HTML' });

    const [familyData, workData, associatesData, conflictData] = await Promise.all([
        googleSearch(`"${query}" (жена OR муж OR брат OR сестра OR сын OR дочь OR родители OR родственники)`),
        googleSearch(`"${query}" (коллеги OR партнёр OR соучредитель OR директор OR компания OR работает OR должность)`),
        googleSearch(`"${query}" (друг OR знакомый OR окружение OR сообщник OR связан OR связанный)`),
        googleSearch(`"${query}" (конфликт OR спор OR враг OR противник OR претензии OR иск)`),
    ]);

    // Семья
    const familyRes = familyData.organic_results || [];
    if (familyRes.length) {
        let msg = `👨‍👩‍👧 <b>Семья и родственники:</b>\n\n`;
        familyRes.slice(0, 4).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    } else {
        await ctx.reply('👨‍👩‍👧 Данных о родственниках не найдено.');
    }

    // Работа и партнёры
    const workRes = workData.organic_results || [];
    if (workRes.length) {
        let msg = `💼 <b>Работа и деловые связи:</b>\n\n`;
        workRes.slice(0, 4).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Окружение
    const assocRes = associatesData.organic_results || [];
    if (assocRes.length) {
        let msg = `🤝 <b>Знакомые и окружение:</b>\n\n`;
        assocRes.slice(0, 3).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Конфликты
    const conflictRes = conflictData.organic_results || [];
    if (conflictRes.length) {
        let msg = `⚡ <b>Конфликты и противники:</b>\n\n`;
        conflictRes.slice(0, 3).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }
}

// ─── Document Search (Документы и паспорт) ───────────────────────────────────
async function handleDocSearch(ctx, query) {
    await ctx.reply(`📄 <b>Поиск по документам: ${query}</b>`, { parse_mode: 'HTML' });

    const [mainData, leakData, govData] = await Promise.all([
        googleSearch(`"${query}" паспорт документы данные`),
        googleSearch(`"${query}" (утечка OR слив OR leaked OR breach OR база данных)`),
        googleSearch(`"${query}" site:nalog.ru OR site:gosuslugi.ru OR site:rosreestr.ru OR site:egrul.nalog.ru`),
    ]);

    const results = mainData.organic_results || [];
    const allText = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
    const contacts = extractContactInfo(allText);

    let msg = `📄 <b>Результаты поиска: ${query}</b>\n\n`;
    if (contacts.phones.length)    msg += `📞 ${contacts.phones.join(', ')}\n`;
    if (contacts.addresses.length) msg += `📍 ${contacts.addresses.join(' | ')}\n`;
    if (contacts.emails.length)    msg += `📧 ${contacts.emails.join(', ')}\n`;
    if (contacts.phones.length || contacts.addresses.length || contacts.emails.length) msg += '\n';

    if (results.length) {
        results.slice(0, 5).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
    } else {
        msg += '📭 Прямых совпадений не найдено.\n\n';
    }
    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Утечки данных
    const leakRes = leakData.organic_results || [];
    if (leakRes.length) {
        let leakMsg = `🔓 <b>Возможные утечки с этими данными:</b>\n\n`;
        leakRes.slice(0, 4).forEach((r, i) => {
            leakMsg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) leakMsg += `${r.snippet}\n`;
            leakMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(leakMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Гос. базы
    const govRes = govData.organic_results || [];
    if (govRes.length) {
        let govMsg = `🏛 <b>Государственные базы данных:</b>\n\n`;
        govRes.slice(0, 4).forEach(r => {
            govMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) govMsg += `  <i>${r.snippet.slice(0, 120)}</i>\n\n`;
        });
        await ctx.reply(govMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Прямые ссылки
    const enc = encodeURIComponent(query);
    await ctx.reply(
        `🔎 <b>Проверьте вручную:</b>\n\n` +
        `📋 <a href="https://egrul.nalog.ru/index.html">ЕГРЮЛ/ЕГРИП (ИНН)</a>\n` +
        `👮 <a href="https://xn--b1afk4ade4e.xn--b1ab2a0a.xn--b1aew.xn--p1ai/info-service.htm#!5">МВД — действительность паспорта</a>\n` +
        `🏠 <a href="https://rosreestr.gov.ru/wps/portal/online_check">Росреестр — недвижимость</a>\n` +
        `💰 <a href="https://fssp.gov.ru/iss/ip/?territory=0&predmet=0&name=${enc}">ФССП — долги</a>\n` +
        `🔍 <a href="https://leakcheck.io/?query=${enc}">LeakCheck.io — утечки</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── SpiderFoot Scan ──────────────────────────────────────────────────────────
async function handleSpiderFoot(ctx, target) {
    if (!sfAvailable) {
        await ctx.reply('⏳ SpiderFoot запускается, подождите 30 сек и попробуйте снова...');
        await startSpiderFoot();
        if (!sfAvailable) return ctx.reply('❌ SpiderFoot недоступен. Попробуйте позже.');
    }

    const targetType = detectTargetType(target.replace(/^@/, ''));
    const typeLabel  = { IP_ADDRESS: '🌍 IP', INTERNET_NAME: '🌐 Домен', EMAILADDR: '📧 Email',
                         USERNAME: '👾 Username', PHONE_NUMBER: '📞 Телефон' }[targetType] || '🔍';

    const statusMsg = await ctx.reply(
        `🕷 <b>SpiderFoot: ${target}</b>\n` +
        `${typeLabel} · Тип цели определён\n\n` +
        `⏳ Запускаю 230 OSINT-модулей...\n` +
        `<i>Это займёт 30–90 секунд</i>`,
        { parse_mode: 'HTML' }
    );

    // Прогресс-апдейты пока сканирует
    const progressInterval = setInterval(async () => {
        try {
            const list = await axios.get(`${SF_BASE}/scanlist`);
            const running = list.data.filter(s => s[6] === 'RUNNING');
            if (running.length > 0) {
                const count = running[0][7] || 0;
                await ctx.telegram.editMessageText(
                    ctx.chat.id, statusMsg.message_id, undefined,
                    `🕷 <b>SpiderFoot: ${target}</b>\n${typeLabel}\n\n🔄 Сканирую... Найдено: <b>${count}</b> объектов`,
                    { parse_mode: 'HTML' }
                ).catch(() => {});
            }
        } catch (_) {}
    }, 10000);

    try {
        const cleanTarget = target.replace(/^@/, '');
        const { results, targetType: tt } = await runSFScan(cleanTarget, 90);

        clearInterval(progressInterval);

        if (!results || results.length === 0) {
            await ctx.telegram.editMessageText(
                ctx.chat.id, statusMsg.message_id, undefined,
                `🕷 <b>SpiderFoot: ${target}</b>\n\n📭 Результатов не найдено.`,
                { parse_mode: 'HTML' }
            ).catch(() => {});
            return;
        }

        // Финальная сводка
        await ctx.telegram.editMessageText(
            ctx.chat.id, statusMsg.message_id, undefined,
            `🕷 <b>SpiderFoot: ${target}</b>\n${typeLabel}\n\n✅ Сканирование завершено\n📊 Найдено объектов: <b>${results.length}</b>`,
            { parse_mode: 'HTML' }
        ).catch(() => {});

        // Форматируем и отправляем результаты по блокам
        const parts = formatSFResults(results, tt);

        if (parts.length === 0) {
            // Нет важных типов — показываем статистику по всем типам
            const types = {};
            for (const r of results) {
                const t = r[10] || r[r.length - 1];
                types[t] = (types[t] || 0) + 1;
            }
            let statMsg = `📊 <b>Статистика скана:</b>\n\n`;
            Object.entries(types).sort((a,b) => b[1]-a[1]).slice(0,20).forEach(([t,c]) => {
                statMsg += `${SF_ICONS[t] || '▪️'} ${t}: <b>${c}</b>\n`;
            });
            await ctx.reply(statMsg, { parse_mode: 'HTML' });
        } else {
            // Разбиваем на сообщения по 4096 символов
            let chunk = `🕷 <b>SpiderFoot результаты: ${target}</b>\n\n`;
            for (const part of parts) {
                if ((chunk + part + '\n\n').length > 4000) {
                    await ctx.reply(chunk, { parse_mode: 'HTML', disable_web_page_preview: true });
                    chunk = '';
                }
                chunk += part + '\n\n';
            }
            if (chunk.trim()) {
                await ctx.reply(chunk, { parse_mode: 'HTML', disable_web_page_preview: true });
            }
        }

        // Статистика
        const types = {};
        for (const r of results) { const t = r[10]||r[r.length-1]; types[t]=(types[t]||0)+1; }
        const topTypes = Object.entries(types).sort((a,b)=>b[1]-a[1]).slice(0,8)
            .map(([t,c]) => `${SF_ICONS[t]||'▪️'} ${t}: ${c}`).join('\n');
        await ctx.reply(
            `📈 <b>Итого найдено: ${results.length} объектов</b>\n\n${topTypes}`,
            { parse_mode: 'HTML' }
        );

    } catch (err) {
        clearInterval(progressInterval);
        console.error('[spiderfoot] error:', err.message);
        await ctx.reply('❌ Ошибка SpiderFoot: ' + err.message);
    }
}

// ─── Full Dossier ─────────────────────────────────────────────────────────────
async function handleFullDossier(ctx, query) {
    await ctx.reply(
        `📋 <b>Полное досье: ${query}</b>\n\n` +
        '━━━━━━━━━━━━━━━━━━━━━━\n' +
        '1️⃣  ФИО и биография\n' +
        '2️⃣  Фотографии\n' +
        '3️⃣  Адрес\n' +
        '4️⃣  Компромат\n' +
        '━━━━━━━━━━━━━━━━━━━━━━',
        { parse_mode: 'HTML' }
    );

    await ctx.reply('━━━ 1️⃣  ФИО И БИОГРАФИЯ ━━━');
    await handlePersonSearch(ctx, query);

    await ctx.reply('━━━ 2️⃣  ФОТОГРАФИИ ━━━');
    await handlePhotoSearch(ctx, query);

    await ctx.reply('━━━ 3️⃣  АДРЕС ━━━');
    await handleAddressSearch(ctx, query);

    await ctx.reply('━━━ 4️⃣  КОМПРОМАТ ━━━');
    await handleKompromat(ctx, query);

    await ctx.reply(
        '✅ <b>Досье собрано.</b>',
        { parse_mode: 'HTML', ...mainMenuKeyboard() }
    );
}

// ─── Launch ───────────────────────────────────────────────────────────────────
console.log('🚀 Запуск OSINT Dox Bot...');
bot.launch();
console.log('✅ Бот запущен и принимает сообщения');

// SpiderFoot — запускаем в фоне, не блокируем старт бота
startSpiderFoot().catch(e => console.error('SpiderFoot start error:', e.message));

// Инициализация первого админа
db.get('SELECT COUNT(*) AS c FROM admins', (err, row) => {
    if (!err && row.c === 0 && ADMIN_ID) {
        db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [ADMIN_ID], () => {
            console.log(`🔐 Супер-админ ${ADMIN_ID} добавлен.`);
        });
    }
});

bot.catch((err, ctx) => {
    console.error(`[Error ${ctx?.updateType}]:`, err.message);
});

process.once('SIGINT',  () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
