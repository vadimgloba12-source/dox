/**
 * OSINT Dox Bot — Production build
 * Features: IP · Phone · ФИО · Photos · Address · Kompromat · Email · Username · WHOIS
 * Engine: Google Search via searchapi.io
 */

const { Telegraf, Markup } = require('telegraf');
const axios  = require('axios');
const NodeCache = require('node-cache');
const sqlite3   = require('sqlite3').verbose();
require('dotenv').config();

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
    db.run(`ALTER TABLE users ADD COLUMN banned BOOLEAN DEFAULT 0`).run; // safe if exists
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
    ip_lookup:       5,
    phone_lookup:    10,
    person_search:   15,
    photo_search:    10,
    address_search:  15,
    kompromat:       20,
    email_search:    10,
    username_search: 10,
    whois_lookup:    5,
    full_dossier:    45,   // saves 35★ vs buying separately
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
        [Markup.button.callback('🔍 WHOIS / Домен', 'whois_lookup')],
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
    db.get('SELECT stars FROM users WHERE telegram_id = ?', [ctx.from.id], (err, row) => {
        if (err || !row) return ctx.reply('Пользователь не найден.');
        const costs = Object.entries(COSTS)
            .map(([k, v]) => `${v} ⭐ — ${k.replace(/_/g, ' ')}`)
            .join('\n');
        ctx.reply(
            `💰 <b>Ваш баланс: ${row.stars} ⭐</b>\n\n<b>Стоимость запросов:</b>\n${costs}`,
            { parse_mode: 'HTML' }
        );
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

    // Rate limiting
    if (!checkRateLimit(userId)) {
        userStates.delete(userId);
        return ctx.reply(`⏱ Превышен лимит запросов (${RATE_LIMIT}/час). Попробуйте позже.`);
    }

    // Stars check
    const cost = COSTS[state.action] || 0;
    if (user.stars < cost) {
        userStates.delete(userId);
        return ctx.reply(
            `❌ Недостаточно звёзд.\nНужно: <b>${cost} ⭐</b>  |  У вас: <b>${user.stars} ⭐</b>`,
            { parse_mode: 'HTML', ...Markup.inlineKeyboard([[Markup.button.callback('⭐ Купить звёзды', 'buy_stars')]]) }
        );
    }

    userStates.delete(userId);
    await updateStars(userId, -cost);
    logRequest(userId, state.action, text, cost);

    const remaining = user.stars - cost;
    await ctx.reply(`⏳ Выполняю поиск...\n<i>Остаток: ${remaining} ⭐</i>`, { parse_mode: 'HTML' });

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
            case 'full_dossier':    await handleFullDossier(ctx, text);    break;
        }
    } catch (err) {
        console.error(`[${state.action}] error:`, err.message);
        ctx.reply('❌ Произошла ошибка при выполнении запроса. Попробуйте позже.');
    }
});

// ─── Google Search ────────────────────────────────────────────────────────────
async function googleSearch(query, opts = {}) {
    const cacheKey = `gs_${opts.engine || 'g'}_${query}`;
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
    const resp = await axios.get('https://www.searchapi.io/api/v1/search', { params, timeout: 20000 });
    searchCache.set(cacheKey, resp.data);
    return resp.data;
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

    const flags = [d.mobile && '📱 Мобильный', d.proxy && '⚠️ Прокси/VPN', d.hosting && '☁️ Хостинг']
        .filter(Boolean).join('  ') || 'Обычный';

    const msg =
        `🌐 <b>IP: <code>${d.query}</code></b>\n\n` +
        `🌍 Страна:     ${d.country} (${d.countryCode})\n` +
        `🏙 Город:      ${d.city || '—'}\n` +
        `🏘 Район:      ${d.district || '—'}\n` +
        `📍 Регион:     ${d.regionName || '—'}\n` +
        `📮 Индекс:     ${d.zip || '—'}\n` +
        `📡 Провайдер:  ${d.isp}\n` +
        `🏢 Организация: ${d.org || '—'}\n` +
        `🔢 AS:         ${d.as || '—'}\n` +
        `🕐 Часовой пояс: ${d.timezone}\n` +
        `📌 Координаты: <code>${d.lat}, ${d.lon}</code>\n` +
        `🔎 Тип:        ${flags}\n\n` +
        `<a href="https://www.google.com/maps?q=${d.lat},${d.lon}">🗺 Google Maps</a>  ` +
        `<a href="https://yandex.ru/maps/?ll=${d.lon},${d.lat}&z=13&pt=${d.lon},${d.lat},pm2rdm">🗺 Яндекс</a>  ` +
        `<a href="https://www.openstreetmap.org/?mlat=${d.lat}&mlon=${d.lon}&zoom=13">🗺 OSM</a>`;

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Static map photo (OSM staticmap service)
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

    // Google owner search
    const [ownerData, vkData] = await Promise.all([
        googleSearch(`"${clean}" владелец телефона ФИО`),
        googleSearch(`"${clean}" site:vk.com OR site:ok.ru`),
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

    const vkResults = vkData.organic_results || [];
    if (vkResults.length) {
        let vkMsg = `📱 <b>Профили в соцсетях:</b>\n\n`;
        vkResults.slice(0, 3).forEach(r => {
            const net = r.domain?.includes('vk.com') ? '🔵 ВКонтакте' : r.domain?.includes('ok.ru') ? '🟠 ОК' : '🌐';
            vkMsg += `${net}: <a href="${r.link}">${r.title}</a>\n${r.snippet || ''}\n\n`;
        });
        await ctx.reply(vkMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }
}

// ─── Person Search ────────────────────────────────────────────────────────────
async function handlePersonSearch(ctx, query) {
    const [mainData, socialData, bizData] = await Promise.all([
        googleSearch(`"${query}" биография`),
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
        googleSearch(`"${query}" адрес проживания регистрации`),
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

    const enc = encodeURIComponent(email);
    await ctx.reply(
        `🔍 <b>Проверьте вручную:</b>\n\n` +
        `🔓 <a href="https://haveibeenpwned.com/account/${enc}">HaveIBeenPwned.com</a>\n` +
        `🔍 <a href="https://leakcheck.io/?query=${enc}">LeakCheck.io</a>\n` +
        `🌐 <a href="https://www.google.com/search?q=%22${enc}%22">Google поиск</a>`,
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

    // Direct platform links
    const enc = encodeURIComponent(username);
    await ctx.reply(
        `🔗 <b>Прямые ссылки:</b>\n\n` +
        `🔵 <a href="https://vk.com/${username}">vk.com/${username}</a>\n` +
        `📷 <a href="https://instagram.com/${username}">instagram.com/${username}</a>\n` +
        `🐦 <a href="https://twitter.com/${username}">twitter.com/${username}</a>\n` +
        `🎵 <a href="https://tiktok.com/@${username}">tiktok.com/@${username}</a>\n` +
        `✈️ <a href="https://t.me/${username}">t.me/${username}</a>\n` +
        `🐙 <a href="https://github.com/${username}">github.com/${username}</a>\n` +
        `📹 <a href="https://youtube.com/@${username}">youtube.com/@${username}</a>`,
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

    // Manual lookup links
    await ctx.reply(
        `🔗 <b>Проверьте вручную:</b>\n\n` +
        `🔍 <a href="https://who.is/whois/${clean}">who.is/whois/${clean}</a>\n` +
        `🌐 <a href="https://www.whois.com/whois/${clean}">whois.com</a>\n` +
        `📡 <a href="https://2ip.ru/whois/?ip=${clean}">2ip.ru</a>\n` +
        `🏢 <a href="https://nic.ru/whois/?query=${clean}">nic.ru</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );

    // Google search for the domain
    const domainSearch = await googleSearch(`"${clean}" владелец информация отзывы`);
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
bot.launch().then(() => {
    console.log('✅ OSINT Dox Bot запущен');
    db.get('SELECT COUNT(*) AS c FROM admins', (err, row) => {
        if (!err && row.c === 0 && ADMIN_ID) {
            db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [ADMIN_ID], () => {
                console.log(`Супер-админ ${ADMIN_ID} добавлен.`);
            });
        }
    });
});

bot.catch((err, ctx) => {
    console.error(`[Error ${ctx?.updateType}]:`, err.message);
});

process.once('SIGINT',  () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
