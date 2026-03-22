const { Telegraf, Markup } = require('telegraf');
const axios = require('axios');
const NodeCache = require('node-cache');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

// ─── База данных ────────────────────────────────────────────────────────────
const db = new sqlite3.Database('./database.sqlite');
const cache = new NodeCache({ stdTTL: 600 });

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        phone TEXT,
        stars INTEGER DEFAULT 0,
        allowed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
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

// ─── Конфигурация ────────────────────────────────────────────────────────────
const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
    console.error('BOT_TOKEN не указан в .env файле');
    process.exit(1);
}

const SEARCHAPI_KEY = process.env.SEARCHAPI_KEY || '3U2BbwQzCxKvRzeaAATjeRz6';

// Стоимость запросов в звёздах
const COSTS = {
    ip_lookup:       5,
    phone_lookup:    10,
    person_search:   15,
    photo_search:    10,
    kompromat:       20,
    address_search:  15,
    full_dossier:    45,  // экономия 15 ⭐ vs раздельно (15+10+15+20=60)
};

const bot = new Telegraf(BOT_TOKEN);

// ─── Состояние пользователей (замена ctx.session) ───────────────────────────
const userStates = new Map();

// ─── Вспомогательные функции ─────────────────────────────────────────────────
function getUser(telegramId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (err, row) => {
            if (err) reject(err); else resolve(row);
        });
    });
}

function updateStars(telegramId, delta) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET stars = stars + ? WHERE telegram_id = ?', [delta, telegramId], function(err) {
            if (err) reject(err); else resolve(this.changes);
        });
    });
}

function notifyAdmins(message) {
    db.all('SELECT telegram_id FROM admins', (err, rows) => {
        if (err) return;
        rows.forEach(r => bot.telegram.sendMessage(r.telegram_id, message).catch(() => {}));
    });
}

function isAdmin(ctx, next) {
    db.get('SELECT * FROM admins WHERE telegram_id = ?', [ctx.from.id], (err, row) => {
        if (err || !row) return ctx.reply('⛔ У вас нет прав администратора.');
        return next();
    });
}

function mainMenuKeyboard() {
    return Markup.inlineKeyboard([
        [Markup.button.callback('📋 Полное досье (ФИО+фото+адрес+компромат)', 'full_dossier')],
        [Markup.button.callback('🌐 Поиск по IP-адресу', 'ip_lookup')],
        [Markup.button.callback('📞 Поиск по номеру телефона', 'phone_lookup')],
        [Markup.button.callback('👤 Поиск по ФИО', 'person_search'), Markup.button.callback('📸 Фото', 'photo_search')],
        [Markup.button.callback('🏠 Адрес', 'address_search'), Markup.button.callback('🕵️ Компромат', 'kompromat')],
        [
            Markup.button.callback('⭐ Купить звёзды', 'buy_stars'),
            Markup.button.callback('💰 Баланс', 'show_balance'),
        ],
    ]);
}

function adminMenuKeyboard() {
    return Markup.inlineKeyboard([
        [Markup.button.callback('📋 Ожидающие подтверждения', 'adm_pending')],
        [Markup.button.callback('📊 Статистика', 'adm_stats')],
    ]);
}

// ─── Команды ─────────────────────────────────────────────────────────────────
bot.start(async (ctx) => {
    const userId = ctx.from.id;
    const name   = ctx.from.first_name;

    db.get('SELECT * FROM users WHERE telegram_id = ?', [userId], (err, row) => {
        if (err) return ctx.reply('Произошла ошибка. Попробуйте позже.');

        if (!row) {
            return ctx.reply(
                `👋 Привет, ${name}!\n\n` +
                '🤖 Я OSINT-бот. Умею:\n' +
                '• Искать информацию по IP-адресу\n' +
                '• Искать по номеру телефона\n' +
                '• Находить данные человека по ФИО\n' +
                '• Показывать фотографии человека\n' +
                '• Искать точный адрес\n' +
                '• Собирать компромат\n\n' +
                '📱 Сначала отправьте свой номер телефона для регистрации:',
                Markup.keyboard([
                    Markup.button.contactRequest('📱 Отправить номер телефона')
                ]).resize()
            );
        }

        if (!row.allowed) {
            return ctx.reply('⏳ Ваш аккаунт ожидает подтверждения администратора.');
        }

        ctx.reply(
            `🎉 С возвращением, ${name}!\n💰 Баланс: ${row.stars} ⭐\n\nВыберите действие:`,
            mainMenuKeyboard()
        );
    });
});

bot.on('contact', (ctx) => {
    const contact = ctx.message.contact;
    const userId  = ctx.from.id;

    if (contact.user_id !== userId) {
        return ctx.reply('Пожалуйста, отправьте свой контакт.');
    }

    const phone = contact.phone_number;

    db.run(
        'INSERT OR REPLACE INTO users (telegram_id, phone, stars, allowed) VALUES (?, ?, 0, 0)',
        [userId, phone],
        (err) => {
            if (err) return ctx.reply('Ошибка сохранения номера.');

            ctx.reply('✅ Номер сохранён. Ожидайте подтверждения администратора.', Markup.removeKeyboard());

            notifyAdmins(
                `🆕 Новый пользователь:\n` +
                `👤 ${ctx.from.first_name} (@${ctx.from.username || '—'})\n` +
                `📱 ${phone}\n🆔 ID: ${userId}\n\n` +
                `Для подтверждения: /allow_user ${userId}`
            );

            // Автоматический супер-админ по номеру
            if (['79282953494', '+79282953494'].includes(phone)) {
                db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [userId]);
                db.run('UPDATE users SET allowed = 1 WHERE telegram_id = ?', [userId]);
                bot.telegram.sendMessage(userId, '🔐 Вы автоматически добавлены как администратор.');
            }
        }
    );
});

bot.command('menu', (ctx) => ctx.reply('Главное меню:', mainMenuKeyboard()));

bot.command('balance', (ctx) => {
    db.get('SELECT stars FROM users WHERE telegram_id = ?', [ctx.from.id], (err, row) => {
        if (err || !row) return ctx.reply('Пользователь не найден.');
        ctx.reply(`💰 Ваш баланс: ${row.stars} ⭐`);
    });
});

bot.command('admin', (ctx) => isAdmin(ctx, () => {
    ctx.reply('🔧 Панель администратора:', adminMenuKeyboard());
}));

bot.command('allow_user', (ctx) => isAdmin(ctx, () => {
    const args = ctx.message.text.split(' ');
    if (args.length < 2) return ctx.reply('Использование: /allow_user <telegram_id>');
    const targetId = parseInt(args[1]);
    db.run('UPDATE users SET allowed = 1 WHERE telegram_id = ?', [targetId], function(err) {
        if (err) return ctx.reply('Ошибка базы данных.');
        if (this.changes === 0) return ctx.reply('Пользователь не найден.');
        ctx.reply(`✅ Пользователь ${targetId} подтверждён.`);
        bot.telegram.sendMessage(targetId, '✅ Вы подтверждены! Напишите /start').catch(() => {});
    });
}));

bot.command('add_stars', (ctx) => isAdmin(ctx, () => {
    const args = ctx.message.text.split(' ');
    if (args.length < 3) return ctx.reply('Использование: /add_stars <telegram_id> <количество>');
    const targetId = parseInt(args[1]);
    const amount   = parseInt(args[2]);
    if (isNaN(amount) || amount <= 0) return ctx.reply('Введите корректное количество.');
    db.run('UPDATE users SET stars = stars + ? WHERE telegram_id = ?', [amount, targetId], function(err) {
        if (err) return ctx.reply('Ошибка базы данных.');
        if (this.changes === 0) return ctx.reply('Пользователь не найден.');
        ctx.reply(`✅ Начислено ${amount} ⭐ пользователю ${targetId}.`);
        bot.telegram.sendMessage(targetId, `⭐ Вам начислено ${amount} звёзд! Проверьте /balance`).catch(() => {});
    });
}));

bot.command('list_pending', (ctx) => isAdmin(ctx, () => {
    db.all('SELECT telegram_id, phone FROM users WHERE allowed = 0', (err, rows) => {
        if (err) return ctx.reply('Ошибка базы данных.');
        if (!rows.length) return ctx.reply('Нет ожидающих пользователей.');
        let msg = '⏳ Ожидают подтверждения:\n\n';
        rows.forEach(r => {
            msg += `🆔 ${r.telegram_id}  📱 ${r.phone}\n/allow_user ${r.telegram_id}\n\n`;
        });
        ctx.reply(msg);
    });
}));

bot.command('stats', (ctx) => isAdmin(ctx, () => {
    db.get('SELECT COUNT(*) AS t FROM users', (_, r1) => {
        db.get('SELECT COUNT(*) AS a FROM users WHERE allowed = 1', (_, r2) => {
            db.get('SELECT COUNT(*) AS rq FROM requests', (_, r3) => {
                ctx.reply(
                    `📊 <b>Статистика бота:</b>\n\n` +
                    `👥 Всего пользователей: ${r1.t}\n` +
                    `✅ Подтверждённых: ${r2.a}\n` +
                    `📋 Всего запросов: ${r3.rq}`,
                    { parse_mode: 'HTML' }
                );
            });
        });
    });
}));

// ─── Кнопки главного меню ────────────────────────────────────────────────────
function startAction(ctx, action, prompt) {
    ctx.answerCbQuery().catch(() => {});
    userStates.set(ctx.from.id, { action });
    ctx.reply(prompt, { parse_mode: 'HTML' });
}

bot.action('full_dossier',   (ctx) => startAction(ctx, 'full_dossier',
    `📋 <b>Полное досье</b>\n\nВведите ФИО человека — бот автоматически соберёт:\n` +
    `• биографию и данные из соцсетей\n• фотографии\n• адрес\n• компромат\n\n` +
    `💰 Стоимость: ${COSTS.full_dossier} ⭐ (вместо 60 ⭐ раздельно)`
));
bot.action('ip_lookup',      (ctx) => startAction(ctx, 'ip_lookup',      `🌐 Введите IP-адрес:\n(стоимость: ${COSTS.ip_lookup} ⭐)`));
bot.action('phone_lookup',   (ctx) => startAction(ctx, 'phone_lookup',   `📞 Введите номер телефона (например, +79001234567):\n(стоимость: ${COSTS.phone_lookup} ⭐)`));
bot.action('person_search',  (ctx) => startAction(ctx, 'person_search',  `👤 Введите ФИО для поиска:\n(стоимость: ${COSTS.person_search} ⭐)`));
bot.action('photo_search',   (ctx) => startAction(ctx, 'photo_search',   `📸 Введите имя человека для поиска фотографий:\n(стоимость: ${COSTS.photo_search} ⭐)`));
bot.action('address_search', (ctx) => startAction(ctx, 'address_search', `🏠 Введите ФИО или запрос для поиска адреса:\n(стоимость: ${COSTS.address_search} ⭐)`));
bot.action('kompromat',      (ctx) => startAction(ctx, 'kompromat',      `🕵️ Введите ФИО для поиска компромата:\n(стоимость: ${COSTS.kompromat} ⭐)`));

bot.action('show_balance', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    db.get('SELECT stars FROM users WHERE telegram_id = ?', [ctx.from.id], (err, row) => {
        if (err || !row) return ctx.reply('Пользователь не найден.');
        ctx.reply(`💰 Ваш баланс: ${row.stars} ⭐`);
    });
});

bot.action('buy_stars', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    ctx.reply(
        '⭐ <b>Покупка звёзд:</b>\n\n' +
        '10 ⭐  →  50 руб.\n' +
        '25 ⭐  →  100 руб.\n' +
        '50 ⭐  →  180 руб.\n' +
        '100 ⭐ →  300 руб.\n\n' +
        'Свяжитесь с @admin для оплаты.',
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

['stars_10', 'stars_25', 'stars_50', 'stars_100'].forEach(action => {
    bot.action(action, (ctx) => {
        ctx.answerCbQuery().catch(() => {});
        const map = { stars_10: [10, 50], stars_25: [25, 100], stars_50: [50, 180], stars_100: [100, 300] };
        const [stars, price] = map[action];
        ctx.reply(
            `⭐ Вы выбрали <b>${stars} звёзд</b> за <b>${price} руб.</b>\n\n` +
            `Переведите ${price} руб. администратору @admin\n` +
            `Укажите ваш ID: <code>${ctx.from.id}</code>`,
            { parse_mode: 'HTML' }
        );
    });
});

bot.action('back_menu', (ctx) => {
    ctx.answerCbQuery().catch(() => {});
    ctx.editMessageText('Главное меню:', mainMenuKeyboard());
});

// Кнопки администратора
bot.action('adm_pending', (ctx) => isAdmin(ctx, () => {
    ctx.answerCbQuery().catch(() => {});
    db.all('SELECT telegram_id, phone FROM users WHERE allowed = 0', (err, rows) => {
        if (err) return ctx.reply('Ошибка базы данных.');
        if (!rows.length) return ctx.reply('Нет ожидающих пользователей.');
        let msg = '⏳ Ожидают подтверждения:\n\n';
        rows.forEach(r => { msg += `🆔 ${r.telegram_id}  📱 ${r.phone}\n/allow_user ${r.telegram_id}\n\n`; });
        ctx.reply(msg);
    });
}));

bot.action('adm_stats', (ctx) => isAdmin(ctx, () => {
    ctx.answerCbQuery().catch(() => {});
    db.get('SELECT COUNT(*) AS t FROM users', (_, r1) => {
        db.get('SELECT COUNT(*) AS a FROM users WHERE allowed = 1', (_, r2) => {
            db.get('SELECT COUNT(*) AS rq FROM requests', (_, r3) => {
                ctx.reply(
                    `📊 <b>Статистика:</b>\n👥 ${r1.t}  ✅ ${r2.a}  📋 ${r3.rq}`,
                    { parse_mode: 'HTML' }
                );
            });
        });
    });
}));

// ─── Обработка текстовых сообщений ───────────────────────────────────────────
bot.on('text', async (ctx) => {
    const userId = ctx.from.id;
    const text   = ctx.message.text.trim();

    if (text.startsWith('/')) return;

    const state = userStates.get(userId);
    if (!state) return;

    const user = await getUser(userId).catch(() => null);
    if (!user || !user.allowed) {
        return ctx.reply('⛔ Доступ запрещён. Ожидайте подтверждения.');
    }

    const cost = COSTS[state.action] || 0;
    if (user.stars < cost) {
        userStates.delete(userId);
        return ctx.reply(`❌ Недостаточно звёзд. Нужно ${cost} ⭐, у вас ${user.stars} ⭐`);
    }

    userStates.delete(userId);
    await updateStars(userId, -cost);
    db.run('INSERT INTO requests (user_id, type, query, cost) VALUES (?, ?, ?, ?)',
        [userId, state.action, text, cost]);

    await ctx.reply('⏳ Выполняю поиск...');

    try {
        switch (state.action) {
            case 'ip_lookup':      await handleIpLookup(ctx, text); break;
            case 'phone_lookup':   await handlePhoneLookup(ctx, text); break;
            case 'person_search':  await handlePersonSearch(ctx, text); break;
            case 'photo_search':   await handlePhotoSearch(ctx, text); break;
            case 'address_search': await handleAddressSearch(ctx, text); break;
            case 'kompromat':      await handleKompromat(ctx, text); break;
            case 'full_dossier':   await handleFullDossier(ctx, text); break;
        }
    } catch (err) {
        console.error(`Ошибка в ${state.action}:`, err.message);
        ctx.reply('❌ Произошла ошибка при выполнении запроса.');
    }
});

// ─── Google Search через SearchAPI.io ────────────────────────────────────────
async function googleSearch(query, opts = {}) {
    const params = {
        engine: opts.engine || 'google',
        q: query,
        gl: opts.gl || 'ru',
        hl: opts.hl || 'ru',
        num: opts.num || 10,
        api_key: SEARCHAPI_KEY,
        ...opts.extra,
    };
    const resp = await axios.get('https://www.searchapi.io/api/v1/search', { params, timeout: 20000 });
    return resp.data;
}

// ─── Надёжная отправка фото с несколькими fallback'ами ───────────────────────
// Порядок попыток: прямой URL → скачать и переслать → следующий URL
async function sendPhotoSafe(ctx, caption, ...urls) {
    for (const url of urls) {
        if (!url || url.startsWith('data:')) continue;

        // Попытка 1: прямой URL
        const direct = await ctx.replyWithPhoto(url, { caption, parse_mode: 'HTML' }).catch(() => null);
        if (direct) return true;

        // Попытка 2: скачать через axios и отправить как буфер
        try {
            const resp = await axios.get(url, {
                responseType: 'arraybuffer',
                timeout: 10000,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            });
            const ct = resp.headers['content-type'] || '';
            if (ct.startsWith('image/')) {
                await ctx.replyWithPhoto(
                    { source: Buffer.from(resp.data), filename: 'photo.jpg' },
                    { caption, parse_mode: 'HTML' }
                );
                return true;
            }
        } catch (_) {}
    }
    return false;
}

// ─── Извлечение телефонов и адресов из произвольного текста ──────────────────
function extractContactInfo(text) {
    const phones = [
        ...(text.match(/(?:\+7|8)[\s\-\(]?\d{3}[\s\-\)]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}/g) || []),
        ...(text.match(/\b\d{3}[\s\-]\d{3}[\s\-]\d{2}[\s\-]\d{2}\b/g) || []),
    ];
    const addresses = (text.match(
        /(?:г\.|город|ул\.|улица|пр\.|пр-т|проспект|пер\.|переулок|бул\.|бульвар|пл\.|площадь|ш\.|шоссе|д\.\s*\d+)[^,\n]{3,60}/gi
    ) || []);
    return {
        phones: [...new Set(phones)].slice(0, 5),
        addresses: [...new Set(addresses)].slice(0, 5),
    };
}

// ─── Рендер Google Knowledge Graph (динамические поля) ───────────────────────
// Пропускаем служебные ключи и показываем все содержательные поля
const KG_SKIP = new Set([
    'kgmid', 'knowledge_graph_type', 'source', 'profiles',
    'people_also_search_for', 'people_also_search_for_link', 'images',
]);
const KG_FIELD_ICONS = {
    'дата': '🎂', 'рождения': '🎂', 'место': '📍', 'смерть': '✝️',
    'возраст': '🔢', 'дети': '👶', 'супруг': '💍', 'образование': '🎓',
    'родител': '👪', 'должность': '💼', 'звание': '🏅', 'партия': '🏛',
    'религия': '✝️', 'рост': '📏', 'гражданство': '🌍', 'срок': '📅',
    'профессия': '💼', 'награды': '🏆', 'альма': '🎓', 'сайт': '🌐',
};

function renderKnowledgeGraph(kg) {
    if (!kg || !kg.title) return null;

    let lines = [`📌 <b>${kg.title}</b>`];
    if (kg.type)        lines.push(`📂 ${kg.type}`);
    if (kg.description) lines.push(`\n📝 ${kg.description}`);
    lines.push('');

    for (const [key, val] of Object.entries(kg)) {
        if (KG_SKIP.has(key) || key === 'title' || key === 'type' || key === 'description') continue;
        if (key.endsWith('_links') || key.endsWith('_link')) continue;
        if (typeof val !== 'string') continue;

        const lk = key.toLowerCase();
        const icon = Object.entries(KG_FIELD_ICONS).find(([k]) => lk.includes(k))?.[1] || '▪️';
        const label = key.replace(/_/g, ' ');
        lines.push(`${icon} <b>${label}:</b> ${val}`);
    }
    return lines.join('\n');
}

// ─── IP Lookup ───────────────────────────────────────────────────────────────
async function handleIpLookup(ctx, ip) {
    const cacheKey = `ip_${ip}`;
    let data = cache.get(cacheKey);

    if (!data) {
        const resp = await axios.get(
            `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,mobile,proxy,hosting,query`,
            { timeout: 10000 }
        );
        data = resp.data;
        if (data.status === 'success') cache.set(cacheKey, data);
    }

    if (data.status === 'fail') {
        return ctx.reply(`❌ Ошибка: ${data.message}`);
    }

    const flags = [
        data.mobile  ? '📱 Мобильный'  : null,
        data.proxy   ? '⚠️ Прокси/VPN' : null,
        data.hosting ? '☁️ Хостинг'    : null,
    ].filter(Boolean).join('  ') || 'Обычный';

    const mapsUrl = `https://www.google.com/maps?q=${data.lat},${data.lon}`;
    const yMapsUrl = `https://yandex.ru/maps/?ll=${data.lon},${data.lat}&z=13&pt=${data.lon},${data.lat},pm2rdm`;

    const msg =
        `🌐 <b>IP-адрес: <code>${data.query}</code></b>\n\n` +
        `🌍 Страна:    ${data.country} (${data.countryCode})\n` +
        `🏙 Город:     ${data.city || '—'}\n` +
        `📍 Регион:    ${data.regionName || '—'}\n` +
        `📮 Индекс:    ${data.zip || '—'}\n` +
        `📡 Провайдер: ${data.isp}\n` +
        `🏢 Организация: ${data.org || '—'}\n` +
        `🕐 Часовой пояс: ${data.timezone}\n` +
        `📌 Координаты: <code>${data.lat}, ${data.lon}</code>\n` +
        `🔎 Тип: ${flags}\n\n` +
        `🗺 <a href="${mapsUrl}">Google Maps</a>  |  <a href="${yMapsUrl}">Яндекс.Карты</a>`;

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Карта как фото через Geoapify (без ключа даёт watermark но работает)
    const mapImg = `https://maps.geoapify.com/v1/staticmap?style=osm-bright&width=600&height=300&center=lonlat:${data.lon},${data.lat}&zoom=12&marker=lonlat:${data.lon},${data.lat};type:awesome;color:%23ff0000&apiKey=free`;
    await ctx.replyWithPhoto(mapImg, {
        caption: `📍 ${data.city}, ${data.regionName}, ${data.country}`
    }).catch(async () => {
        // fallback: OSM tile
        const fallback = `https://static-maps.yandex.ru/1.x/?ll=${data.lon},${data.lat}&z=13&size=600,300&l=map&pt=${data.lon},${data.lat},pm2rdm`;
        await ctx.replyWithPhoto(fallback).catch(() => {});
    });
}

// ─── Phone Lookup ─────────────────────────────────────────────────────────────
async function handlePhoneLookup(ctx, phone) {
    const cleanPhone = phone.replace(/[\s()−-]/g, '');

    // Numverify для базовых данных
    const apiKey = process.env.NUMVERIFY_API_KEY || 'demo';
    const numResp = await axios.get(
        `http://apilayer.net/api/validate?access_key=${apiKey}&number=${cleanPhone}&format=1`,
        { timeout: 10000 }
    ).catch(() => null);

    let msg = `📞 <b>Номер: <code>${cleanPhone}</code></b>\n\n`;

    if (numResp && numResp.data.valid) {
        const d = numResp.data;
        msg +=
            `✅ Статус: Действителен\n` +
            `🌍 Страна: ${d.country_name} (${d.country_code})\n` +
            `📞 Оператор: ${d.carrier || '—'}\n` +
            `📟 Тип линии: ${d.line_type || '—'}\n` +
            `📍 Локация: ${d.location || '—'}\n` +
            `🔢 Формат: ${d.international_format}\n`;
    } else {
        msg += `⚠️ Базовая валидация не пройдена (возможно, нет API-ключа NumVerify)\n`;
    }

    await ctx.reply(msg, { parse_mode: 'HTML' });

    // Поиск человека по номеру через Google
    await ctx.reply('🔍 Ищу владельца номера через Google...');
    const searchData = await googleSearch(`"${cleanPhone}" ФИО владелец телефон`);
    const results = searchData.organic_results || [];

    if (results.length === 0) {
        return ctx.reply('📭 По данному номеру ничего не найдено в открытых источниках.');
    }

    let searchMsg = `📋 <b>Открытые данные по номеру ${cleanPhone}:</b>\n\n`;
    results.slice(0, 5).forEach((r, i) => {
        searchMsg += `<b>${i + 1}. ${r.title}</b>\n`;
        if (r.snippet) searchMsg += `${r.snippet}\n`;
        searchMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
    });

    await ctx.reply(searchMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
}

// ─── Person Search (ФИО) ─────────────────────────────────────────────────────
async function handlePersonSearch(ctx, query) {
    const [mainData, socialData, bizData] = await Promise.all([
        googleSearch(query + ' биография'),
        googleSearch(`${query} site:vk.com OR site:ok.ru OR site:t.me OR site:instagram.com`),
        googleSearch(`${query} site:rusprofile.ru OR site:zachestnyibiznes.ru OR site:focus.kontur.ru OR site:egrul.nalog.ru`),
    ]);

    // Knowledge Graph
    const kg = mainData.knowledge_graph;
    if (kg) {
        const kgText = renderKnowledgeGraph(kg);
        if (kgText) {
            await ctx.reply(kgText, { parse_mode: 'HTML' });

            const kgImages = kg.images || [];
            if (kgImages.length > 0) {
                await sendPhotoSafe(ctx, kg.title || query,
                    kgImages[0].image, kgImages[0].image_url, kgImages[1]?.image
                );
            }
        }
    }

    // Основные результаты + извлечение контактов из сниппетов
    const results = mainData.organic_results || [];
    if (results.length === 0 && !kg) {
        return ctx.reply(`📭 По запросу "<b>${query}</b>" ничего не найдено.`, { parse_mode: 'HTML' });
    }

    if (results.length > 0) {
        const allSnippets = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
        const contacts = extractContactInfo(allSnippets);

        let msg = `👤 <b>Поиск по ФИО: ${query}</b>\n`;
        if (contacts.phones.length)    msg += `\n📞 Телефоны в результатах: ${contacts.phones.join(', ')}`;
        if (contacts.addresses.length) msg += `\n📍 Адреса в результатах: ${contacts.addresses.join(' | ')}`;
        msg += '\n\n';

        results.slice(0, 5).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Социальные сети
    const socialResults = socialData.organic_results || [];
    if (socialResults.length > 0) {
        let smMsg = `📱 <b>Профили в социальных сетях:</b>\n\n`;
        socialResults.slice(0, 5).forEach(r => {
            const network = r.domain?.includes('vk.com') ? '🔵 ВКонтакте' :
                            r.domain?.includes('ok.ru')  ? '🟠 Одноклассники' :
                            r.domain?.includes('t.me')   ? '✈️ Telegram' :
                            r.domain?.includes('instagram') ? '📷 Instagram' : '🌐';
            smMsg += `${network}: <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) smMsg += `  ${r.snippet}\n`;
            smMsg += '\n';
        });
        await ctx.reply(smMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Деловые базы
    const bizResults = bizData.organic_results || [];
    if (bizResults.length > 0) {
        let bizMsg = `🏢 <b>Деловые базы и реестры:</b>\n\n`;
        bizResults.slice(0, 4).forEach(r => {
            bizMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) bizMsg += `  ${r.snippet}\n\n`;
        });
        await ctx.reply(bizMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }
}

// ─── Photo Search (фотографии человека) ──────────────────────────────────────
async function handlePhotoSearch(ctx, query) {
    const data = await googleSearch(query, { engine: 'google_images', num: 20 });
    const images = data.images || [];

    if (images.length === 0) {
        return ctx.reply(`📭 Фотографии по запросу "<b>${query}</b>" не найдены.`, { parse_mode: 'HTML' });
    }

    await ctx.reply(`📸 <b>Фотографии: ${query}</b>`, { parse_mode: 'HTML' });

    let sent = 0;
    for (const img of images) {
        if (sent >= 6) break;

        // Thumbnail (encrypted-tbn0.gstatic.com) работает надёжнее оригинала
        const thumb    = typeof img.thumbnail === 'string' && !img.thumbnail.startsWith('data:') ? img.thumbnail : null;
        const original = img.original?.link;
        const caption  = `📸 ${img.title || query}${img.source?.name ? '\n🔗 ' + img.source.name : ''}`;

        // Приоритет: thumbnail → original (скачать)
        const ok = await sendPhotoSafe(ctx, caption, thumb, original);
        if (ok) sent++;
    }

    if (sent === 0) {
        await ctx.reply('❌ Не удалось загрузить фотографии. Попробуйте уточнить запрос (добавьте город или профессию).');
    } else {
        await ctx.reply(`✅ Отправлено фотографий: ${sent}`);
    }
}

// ─── Address Search (точный адрес) ───────────────────────────────────────────
async function handleAddressSearch(ctx, query) {
    const [mainData, officialData] = await Promise.all([
        googleSearch(`"${query}" адрес проживания регистрации`),
        googleSearch(`"${query}" site:fssp.gov.ru OR site:egrul.nalog.ru OR site:rusprofile.ru OR site:sudact.ru OR site:kad.arbitr.ru`),
    ]);

    const results = mainData.organic_results || [];
    const allText = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ');
    const contacts = extractContactInfo(allText);

    let msg = `🏠 <b>Поиск адреса: ${query}</b>\n\n`;

    // Адреса извлечённые из сниппетов
    if (contacts.addresses.length > 0) {
        msg += `📍 <b>Найденные адреса:</b>\n`;
        contacts.addresses.forEach(a => { msg += `  • ${a.trim()}\n`; });
        msg += '\n';
    }
    if (contacts.phones.length > 0) {
        msg += `📞 <b>Телефоны:</b> ${contacts.phones.join(', ')}\n\n`;
    }

    // Knowledge Graph адрес
    const kg = mainData.knowledge_graph;
    if (kg) {
        const addrField = kg.address || kg.headquarters || kg.location || kg['Адрес'] || kg['Местонахождение'];
        if (addrField) msg += `🗂 <b>Адрес из Google Knowledge Graph:</b>\n${addrField}\n\n`;
    }

    if (results.length > 0) {
        results.slice(0, 5).forEach((r, i) => {
            msg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) msg += `${r.snippet}\n`;
            msg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
    } else {
        msg += '📭 Адрес в открытых источниках не найден.\n\n';
    }

    await ctx.reply(msg, { parse_mode: 'HTML', disable_web_page_preview: true });

    // Официальные базы
    const offResults = officialData.organic_results || [];
    if (offResults.length > 0) {
        let offMsg = `⚖️ <b>Официальные базы данных:</b>\n\n`;
        offResults.slice(0, 4).forEach(r => {
            const snippetContacts = extractContactInfo(`${r.title} ${r.snippet || ''}`);
            offMsg += `• <a href="${r.link}">${r.title}</a>\n`;
            if (r.snippet) offMsg += `  ${r.snippet}\n`;
            if (snippetContacts.addresses.length) offMsg += `  📍 ${snippetContacts.addresses[0]}\n`;
            offMsg += '\n';
        });
        await ctx.reply(offMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // Прямые ссылки для самостоятельного поиска
    const enc = encodeURIComponent(query);
    await ctx.reply(
        `🔎 <b>Проверьте вручную:</b>\n\n` +
        `📋 <a href="https://egrul.nalog.ru/index.html">ЕГРЮЛ/ЕГРИП (ФНС)</a>\n` +
        `💰 <a href="https://fssp.gov.ru/iss/ip/?territory=0&predmet=0&name=${enc}">ФССП — исполнительные производства</a>\n` +
        `🏛 <a href="https://kad.arbitr.ru/?ins[0]=${enc}">Картотека арбитражных дел</a>\n` +
        `⚖️ <a href="https://sudact.ru/search/?query=${enc}">ГАС Правосудие</a>\n` +
        `🏢 <a href="https://www.rusprofile.ru/search?query=${enc}&type=person">Rusprofile — физлица</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Kompromat ────────────────────────────────────────────────────────────────
async function handleKompromat(ctx, query) {
    await ctx.reply(
        `🕵️ <b>Сбор компромата: ${query}</b>\n\nЗапрашиваю параллельно несколько источников...`,
        { parse_mode: 'HTML' }
    );

    const [newsData, courtData, debtData] = await Promise.all([
        googleSearch(`"${query}" суд арест обвинение скандал мошенничество уголовное`, { engine: 'google_news', num: 8 }),
        googleSearch(`"${query}" приговор суд уголовное дело осуждён виновен`, { num: 6 }),
        googleSearch(`"${query}" банкротство долги исполнительное производство ФССП`, { num: 5 }),
    ]);

    // 1. Новости
    const news = newsData.organic_results || [];
    if (news.length > 0) {
        let newsMsg = `📰 <b>Новости и скандалы:</b>\n\n`;
        news.slice(0, 5).forEach((n, i) => {
            newsMsg += `<b>${i + 1}. ${n.title}</b>\n`;
            if (n.date)    newsMsg += `📅 ${n.date}\n`;
            if (n.snippet) newsMsg += `${n.snippet}\n`;
            newsMsg += `🔗 <a href="${n.link}">${n.source || n.domain || n.link}</a>\n\n`;
        });
        await ctx.reply(newsMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    } else {
        await ctx.reply('📰 Публичных новостей о судах/арестах не найдено.');
    }

    // 2. Судебные дела
    const courtResults = courtData.organic_results || [];
    if (courtResults.length > 0) {
        let courtMsg = `⚖️ <b>Судебные дела:</b>\n\n`;
        courtResults.slice(0, 4).forEach((r, i) => {
            courtMsg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) courtMsg += `${r.snippet}\n`;
            courtMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(courtMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // 3. Долги и банкротство
    const debtResults = debtData.organic_results || [];
    if (debtResults.length > 0) {
        let debtMsg = `💸 <b>Долги и банкротство:</b>\n\n`;
        debtResults.slice(0, 3).forEach((r, i) => {
            debtMsg += `<b>${i + 1}. ${r.title}</b>\n`;
            if (r.snippet) debtMsg += `${r.snippet}\n`;
            debtMsg += `🔗 <a href="${r.link}">${r.domain || r.link}</a>\n\n`;
        });
        await ctx.reply(debtMsg, { parse_mode: 'HTML', disable_web_page_preview: true });
    }

    // 4. Прямые ссылки
    const enc = encodeURIComponent(query);
    await ctx.reply(
        `🗂 <b>Проверьте в официальных базах:</b>\n\n` +
        `💰 <a href="https://fssp.gov.ru/iss/ip/?territory=0&predmet=0&name=${enc}">ФССП — долги и приставы</a>\n` +
        `⚖️ <a href="https://sudact.ru/search/?query=${enc}">ГАС Правосудие — решения судов</a>\n` +
        `🏛 <a href="https://kad.arbitr.ru/?ins[0]=${enc}">Картотека арбитражных дел</a>\n` +
        `📑 <a href="https://bankrot.fedresurs.ru/bankrupts?searchStr=${enc}">Реестр банкротств (Федресурс)</a>\n` +
        `🔍 <a href="https://www.google.com/search?q=${enc}+%D0%BA%D0%BE%D0%BC%D0%BF%D1%80%D0%BE%D0%BC%D0%B0%D1%82">Google: "${query} компромат"</a>\n` +
        `📰 <a href="https://yandex.ru/news/search?text=${enc}">Яндекс.Новости</a>`,
        { parse_mode: 'HTML', disable_web_page_preview: true }
    );
}

// ─── Полное досье (все 4 поиска в одном) ─────────────────────────────────────
async function handleFullDossier(ctx, query) {
    await ctx.reply(
        `📋 <b>Полное досье: ${query}</b>\n\n` +
        '━━━━━━━━━━━━━━━━━━━━━━\n' +
        '1️⃣ ФИО и биография\n' +
        '2️⃣ Фотографии\n' +
        '3️⃣ Адрес\n' +
        '4️⃣ Компромат\n' +
        '━━━━━━━━━━━━━━━━━━━━━━',
        { parse_mode: 'HTML' }
    );

    await ctx.reply('━━━ 1️⃣ ФИО И БИОГРАФИЯ ━━━');
    await handlePersonSearch(ctx, query);

    await ctx.reply('━━━ 2️⃣ ФОТОГРАФИИ ━━━');
    await handlePhotoSearch(ctx, query);

    await ctx.reply('━━━ 3️⃣ АДРЕС ━━━');
    await handleAddressSearch(ctx, query);

    await ctx.reply('━━━ 4️⃣ КОМПРОМАТ ━━━');
    await handleKompromat(ctx, query);

    await ctx.reply('✅ <b>Досье собрано.</b>', { parse_mode: 'HTML', ...mainMenuKeyboard() });
}

// ─── Запуск ───────────────────────────────────────────────────────────────────
bot.launch().then(() => {
    console.log('✅ Telegram бот запущен');
    db.get('SELECT COUNT(*) AS count FROM admins', (err, row) => {
        if (!err && row.count === 0) {
            const adminId = process.env.ADMIN_ID;
            if (adminId) {
                db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [adminId], () => {
                    console.log(`Админ ${adminId} добавлен.`);
                });
            }
        }
    });
});

bot.catch((err, ctx) => {
    console.error(`Ошибка [${ctx.updateType}]:`, err.message);
});

process.once('SIGINT',  () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
