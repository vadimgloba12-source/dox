
const { Telegraf, Markup } = require('telegraf');
const axios = require('axios');
const NodeCache = require('node-cache');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

// Инициализация базы данных SQLite
const db = new sqlite3.Database('./database.sqlite');

// Создание таблиц
db.serialize(() => {
    // Таблица пользователей (номер телефона, баланс звёзд, разрешён ли доступ)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        phone TEXT,
        stars INTEGER DEFAULT 0,
        allowed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Таблица админов
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        telegram_id INTEGER UNIQUE,
        is_super BOOLEAN DEFAULT 0
    )`);

    // Таблица запросов (история использования)
    db.run(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        query TEXT,
        result TEXT,
        cost INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const cache = new NodeCache({ stdTTL: 600 });

// Конфигурация
const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
    console.error('BOT_TOKEN не указан в .env файле');
    process.exit(1);
}

const bot = new Telegraf(BOT_TOKEN);

// Middleware для проверки админских прав
function isAdmin(ctx, next) {
    const userId = ctx.from.id;
    db.get('SELECT * FROM admins WHERE telegram_id = ?', [userId], (err, row) => {
        if (err || !row) {
            return ctx.reply('⛔ У вас нет прав администратора.');
        }
        return next();
    });
}

// Команда старт
bot.start(async (ctx) => {
    const userId = ctx.from.id;
    const userName = ctx.from.first_name;

    // Проверяем, есть ли пользователь в базе
    db.get('SELECT * FROM users WHERE telegram_id = ?', [userId], (err, row) => {
        if (err) {
            console.error(err);
            return ctx.reply('Произошла ошибка. Попробуйте позже.');
        }

        if (!row) {
            // Новый пользователь — просим предоставить номер телефона
            ctx.reply(
                `Привет, ${userName}! 👋\n` +
                'Это бот для получения информации по IP и номерам телефонов.\n\n' +
                'Для использования необходимо предоставить номер телефона.',
                Markup.keyboard([
                    Markup.button.contactRequest('📱 Отправить номер телефона')
                ]).resize()
            );
        } else if (!row.allowed) {
            ctx.reply('Ваш номер ещё не подтверждён администратором. Ожидайте.');
        } else {
            ctx.reply(
                `С возвращением, ${userName}! 🎉\n` +
                `Ваш баланс звёзд: ${row.stars} ⭐\n\n` +
                'Выберите действие:',
                mainMenuKeyboard()
            );
        }
    });
});

// Обработка отправки контакта
bot.on('contact', async (ctx) => {
    const contact = ctx.message.contact;
    const userId = ctx.from.id;

    if (contact.user_id !== userId) {
        return ctx.reply('Вы отправили не свой контакт.');
    }

    const phone = contact.phone_number;
    // Сохраняем или обновляем пользователя
    db.run(
        'INSERT OR REPLACE INTO users (telegram_id, phone, allowed) VALUES (?, ?, ?)',
        [userId, phone, 0],
        (err) => {
            if (err) {
                console.error(err);
                return ctx.reply('Ошибка сохранения номера.');
            }
            ctx.reply(
                `Номер ${phone} сохранён. Ожидайте подтверждения администратора.`,
                Markup.removeKeyboard()
            );
            // Уведомление админам
            notifyAdmins(`Новый пользователь: @${ctx.from.username} (${phone}) ожидает подтверждения.`);
            // Если номер соответствует специальному номеру админа, добавляем в админы
            if (phone === '+79282953494' || phone === '79282953494' || phone === '+7 928 295 34 94') {
                db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [userId], (err) => {
                    if (!err) {
                        console.log(`Пользователь ${userId} добавлен как админ по номеру ${phone}.`);
                        bot.telegram.sendMessage(userId, '🔐 Вы автоматически добавлены как администратор.');
                    }
                });
            }
        }
    );
});

// Команда /menu
bot.command('menu', (ctx) => {
    ctx.reply('Главное меню:', mainMenuKeyboard());
});

// Команда /balance
bot.command('balance', (ctx) => {
    const userId = ctx.from.id;
    db.get('SELECT stars FROM users WHERE telegram_id = ?', [userId], (err, row) => {
        if (err || !row) {
            return ctx.reply('Пользователь не найден.');
        }
        ctx.reply(`Ваш баланс: ${row.stars} ⭐`);
    });
});

// Команда /myip — показать IP пользователя
bot.command('myip', (ctx) => {
    // IP пользователя можно получить из ctx.update (не напрямую)
    // В Telegram бот не видит IP пользователя, но можно показать публичный IP пользователя через внешний API
    ctx.reply('Определяю ваш IP...');
    axios.get('https://api.ipify.org?format=json')
        .then(response => {
            const ip = response.data.ip;
            ctx.reply(`Ваш публичный IP‑адрес: <code>${ip}</code>\n\n` +
                'Вы можете использовать его для поиска информации через команду поиска по IP.', { parse_mode: 'HTML' });
        })
        .catch(error => {
            console.error(error);
            ctx.reply('Не удалось определить IP.');
        });
});

// АДМИНСКИЕ КОМАНДЫ

// /admin — панель админа
bot.command('admin', (ctx) => isAdmin(ctx, () => {
    ctx.reply(
        'Панель администратора:',
        adminMenuKeyboard()
    );
}));

// /allow_user [id] — разрешить пользователю
bot.command('allow_user', (ctx) => isAdmin(ctx, () => {
    const args = ctx.message.text.split(' ');
    if (args.length < 2) {
        return ctx.reply('Использование: /allow_user <telegram_id>');
    }
    const targetId = parseInt(args[1]);
    db.run('UPDATE users SET allowed = 1 WHERE telegram_id = ?', [targetId], function(err) {
        if (err) {
            ctx.reply('Ошибка базы данных.');
            return;
        }
        if (this.changes === 0) {
            ctx.reply('Пользователь не найден.');
        } else {
            ctx.reply('Пользователь подтверждён.');
            bot.telegram.sendMessage(targetId, '✅ Ваш номер подтверждён администратором. Теперь вы можете использовать бота.');
        }
    });
}));

// /add_stars [id] [amount] — добавить звёзды
bot.command('add_stars', (ctx) => isAdmin(ctx, () => {
    const args = ctx.message.text.split(' ');
    if (args.length < 3) {
        return ctx.reply('Использование: /add_stars <telegram_id> <количество>');
    }
    const targetId = parseInt(args[1]);
    const amount = parseInt(args[2]);
    if (isNaN(amount) || amount <= 0) {
        return ctx.reply('Количество должно быть положительным числом.');
    }
    db.run('UPDATE users SET stars = stars + ? WHERE telegram_id = ?', [amount, targetId], function(err) {
        if (err) {
            ctx.reply('Ошибка базы данных.');
            return;
        }
        if (this.changes === 0) {
            ctx.reply('Пользователь не найден.');
        } else {
            ctx.reply(`Добавлено ${amount} ⭐ пользователю ${targetId}.`);
            bot.telegram.sendMessage(targetId, `Вам начислено ${amount} ⭐. Новый баланс: ? (проверьте /balance)`);
        }
    });
}));

// /list_pending — список ожидающих подтверждения
bot.command('list_pending', (ctx) => isAdmin(ctx, () => {
    db.all('SELECT telegram_id, phone FROM users WHERE allowed = 0', (err, rows) => {
        if (err) {
            return ctx.reply('Ошибка базы данных.');
        }
        if (rows.length === 0) {
            return ctx.reply('Нет ожидающих пользователей.');
        }
        let message = 'Ожидающие подтверждения:\n';
        rows.forEach(row => {
            message += `ID: ${row.telegram_id}, Телефон: ${row.phone}\n`;
        });
        ctx.reply(message);
    });
}));

// /stats — статистика
bot.command('stats', (ctx) => isAdmin(ctx, () => {
    db.get('SELECT COUNT(*) as total_users FROM users', (err, row1) => {
        db.get('SELECT COUNT(*) as allowed_users FROM users WHERE allowed = 1', (err, row2) => {
            db.get('SELECT SUM(stars) as total_stars FROM users', (err, row3) => {
                const totalStars = row3.total_stars || 0;
                ctx.reply(
                    `📊 Статистика бота:\n` +
                    `👥 Всего пользователей: ${row1.total_users}\n` +
                    `✅ Подтверждённых: ${row2.allowed_users}\n` +
                    `⭐ Всего звёзд в системе: ${totalStars}`
                );
            });
        });
    });
}));

// Обработка кнопок
bot.action('ip_lookup', (ctx) => {
    ctx.reply('Введите IP‑адрес для поиска:');
    ctx.session = { action: 'ip_lookup' };
});

bot.action('phone_lookup', (ctx) => {
    ctx.reply('Введите номер телефона для проверки:');
    ctx.session = { action: 'phone_lookup' };
});

// Покупка звёзд
bot.action('buy_stars', (ctx) => {
    ctx.reply(
        'Выберите пакет звёзд для покупки:\n\n' +
        '1. 10 ⭐ — 50 руб.\n' +
        '2. 25 ⭐ — 100 руб.\n' +
        '3. 50 ⭐ — 180 руб.\n' +
        '4. 100 ⭐ — 300 руб.\n\n' +
        'Для оплаты свяжитесь с администратором @admin.',
        Markup.inlineKeyboard([
            [Markup.button.callback('10 ⭐ (50 руб)', 'stars_10')],
            [Markup.button.callback('25 ⭐ (100 руб)', 'stars_25')],
            [Markup.button.callback('50 ⭐ (180 руб)', 'stars_50')],
            [Markup.button.callback('100 ⭐ (300 руб)', 'stars_100')],
            [Markup.button.callback('Назад', 'back_to_menu')]
        ])
    );
});

// Обработка выбора пакета
bot.action('stars_10', (ctx) => handleStarsPurchase(ctx, 10, 50));
bot.action('stars_25', (ctx) => handleStarsPurchase(ctx, 25, 100));
bot.action('stars_50', (ctx) => handleStarsPurchase(ctx, 50, 180));
bot.action('stars_100', (ctx) => handleStarsPurchase(ctx, 100, 300));

bot.action('back_to_menu', (ctx) => {
    ctx.editMessageText('Главное меню:', mainMenuKeyboard());
});

function handleStarsPurchase(ctx, stars, price) {
    ctx.reply(
        `Вы выбрали пакет ${stars} ⭐ за ${price} руб.\n\n` +
        'Для завершения оплаты отправьте сумму администратору @admin и укажите ваш ID: ' + ctx.from.id + '\n' +
        'После подтверждения вам будут начислены звёзды.'
    );
}

// Обработка текстовых сообщений (для ввода IP/телефона)
bot.on('text', async (ctx) => {
    const userId = ctx.from.id;
    const text = ctx.message.text;

    // Проверяем, есть ли активная сессия
    if (ctx.session && ctx.session.action === 'ip_lookup') {
        // Проверка баланса
        const user = await getUser(userId);
        if (!user || user.stars < 5) {
            return ctx.reply('Недостаточно звёзд. Нужно 5 ⭐ за запрос.');
        }
        // Списание звёзд
        await updateStars(userId, -5);
        // Поиск IP
        const result = await lookupIP(text);
        ctx.reply(result, { parse_mode: 'HTML' });
        ctx.session = null;
    } else if (ctx.session && ctx.session.action === 'phone_lookup') {
        const user = await getUser(userId);
        if (!user || user.stars < 10) {
            return ctx.reply('Недостаточно звёзд. Нужно 10 ⭐ за запрос.');
        }
        await updateStars(userId, -10);
        const result = await lookupPhone(text);
        ctx.reply(result, { parse_mode: 'HTML' });
        ctx.session = null;
    }
});

// Вспомогательные функции
function mainMenuKeyboard() {
    return Markup.inlineKeyboard([
        [Markup.button.callback('🔍 Поиск по IP', 'ip_lookup')],
        [Markup.button.callback('📞 Поиск по номеру', 'phone_lookup')],
        [Markup.button.callback('⭐ Купить звёзды', 'buy_stars')],
        [Markup.button.callback('📊 Мой баланс', 'balance')],
        [Markup.button.callback('🌐 Мой IP', 'my_ip_action')]
    ]);
}

// Добавляем действие для кнопки "Мой IP"
bot.action('my_ip_action', (ctx) => {
    ctx.reply('Определяю ваш IP...');
    axios.get('https://api.ipify.org?format=json')
        .then(response => {
            const ip = response.data.ip;
            ctx.reply(`Ваш публичный IP‑адрес: <code>${ip}</code>`, { parse_mode: 'HTML' });
        })
        .catch(error => {
            console.error(error);
            ctx.reply('Не удалось определить IP.');
        });
});

function adminMenuKeyboard() {
    return Markup.inlineKeyboard([
        [Markup.button.callback('📋 Список ожидающих', 'list_pending')],
        [Markup.button.callback('✅ Подтвердить пользователя', 'allow_user')],
        [Markup.button.callback('⭐ Добавить звёзды', 'add_stars')],
        [Markup.button.callback('📊 Статистика', 'stats')]
    ]);
}

function getUser(telegramId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE telegram_id = ?', [telegramId], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function updateStars(telegramId, delta) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET stars = stars + ? WHERE telegram_id = ?', [delta, telegramId], function(err) {
            if (err) reject(err);
            else resolve(this.changes);
        });
    });
}

async function lookupIP(ip) {
    try {
        const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
        const data = response.data;
        if (data.status === 'fail') {
            return `Ошибка: ${data.message}`;
        }
        return `<b>Результат для IP ${data.query}:</b>\n` +
               `🌍 Страна: ${data.country} (${data.countryCode})\n` +
               `🏙️ Город: ${data.city}\n` +
               `📍 Регион: ${data.regionName}\n` +
               `📡 Провайдер: ${data.isp}\n` +
               `📊 Организация: ${data.org}\n` +
               `🕐 Часовой пояс: ${data.timezone}\n` +
               `📌 Координаты: ${data.lat}, ${data.lon}`;
    } catch (error) {
        console.error(error);
        return 'Ошибка при запросе к API.';
    }
}

async function lookupPhone(phone) {
    // Используем демо-ключ num

    const apiKey = process.env.NUMVERIFY_API_KEY || 'demo';
    const url = `http://apilayer.net/api/validate?access_key=${apiKey}&number=${phone}&country_code=&format=1`;
    try {
        const response = await axios.get(url);
        const data = response.data;
        if (!data.valid) {
            return 'Номер недействителен.';
        }
        return `<b>Результат для номера ${data.number}:</b>\n` +
               `✅ Действителен: Да\n` +
               `🌍 Страна: ${data.country_name} (${data.country_code})\n` +
               `📞 Оператор: ${data.carrier}\n` +
               `📟 Тип линии: ${data.line_type}\n` +
               `📍 Локация: ${data.location}`;
    } catch (error) {
        console.error(error);
        return 'Ошибка при запросе к API.';
    }
}

function notifyAdmins(message) {
    // Получаем список админов и отправляем им сообщение
    db.all('SELECT telegram_id FROM admins', (err, rows) => {
        if (err) return;
        rows.forEach(row => {
            bot.telegram.sendMessage(row.telegram_id, message).catch(console.error);
        });
    });
}

// Запуск бота
bot.launch().then(() => {
    console.log('Telegram бот запущен');
    // Добавим первого админа, если таблица пуста
    db.get('SELECT COUNT(*) as count FROM admins', (err, row) => {
        if (row.count === 0) {
            const adminId = process.env.ADMIN_ID;
            if (adminId) {
                db.run('INSERT OR REPLACE INTO admins (telegram_id, is_super) VALUES (?, 1)', [adminId], (err) => {
                    if (!err) {
                        console.log(`Админ ${adminId} добавлен как супер-админ.`);
                    }
                });
            }
        }
    });
});

// Обработка ошибок
bot.catch((err, ctx) => {
    console.error(`Ошибка для ${ctx.updateType}:`, err);
});
