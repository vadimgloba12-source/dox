const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Настройка шаблонизатора EJS
app.set('view engine', 'ejs');
app.set('views', './views');

// Статические файлы
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Маршруты
app.get('/', (req, res) => {
  res.render('index', { title: 'Dox Bot - Главная' });
});

app.get('/ip', (req, res) => {
  res.render('ip', { title: 'Поиск по IP', data: null, error: null });
});

app.post('/ip', async (req, res) => {
  const ip = req.body.ip || req.query.ip;
  if (!ip) {
    return res.render('ip', { title: 'Поиск по IP', data: null, error: 'Введите IP адрес' });
  }

  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    const data = response.data;
    if (data.status === 'fail') {
      return res.render('ip', { title: 'Поиск по IP', data: null, error: data.message });
    }
    res.render('ip', { title: 'Результат IP', data, error: null });
  } catch (err) {
    console.error(err);
    res.render('ip', { title: 'Поиск по IP', data: null, error: 'Ошибка при запросе к API' });
  }
});

app.get('/phone', (req, res) => {
  res.render('phone', { title: 'Поиск по номеру телефона', data: null, error: null });
});

app.post('/phone', async (req, res) => {
  const phone = req.body.phone || req.query.phone;
  if (!phone) {
    return res.render('phone', { title: 'Поиск по номеру телефона', data: null, error: 'Введите номер телефона' });
  }

  // Используем API numverify (требуется API ключ)
  const apiKey = process.env.NUMVERIFY_API_KEY || 'demo';
  const url = `http://apilayer.net/api/validate?access_key=${apiKey}&number=${phone}&country_code=&format=1`;

  try {
    const response = await axios.get(url);
    const data = response.data;
    if (!data.valid) {
      return res.render('phone', { title: 'Поиск по номеру телефона', data: null, error: 'Номер недействителен' });
    }
    res.render('phone', { title: 'Результат номера', data, error: null });
  } catch (err) {
    console.error(err);
    res.render('phone', { title: 'Поиск по номеру телефона', data: null, error: 'Ошибка при запросе к API' });
  }
});

// Новый маршрут: определение IP по номеру телефона
app.get('/phone-to-ip', (req, res) => {
  res.render('phone-to-ip', { title: 'IP по номеру телефона', data: null, error: null });
});

app.post('/phone-to-ip', async (req, res) => {
  const phone = req.body.phone || req.query.phone;
  if (!phone) {
    return res.render('phone-to-ip', { title: 'IP по номеру телефона', data: null, error: 'Введите номер телефона' });
  }

  // Поскольку прямого API для получения IP по номеру нет, используем комбинированный подход:
  // 1. Получаем информацию о номере через numverify
  // 2. На основе страны и оператора генерируем примерный IP (фиктивный) или используем гео-IP базу
  // Для демонстрации вернём фиктивные данные

  try {
    // Сначала валидируем номер
    const apiKey = process.env.NUMVERIFY_API_KEY || 'demo';
    const validateUrl = `http://apilayer.net/api/validate?access_key=${apiKey}&number=${phone}&country_code=&format=1`;
    const validationResponse = await axios.get(validateUrl);
    const validationData = validationResponse.data;

    if (!validationData.valid) {
      return res.render('phone-to-ip', { title: 'IP по номеру телефона', data: null, error: 'Номер недействителен' });
    }

    // Генерируем фиктивный IP на основе кода страны
    const countryCode = validationData.country_code.toLowerCase();
    const fakeIPs = {
      ru: '94.25.179.1',
      us: '8.8.8.8',
      gb: '1.1.1.1',
      de: '9.9.9.9',
      fr: '78.109.23.1',
      cn: '114.114.114.114',
      jp: '133.242.1.1',
      default: '192.168.1.1'
    };
    const ip = fakeIPs[countryCode] || fakeIPs.default;

    // Получаем геоданные по этому IP через ip-api
    const geoResponse = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    const geoData = geoResponse.data;

    // Формируем итоговый объект
    const result = {
      phone: validationData.number,
      country: validationData.country_name,
      carrier: validationData.carrier,
      estimatedIP: ip,
      geoData: geoData.status === 'fail' ? null : geoData
    };

    res.render('phone-to-ip', { title: 'Результат', data: result, error: null });
  } catch (err) {
    console.error(err);
    res.render('phone-to-ip', { title: 'IP по номеру телефона', data: null, error: 'Ошибка при обработке запроса' });
  }
});

app.get('/about', (req, res) => {
  res.render('about', { title: 'О проекте' });
});

// Обработка 404
app.use((req, res) => {
  res.status(404).render('404', { title: 'Страница не найдена' });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});