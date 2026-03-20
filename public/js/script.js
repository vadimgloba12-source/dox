// Основной скрипт для Dox Bot

document.addEventListener('DOMContentLoaded', function() {
    console.log('Dox Bot loaded');

    // Анимация кнопок
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.05)';
        });
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    });

    // Автозаполнение IP пользователя на странице IP
    if (window.location.pathname === '/ip') {
        const ipInput = document.querySelector('input[name="ip"]');
        if (ipInput && !ipInput.value) {
            // Можно получить IP пользователя через внешний сервис (опционально)
            fetch('https://api.ipify.org?format=json')
                .then(res => res.json())
                .then(data => {
                    ipInput.placeholder = `Ваш IP: ${data.ip}`;
                })
                .catch(() => {});
        }
    }

    // Подсветка активной навигации
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-links a');
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

    // Обработка форм с подтверждением
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const input = this.querySelector('input[type="text"]');
            if (input && !input.value.trim()) {
                e.preventDefault();
                alert('Пожалуйста, заполните поле.');
                input.focus();
            }
        });
    });

    // Динамическое обновление года в футере
    const yearSpan = document.getElementById('current-year');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }
});