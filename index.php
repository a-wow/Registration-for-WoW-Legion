<?php
require_once 'config/config.php';
require_once 'config/database.php';
require_once 'config/functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    bnet_register();
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo get_config('page_title'); ?> - World of Warcraft Legion</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700&family=Marcellus&display=swap" rel="stylesheet">
    <link href="assets/css/styles.css" rel="stylesheet">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <!-- Статус сервера -->
    <section class="stage-section">
        <div class="stage-content">
            <h1 class="stage-title">World of Warcraft: Legion</h1>
            <div class="server-status">
                <span class="status-indicator <?php echo get_server_status() ? 'online' : 'offline'; ?>">
                    <?php echo get_server_status() ? 'Online' : 'Offline'; ?>
                </span>
                <div class="server-info">
                    <p>SET Portal <?php echo get_config('realmlist'); ?></p>
                </div>
            </div>
            <p class="stage-description">
                Добро пожаловать на сервер World of Warcraft: Legion! Погрузитесь в эпический мир Азерота, 
                где герои сражаются с демоническим нашествием. Присоединяйтесь к нашему сообществу и станьте 
                частью легендарной истории! Открытие 31 мая 2025г
            </p>
            <a href="#registration" class="btn btn-primary">Начать игру</a>
        </div>
    </section>

    <!-- Регистрация -->
    <section id="registration" class="stage-section">
        <div class="stage-content">
            <h2 class="stage-title">Регистрация</h2>
            <div class="registration-container">
                <?php 
                error_msg();
                success_msg();
                ?>
                <form method="POST" action="">
                    <div class="mb-3">
                        <label for="email" class="form-label">E-mail</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>

                    <div class="mb-3">
                        <label for="password" class="form-label">
                            Пароль
                            <button type="button" class="info-button" aria-label="Информация о пароле">
                                i
                                <div class="password-tooltip">
                                    <ul>
                                        <li>Длина: 4–16 символов</li>
                                        <li>Допустимые символы: буквы, цифры и специальные символы</li>
                                    </ul>
                                </div>
                            </button>
                        </label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>

                    <div class="mb-3">
                        <label for="confirm_password" class="form-label">Подтвердите пароль</label>
                        <input type="password" class="form-control" id="confirm_password" name="repassword" required>
                    </div>

                    <div class="mb-3">
                        <div class="g-recaptcha" data-sitekey="<?php echo RECAPTCHA_SITE_KEY; ?>"></div>
                    </div>

                    <button type="submit" name="submit" value="register" class="btn btn-primary w-100">Зарегистрироваться</button>
                </form>

                <div class="text-center">
                    <p class="text-muted">Создавая учетную запись, вы соглашаетесь с нашими Условиями обслуживания и Политикой конфиденциальности</p>
                </div>
            </div>
        </div>
    </section>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const minLength = 4;
            const maxLength = 16;
            const allowedChars = /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]*$/;
            
            if (password.length < minLength || password.length > maxLength) {
                this.setCustomValidity(`Пароль должен содержать от ${minLength} до ${maxLength} символов`);
            } else if (!allowedChars.test(password)) {
                this.setCustomValidity('Пароль содержит недопустимые символы');
            } else {
                this.setCustomValidity('');
            }
        });

        document.getElementById('confirm_password').addEventListener('input', function() {
            const password = document.getElementById('password').value;
            if (this.value !== password) {
                this.setCustomValidity('Пароли не совпадают');
            } else {
                this.setCustomValidity('');
            }
        });

        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    </script>
</body>
</html>
