<?php
$config['baseurl'] = "http://your_domain";
$config['page_title'] = "A-WoW TITLE";
$config['realmlist'] = 'A-WoW';
$config['wow_server_port'] = 8095; // Порт сервера WoW для проверки онлайн-статуса

// Конфигурация сервера
/*=======================
0 = Classic, 1 = The Burning Crusade (TBC), 2 = Wrath of the Lich King (WotLK), 3 = Cataclysm, 4 = Mist of Pandaria (MOP), 5 = Warlords of Draenor (WOD), 6 = Legion, 7 = BFA
=======================*/
$config['expansion'] = '6'; // Legion

/*=======================
0 = TrinityCore, 1 = AzerothCore, 2 = AshamaneCore, 3 = Skyfire Project, 4 = OregonCore, 5 = CMangos, 10 = etc
=======================*/
$config['server_core'] = 0; // TrinityCore

/*=======================
Если ваш сервер WoD/Legion/BFA, вам следует включить battlenet_support!
true = включено
false = выключено
=======================*/
$config['battlenet_support'] = true;
$config['srp6_support'] = false;

// Конфигурация базы данных
define('DB_HOST', 'localhost');
define('DB_PORT', '8081');
define('DB_USER', 'root');
define('DB_PASS', 'ascent');
define('DB_NAME', 'auth');
define('DB_CHARSET', 'utf8mb4');

$core_config['salt_field'] = 'salt';
$core_config['verifier_field'] = 'verifier';

define('HASH_COST', 12);
define('SESSION_LIFETIME', 3600);

// Настройки reCAPTCHA v2
// https://www.google.com/recaptcha/admin
define('RECAPTCHA_SITE_KEY', 'ключ_сайта');
define('RECAPTCHA_SECRET_KEY', 'секретный_ключ');

error_reporting(E_ALL);
ini_set('display_errors', 1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
