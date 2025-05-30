<?php
require_once 'config.php';
require_once 'database.php';

$error_msg = "";
$success_msg = "";

function getIP()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

function get_config($name)
{
    global $config;
    if (!empty($name)) {
        if (isset($config[$name])) {
            return $config[$name];
        }
    }
    return false;
}

function get_core_config($name)
{
    global $core_config;
    if (!empty($name)) {
        if (isset($core_config[$name])) {
            return $core_config[$name];
        }
    }
    return false;
}

function error_msg($input = false)
{
    global $error_error;
    if (!empty($error_error)) {
        echo "<p class=\"alert alert-danger\">$error_error</p>";
    } elseif (!empty($input)) {
        $error_error = $input;
    }
}

function success_msg($input = false)
{
    global $success_msg;
    if (!empty($success_msg)) {
        echo "<p class=\"alert alert-success\">$success_msg</p>";
    } elseif (!empty($input)) {
        $success_msg = $input;
    }
}

function generateRandomString($length = 10)
{
    $characters = '0123456789abcdefghijklmnopqrstuvwxyz';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}


function RemoteCommandWithSOAP($COMMAND)
{
    global $soap_connection_info;

    if (empty($COMMAND)) {
        return false;
    }

    try {
        $conn = new SoapClient(NULL, array(
            'location' => 'http://' . get_config('soap_host') . ':' . get_config('soap_port') . '/',
            'uri' => get_config('soap_uri'),
            'style' => get_config('soap_style'),
            'login' => get_config('soap_username'),
            'password' => get_config('soap_password')
        ));
        $conn->executeCommand(new SoapParam($COMMAND, 'command'));
        unset($conn);
        return true;
    } catch (Exception $e) {
        return false;
    }
}

function calculateSRP6Verifier($username, $password, $salt)
{
    $g = gmp_init(7);
    $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

    $h1 = sha1(strtoupper($username . ':' . $password), TRUE);

	if(get_config('server_core') == 5)
	{
		$h2 = sha1(strrev($salt) . $h1, TRUE);
	} else {
		$h2 = sha1($salt . $h1, TRUE);
	}

    $h2 = gmp_import($h2, 1, GMP_LSW_FIRST);

    $verifier = gmp_powm($g, $h2, $N);

    $verifier = gmp_export($verifier, 1, GMP_LSW_FIRST);

    $verifier = str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);

	if(get_config('server_core') == 5)
	{
		return strrev($verifier);
	} else {
		return $verifier;
	}
}

function getRegistrationData($username, $password)
{
    $salt = random_bytes(32);

    $verifier = calculateSRP6Verifier($username, $password, $salt);

	if(get_config('server_core') == 5)
	{
		$salt = strtoupper(bin2hex($salt));
		$verifier = strtoupper(bin2hex($verifier));
	}
	
    return array($salt, $verifier);
}

function verifySRP6($user, $pass, $salt, $verifier)
{
    $g = gmp_init(7);
    $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);
    $x = gmp_import(
        sha1($salt . sha1(strtoupper($user . ':' . $pass), TRUE), TRUE),
        1,
        GMP_LSW_FIRST
    );
    $v = gmp_powm($g, $x, $N);
    return ($verifier === str_pad(gmp_export($v, 1, GMP_LSW_FIRST), 32, chr(0), STR_PAD_RIGHT));
}

function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validatePassword($password) {
    return strlen($password) >= 8 && 
           preg_match('/[0-9]/', $password) && 
           preg_match('/[a-zA-Z]/', $password);
}

function generateSalt() {
    return bin2hex(random_bytes(16));
}

function hashPassword($password, $salt) {
    return password_hash($password . $salt, PASSWORD_BCRYPT, ['cost' => HASH_COST]);
}

function createBattlenetAccount($email, $password) {
    $db = Database::getInstance();

    $stmt = $db->query("SELECT id FROM battlenet_accounts WHERE email = ?", [$email]);
    if ($stmt->rowCount() > 0) {
        return false;
    }

    $bnetHash = strtoupper(bin2hex(strrev(hex2bin(strtoupper(hash('sha256', strtoupper(hash('sha256', strtoupper($email)) . ':' . strtoupper($password))))))));

    $db->query(
        "INSERT INTO battlenet_accounts (email, sha_pass_hash) VALUES (?, ?)",
        [$email, $bnetHash]
    );

    return $db->getConnection()->lastInsertId();
}

function createGameAccount($battlenetId) {
    global $config;
    $db = Database::getInstance();

    $username = $battlenetId . '#1';

    $db->query(
        "INSERT INTO account (username, battlenet_account, battlenet_index, email, expansion) 
         VALUES (?, ?, 1, '', ?)",
        [$username, $battlenetId, $config['expansion']]
    );

    return $db->getConnection()->lastInsertId();
}

function setFlashMessage($type, $message) {
    $_SESSION['flash'] = [
        'type' => $type,
        'message' => $message
    ];
}

function getFlashMessage() {
    if (isset($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}

function validateRecaptcha($recaptcha_response) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => RECAPTCHA_SECRET_KEY,
        'response' => $recaptcha_response
    ];

    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];

    $context = stream_context_create($options);
    $response = file_get_contents($url, false, $context);
    $result = json_decode($response, true);

    return $result['success'] ?? false;
}

function bnet_register()
{
    global $error_msg, $success_msg;

    if (!isset($_POST['g-recaptcha-response']) || !validateRecaptcha($_POST['g-recaptcha-response'])) {
        error_msg("Пожалуйста, пройдите проверку reCAPTCHA");
        return;
    }

    if ($_POST['submit'] != 'register' || empty($_POST['password']) || empty($_POST['repassword']) || empty($_POST['email'])) {
        return false;
    }

    if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
        error_msg('Пожалуйста, используйте действительный адрес электронной почты');
        return false;
    }

    if ($_POST['password'] != $_POST['repassword']) {
        error_msg('Пароли не совпадают');
        return false;
    }

    if (!(strlen($_POST['password']) >= 4 && strlen($_POST['password']) <= 16)) {
        error_msg('Пароль должен содержать от 4 до 16 символов');
        return false;
    }

    $db = Database::getInstance();
    
    $stmt = $db->query("SELECT id FROM battlenet_accounts WHERE email = ?", [strtoupper($_POST['email'])]);
    if ($stmt->rowCount() > 0) {
        error_msg('E-mail уже существует');
        return false;
    }

    $bnet_hashed_pass = strtoupper(bin2hex(strrev(hex2bin(strtoupper(hash('sha256', strtoupper(hash('sha256', strtoupper($_POST['email'])) . ':' . strtoupper($_POST['password']))))))));

    $db->query(
        "INSERT INTO battlenet_accounts (email, sha_pass_hash) VALUES (?, ?)",
        [strtoupper($_POST['email']), $bnet_hashed_pass]
    );

    $bnet_account_id = $db->getConnection()->lastInsertId();
    $username = $bnet_account_id . '#1';
    
    if (empty(get_config('srp6_support'))) {
        $hashed_pass = strtoupper(sha1(strtoupper($username . ':' . $_POST['password'])));
        
        $db->query(
            "INSERT INTO account (username, sha_pass_hash, email, expansion, battlenet_account, battlenet_index) 
             VALUES (?, ?, ?, ?, ?, 1)",
            [strtoupper($username), $hashed_pass, strtoupper($_POST['email']), get_config('expansion'), $bnet_account_id]
        );
    } else {
        list($salt, $verifier) = getRegistrationData(strtoupper($username), $_POST['password']);
        
        $db->query(
            "INSERT INTO account (username, " . get_core_config("salt_field") . ", " . get_core_config("verifier_field") . ", email, expansion, battlenet_account, battlenet_index) 
             VALUES (?, ?, ?, ?, ?, ?, 1)",
            [strtoupper($username), $salt, $verifier, strtoupper($_POST['email']), get_config('expansion'), $bnet_account_id]
        );
    }

    success_msg('Аккаунт успешно создан');
    return true;
}

function get_server_status() {
    $realmlist = get_config('realmlist');
    $port = get_config('wow_server_port');
    
    $connection = @fsockopen($realmlist, $port, $errno, $errstr, 5);
    if ($connection) {
        fclose($connection);
        return true;
    }
    return false;
}
