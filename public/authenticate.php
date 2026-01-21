<?php
/**
 * SimpleTOTP Authenticate script
 *
 * This script displays a page to the user, which requests that they
 * submit the response from their TOTP generator.
 *
 * @package simpleSAMLphp
 */

use SimpleSAML\Configuration;
use SimpleSAML\Utils;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\State;
use SimpleSAML\Module;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Logger;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Session;
use SimpleSAML\Store\StoreFactory;

$globalConfig = Configuration::getInstance();
require Module::getModuleDir('simpletotp') . '/lib/totp.php';

function getOptionalBool(Configuration $config, string $key, bool $default): bool {
    if (method_exists($config, 'getOptionalValue')) {
        return (bool) $config->getOptionalValue($key, $default);
    }
    try {
        return (bool) $config->getValue($key, $default);
    } catch (\Throwable $e) {
        return $default;
    }
}

function getOptionalArray(Configuration $config, string $key, array $default): array {
    if (method_exists($config, 'getOptionalValue')) {
        $value = $config->getOptionalValue($key, $default);
        return is_array($value) ? $value : $default;
    }
    try {
        $value = $config->getValue($key, $default);
        return is_array($value) ? $value : $default;
    } catch (\Throwable $e) {
        return $default;
    }
}

function getOptionalString(Configuration $config, string $key, string $default): string {
    if (method_exists($config, 'getOptionalString')) {
        return (string) $config->getOptionalString($key, $default);
    }
    if (method_exists($config, 'getOptionalValue')) {
        return (string) $config->getOptionalValue($key, $default);
    }
    try {
        return (string) $config->getValue($key, $default);
    } catch (\Throwable $e) {
        return $default;
    }
}

function getClientIp(): string {
    if (method_exists(Utils\HTTP::class, 'getClientIP')) {
        return (string) Utils\HTTP::getClientIP();
    }
    if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
        return (string) $_SERVER['REMOTE_ADDR'];
    }
    return 'unknown';
}

function getRateLimitKeySourceInfo(array $state, string $keyType): array {
    if ($keyType === 'secret' && array_key_exists('mfa_secret', $state)) {
        return array((string) $state['mfa_secret'], true);
    }
    if ($keyType === 'uid' && array_key_exists('Attributes', $state)) {
        $attrs = $state['Attributes'];
        if (isset($attrs['uid'][0]) && is_string($attrs['uid'][0])) {
            return array($attrs['uid'][0], true);
        }
    }
    if ($keyType === 'ip') {
        return array(getClientIp(), true);
    }
    if (strpos($keyType, 'attr:') === 0 && array_key_exists('Attributes', $state)) {
        $attrName = substr($keyType, 5);
        $attrs = $state['Attributes'];
        if ($attrName !== '' && isset($attrs[$attrName][0]) && is_string($attrs[$attrName][0])) {
            return array($attrs[$attrName][0], true);
        }
    }
    if (array_key_exists('mfa_secret', $state)) {
        return array((string) $state['mfa_secret'], false);
    }
    return array('unknown', false);
}

$id = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && array_key_exists('StateId', $_POST)) {
    $id = $_POST['StateId'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && array_key_exists('StateId', $_GET)) {
    $id = $_GET['StateId'];
}
if ($id === null) {
    throw new BadRequest(
        'Missing required StateId query parameter.'
    );
}

$sid = State::parseStateID($id);
if (!is_null($sid['url'])) {
	$httpUtils = new Utils\HTTP();
    $httpUtils->checkURLAllowed($sid['url']);
}

$state = State::loadState($id, 'simpletotp:request');
$displayed_error = NULL;
if (!array_key_exists('mfa_secret', $state) || !is_string($state['mfa_secret']) || $state['mfa_secret'] === '') {
    throw new BadRequest('Missing MFA state.');
}

//if code is set, user has posted back to this page with a guess
$codeKey = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (array_key_exists('totp', $_POST)) {
        $codeKey = 'totp';
    } elseif (array_key_exists('code', $_POST)) {
        $codeKey = 'code';
    }
}
if ($codeKey !== null) {
    $codeInput = trim((string) $_POST[$codeKey]);
    if ($codeInput === '') {
        $displayed_error = "You must enter a TOTP token.";
    } elseif (!ctype_digit($codeInput)) {
        $displayed_error = "A valid TOTP token consists of only numeric values.";
    } elseif (strlen($codeInput) !== 6) {
        $displayed_error = "A valid TOTP token must be 6 digits long.";
    } else {
        $session = Session::getSessionFromRequest();
        $now = time();
        $attempts = (int) $session->getData('\SimpleSAML\Module\simpletotp', 'totp_attempts');
        $attempts_since = (int) $session->getData('\SimpleSAML\Module\simpletotp', 'totp_attempts_since');
        $max_attempts = array_key_exists('mfa_max_attempts', $state) ? (int) $state['mfa_max_attempts'] : 5;
        $attempt_window = array_key_exists('mfa_attempt_window', $state) ? (int) $state['mfa_attempt_window'] : 300;
        $rateStorage = array_key_exists('simpletotp_rate_limit_storage', $state) ? (string) $state['simpletotp_rate_limit_storage'] : 'session';
        $rateKeyType = array_key_exists('simpletotp_rate_limit_key', $state) ? (string) $state['simpletotp_rate_limit_key'] : 'uid';
        $useSessionRate = $rateStorage === 'session' || $rateStorage === 'both';
        $useStoreRate = $rateStorage === 'store' || $rateStorage === 'both';

        if ($useSessionRate) {
            if ($attempts_since === 0 || ($now - $attempts_since) > $attempt_window) {
                $attempts = 0;
                $attempts_since = $now;
            }
        }

        $storeBlocked = false;
        $storeCount = 0;
        $storeSince = 0;
        $storeKey = null;
        $store = null;
        if ($useStoreRate) {
            $storeType = getOptionalString($globalConfig, 'store.type', 'phpsession');
            try {
                $store = StoreFactory::getInstance($storeType);
            } catch (\Throwable $e) {
                Logger::warning('simpletotp: Store backend unavailable; falling back to session rate limiting.');
                $store = null;
                $useStoreRate = false;
            }
            if ($useStoreRate && $store) {
                [$keySource, $keyMatched] = getRateLimitKeySourceInfo($state, $rateKeyType);
                if (!$keyMatched) {
                    Logger::warning('simpletotp: Rate limit key source missing; falling back to secret.');
                }
                $storeKey = 'simpletotp:totp:' . hash('sha256', $rateKeyType . ':' . $keySource);
                $storeData = $store->get('array', $storeKey);
                if (is_array($storeData)) {
                    $storeCount = isset($storeData['count']) ? (int) $storeData['count'] : 0;
                    $storeSince = isset($storeData['since']) ? (int) $storeData['since'] : 0;
                }
                if ($storeSince === 0 || ($now - $storeSince) > $attempt_window) {
                    $storeCount = 0;
                    $storeSince = $now;
                }
                if ($storeCount >= $max_attempts) {
                    $storeBlocked = true;
                }
            }
        }

        if (($useSessionRate && $attempts >= $max_attempts) || $storeBlocked) {
            $displayed_error = "Too many TOTP attempts. Please try again later.";
        } else {
            if ($useSessionRate) {
                $attempts++;
                $session->setData(
                    '\SimpleSAML\Module\simpletotp',
                    'totp_attempts',
                    $attempts,
                    Session::DATA_TIMEOUT_SESSION_END
                );
                $session->setData(
                    '\SimpleSAML\Module\simpletotp',
                    'totp_attempts_since',
                    $attempts_since,
                    Session::DATA_TIMEOUT_SESSION_END
                );
            }
            if ($useStoreRate && $storeKey && $store) {
                $storeCount++;
                $store->set('array', $storeKey, array('count' => $storeCount, 'since' => $storeSince), $storeSince + $attempt_window);
            }

            $window = 0;
            if (array_key_exists('mfa_totp_window', $state)) {
                $window = max(0, (int) $state['mfa_totp_window']);
            }

            //check if code is valid
            Logger::debug('MFA: TOTP verification attempt.');
            $isValid = verifyCode($state['mfa_secret'], $codeInput, $window);

            if ($isValid) {
                $session->setData(
                    '\SimpleSAML\Module\simpletotp',
                    'lastverified',
                    $now,
                    Session::DATA_TIMEOUT_SESSION_END
                );
                if ($useSessionRate) {
                    $session->setData(
                        '\SimpleSAML\Module\simpletotp',
                        'totp_attempts',
                        0,
                        Session::DATA_TIMEOUT_SESSION_END
                    );
                    $session->setData(
                        '\SimpleSAML\Module\simpletotp',
                        'totp_attempts_since',
                        $now,
                        Session::DATA_TIMEOUT_SESSION_END
                    );
                }
                if ($useStoreRate && $storeKey && $store) {
                    $store->delete('array', $storeKey);
                }
                ProcessingChain::resumeProcessing($state);
            } else {
                $displayed_error = "You have entered the incorrect TOTP token.";
            }
        }
    }
}

// populate values for template
$t = new Template($globalConfig, 'simpletotp:authenticate.twig');
$t->data['formData'] = array('StateId' => $id);
$t->data['formPost'] = Module::getModuleURL('simpletotp/authenticate.php');
$restartEnabled = array_key_exists('simpletotp_restart_enabled', $state)
    ? (bool) $state['simpletotp_restart_enabled']
    : getOptionalBool($globalConfig, 'simpletotp.restart_enabled', false);
if ($restartEnabled) {
    $t->data['restartUrl'] = Module::getModuleURL('simpletotp/restart.php');
    $t->data['restartReturnTo'] = Module::getModuleURL('simpletotp/authenticate.php', array('StateId' => $id));
    $restartCookies = array_key_exists('simpletotp_clear_cookies', $state) && is_array($state['simpletotp_clear_cookies'])
        ? $state['simpletotp_clear_cookies']
        : getOptionalArray($globalConfig, 'simpletotp.clear_cookies', array('SimpleSAMLAuthToken'));
    $t->data['restartCookies'] = $restartCookies;
}
$t->data['userError'] = $displayed_error;
echo $t->getContents();
