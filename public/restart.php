<?php
/**
 * SimpleTOTP restart helper
 *
 * Clears configured cookies and redirects to a configured restart URL to
 * trigger a fresh login flow when logout endpoints are unavailable.
 */

use SimpleSAML\Configuration;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Utils;

$globalConfig = Configuration::getInstance();
$cookieNames = null;

$returnTo = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && array_key_exists('ReturnTo', $_POST)) {
    $returnTo = $_POST['ReturnTo'];
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && array_key_exists('ReturnTo', $_GET)) {
    $returnTo = $_GET['ReturnTo'];
}
if (!is_string($returnTo) || $returnTo === '') {
    throw new BadRequest('Missing ReturnTo parameter.');
}

if ($cookieNames === null) {
    if (method_exists($globalConfig, 'getOptionalValue')) {
        $cookieNames = $globalConfig->getOptionalValue('simpletotp.clear_cookies', array('SimpleSAMLAuthToken'));
    } else {
        try {
            $cookieNames = $globalConfig->getValue('simpletotp.clear_cookies', array('SimpleSAMLAuthToken'));
        } catch (\Throwable $e) {
            $cookieNames = array('SimpleSAMLAuthToken');
        }
    }
}
if (!is_array($cookieNames)) {
    $cookieNames = array('SimpleSAMLAuthToken');
}

if (empty($cookieNames)) {
    if (method_exists($globalConfig, 'getOptionalString')) {
        $sessionCookie = $globalConfig->getOptionalString('session.cookie.name', 'SimpleSAMLSessionID');
        $authTokenCookie = $globalConfig->getOptionalString('session.authtoken.cookiename', 'SimpleSAMLAuthToken');
        $cookieNames = array($sessionCookie, $authTokenCookie);
    } else {
        try {
            $sessionCookie = $globalConfig->getValue('session.cookie.name', 'SimpleSAMLSessionID');
            $authTokenCookie = $globalConfig->getValue('session.authtoken.cookiename', 'SimpleSAMLAuthToken');
            $cookieNames = array($sessionCookie, $authTokenCookie);
        } catch (\Throwable $e) {
            $cookieNames = array('SimpleSAMLAuthToken');
        }
    }
}

foreach ($cookieNames as $cookieName) {
    if (!is_string($cookieName) || $cookieName === '') {
        continue;
    }
    setcookie($cookieName, '', time() - 3600, '/', '', false, true);
}

$httpUtils = new Utils\HTTP();
$returnTo = $httpUtils->checkURLAllowed($returnTo);
$httpUtils->redirectTrustedURL($returnTo);
