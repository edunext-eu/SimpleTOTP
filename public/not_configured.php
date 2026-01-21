<?php

use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

$globalConfig = Configuration::getInstance();
$t = new Template($globalConfig, 'simpletotp:not_configured.twig');
$restartEnabled = false;
if (method_exists($globalConfig, 'getOptionalValue')) {
    $restartEnabled = (bool) $globalConfig->getOptionalValue('simpletotp.restart_enabled', false);
} else {
    try {
        $restartEnabled = (bool) $globalConfig->getValue('simpletotp.restart_enabled', false);
    } catch (\Throwable $e) {
        $restartEnabled = false;
    }
}
if ($restartEnabled) {
    $t->data['restartUrl'] = Module::getModuleURL('simpletotp/restart.php');
    $t->data['restartReturnTo'] = Module::getModuleURL('simpletotp/not_configured.php');
    $restartCookies = null;
    if (method_exists($globalConfig, 'getOptionalValue')) {
        $value = $globalConfig->getOptionalValue('simpletotp.clear_cookies', array('SimpleSAMLAuthToken'));
        $restartCookies = is_array($value) ? $value : array('SimpleSAMLAuthToken');
    } else {
        try {
            $value = $globalConfig->getValue('simpletotp.clear_cookies', array('SimpleSAMLAuthToken'));
            $restartCookies = is_array($value) ? $value : array('SimpleSAMLAuthToken');
        } catch (\Throwable $e) {
            $restartCookies = array('SimpleSAMLAuthToken');
        }
    }
    $t->data['restartCookies'] = $restartCookies;
}
echo $t->getContents();
