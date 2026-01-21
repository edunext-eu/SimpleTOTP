<?php
/**
 * Google Authentication functions below taken from
 * https://github.com/PHPGangsta/GoogleAuthenticator
 * security fixes backported from fork https://github.com/poetter-sebastian/SimpleThenticator
 * Copyright (c) 2012, Michael Kliewe All rights reserved.
 */

function getCode($secret, $timeSlice = null) {
    if ($timeSlice === null) {
        $timeSlice = floor(time() / 30);
    }
    $secretkey = _base32Decode($secret);
    // Reject invalid base32 secrets instead of generating a mismatched code.
    if ($secretkey === false) {
        return false;
    }
    // Pack time into binary string
    $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
    // Hash it with users secret key
    $hm = hash_hmac('SHA1', $time, $secretkey, true);
    // Use last nipple of result as index/offset
    $offset = ord(substr($hm, -1)) & 0x0F;
    // grab 4 bytes of the result
    $hashpart = substr($hm, $offset, 4);
    // Unpak binary value
    $value = unpack('N', $hashpart);
    $value = $value[1];
    // Only 32 bits
    $value = $value & 0x7FFFFFFF;
    $modulo = pow(10, 6);
    return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
}

function verifyCode($secret, $code, $window = 0, $timeSlice = null) {
    if ($timeSlice === null) {
        $timeSlice = floor(time() / 30);
    }
    $window = (int) $window;
    if ($window < 0) {
        $window = 0;
    }
    for ($i = -$window; $i <= $window; $i++) {
        $computed = getCode($secret, $timeSlice + $i);
        if ($computed !== false && timingSafeEquals($computed, $code)) {
            return true;
        }
    }
    return false;
}

function _base32Decode($secret) {
    if (empty($secret)) return '';
    $base32chars = _getBase32LookupTable();
    $base32charsFlipped = array_flip($base32chars);

    foreach (str_split($secret) as $char) {
        if (!isset($base32charsFlipped[$char])) return false;
    }

    $paddingCharCount = substr_count($secret, $base32chars[32]);
    $allowedValues = array(6, 4, 3, 1, 0);
    if (!in_array($paddingCharCount, $allowedValues)) return false;
    for ($i = 0; $i < 4; $i++){
        if ($paddingCharCount == $allowedValues[$i] &&
            substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) return false;
    }
    $secret = str_replace('=','', $secret);
    $secret = str_split($secret);
    $binaryString = "";
    for ($i = 0; $i < count($secret); $i = $i+8) {
        $x = "";
        if (!in_array($secret[$i], $base32chars)) return false;
        for ($j = 0; $j < 8; $j++) {
            $value = $base32charsFlipped[$secret[$i + $j]] ?? null;
            if ($value === null) return false;
            $x .= str_pad(base_convert($value, 10, 2), 5, '0', STR_PAD_LEFT);
        }
        $eightBits = str_split($x, 8);
        for ($z = 0; $z < count($eightBits); $z++) {
            $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y:"";
        }
    }
    return $binaryString;
}

function _getBase32LookupTable()
{
    return array(
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        '='  // padding char
    );
}

function timingSafeEquals($safeString, $userString) {
    if (function_exists('hash_equals')) {
        return hash_equals($safeString, $userString);
    }
    $safeLen = strlen($safeString);
    $userLen = strlen($userString);
    if ($userLen !== $safeLen) return false;
    $result = 0;
    for ($i = 0; $i < $userLen; $i++) {
        $result |= (ord($safeString[$i]) ^ ord($userString[$i]));
    }
    return $result === 0;
}
