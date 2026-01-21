<?php
/**
 * SimpleTOTP Authentication Processing filter
 *
 * SimpleTOTP is a SimpleSAMLphp auth processing filter that enables the use
 *  of the Time-Based One-Time Password Algorithm (TOTP) as a second-factor (aka multi-factor)
 *  authentication mechanism on either an Identity Provider or Service Provider
 *  (...or both!).
 *
 *
 * @package simpleSAMLphp
 */

declare(strict_types=1);

namespace SimpleSAML\Module\simpletotp\Auth\Process;
use SimpleSAML\Auth;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\Logger;
use SimpleSAML\Error\Exception;
use SimpleSAML\Session;

class Mfa extends Auth\ProcessingFilter {
    /**
     * Attribute that stores the TOTP secret
     */
    private $secret_attr = 'totp_secret';

    /**
     * Value of the TOTP secret
     */
    private $secret_val = NULL;

    /**
     * Whether or not the user should be forced to use MFA.
     *  If false, a user that does not have a TOTP secret will be able to continue
     *   authentication
     */
    private $enforce_mfa = false;

    /**
     * If true, treat empty or null secrets as "not configured" and allow auth to continue.
     */
    private $allow_empty_secret = false;

    /**
     * Maximum allowed TOTP attempts within a time window.
     */
    private $max_attempts = 5;

    /**
     * Time window in seconds for TOTP attempt limiting.
     */
    private $attempt_window = 300;

    /**
     * External URL to redirect user to if $enforce_mfa is true and they do not
     *  have a TOTP attribute set.  If this attribute is NULL, the user will
     *  be redirect to the internal error page.
     */
    private $not_configured_url = NULL;

    /**
     * Timeout (in minutes) for a validated TOTP value.  If a user is authenticating again, 
     *  and the time difference is less than this validation, they won't be asked for a TOTP value.
     *  Defaults to 60 minutes.
     */
    private $validation_timeout = 60;

    /**
     * Allowed time-step window (in 30s steps) for TOTP verification.
     * Defaults to 0 (no drift allowed).
     */
    private $totp_window = 0;

    /**
     * Storage for TOTP rate limiting (session, store, or both).
     */
    private $totp_rate_limit_storage = 'session';

    /**
     * Key source for TOTP rate limiting (secret, uid, ip, or attr:<name>).
     */
    private $totp_rate_limit_key = 'uid';

    /**
     * Whether to show the restart button on MFA pages.
     */
    private $restart_enabled = false;

    /**
     * Cookie names to clear when restarting the flow.
     */
    private $clear_cookies = array('SimpleSAMLAuthToken');
    /**
     * Initialize the filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use
     */
    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('enforce_mfa', $config)) {
            $this->enforce_mfa = $config['enforce_mfa'];
            if (!is_bool($this->enforce_mfa)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: enforce_mfa must be a boolean.');
            }
        }

        if (array_key_exists('allow_empty_secret', $config)) {
            $this->allow_empty_secret = $config['allow_empty_secret'];
            if (!is_bool($this->allow_empty_secret)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: allow_empty_secret must be a boolean.');
            }
        }

        if (array_key_exists('max_attempts', $config)) {
            $this->max_attempts = $config['max_attempts'];
            if (!is_int($this->max_attempts) || $this->max_attempts < 1) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: max_attempts must be a positive integer.');
            }
        }

        if (array_key_exists('attempt_window', $config)) {
            $this->attempt_window = $config['attempt_window'];
            if (!is_int($this->attempt_window) || $this->attempt_window < 1) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: attempt_window must be a positive integer.');
            }
        }

        if (array_key_exists('secret_attr', $config)) {
            $this->secret_attr = $config['secret_attr'];
            if (!is_string($this->secret_attr)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: secret_attr must be a string');
            }
        }

        if (array_key_exists('not_configured_url', $config)) {
            $this->not_configured_url = $config['not_configured_url'];
            if ($config['not_configured_url'] !== NULL && !is_string($config['not_configured_url'])) {
                throw new Exception('Invalid attribute value given to simpletotp::mfa filter: not_configured_url must be a string');
            }

            //validate URL to ensure it's we will be able to redirect to
            $httpUtils = new Utils\HTTP();
            if (is_string($config['not_configured_url'])) {
                $this->not_configured_url =
                    $httpUtils->checkURLAllowed($config['not_configured_url']);
            } else {
                $this->not_configured_url = NULL;
            }
        }

        if (array_key_exists('validation_timeout', $config)) {
            $this->validation_timeout = $config['validation_timeout'];
            if (!is_int($this->validation_timeout)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: validation_timeout must be an integer');
            }
        }

        if (array_key_exists('totp_window', $config)) {
            $this->totp_window = $config['totp_window'];
            if (!is_int($this->totp_window) || $this->totp_window < 0) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: totp_window must be a non-negative integer');
            }
        }

        if (array_key_exists('totp_rate_limit_storage', $config)) {
            $this->totp_rate_limit_storage = $config['totp_rate_limit_storage'];
            $allowed = array('session', 'store', 'both');
            if (!is_string($this->totp_rate_limit_storage) || !in_array($this->totp_rate_limit_storage, $allowed, true)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: totp_rate_limit_storage must be session, store, or both.');
            }
        }

        if (array_key_exists('totp_rate_limit_key', $config)) {
            $this->totp_rate_limit_key = $config['totp_rate_limit_key'];
            if (!is_string($this->totp_rate_limit_key) || $this->totp_rate_limit_key === '') {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: totp_rate_limit_key must be a non-empty string.');
            }
        }

        $restartKey = null;
        if (array_key_exists('restart_enabled', $config)) {
            $restartKey = 'restart_enabled';
        } elseif (array_key_exists('simpletotp.restart_enabled', $config)) {
            $restartKey = 'simpletotp.restart_enabled';
        }
        if ($restartKey !== null) {
            $this->restart_enabled = $config[$restartKey];
            if (!is_bool($this->restart_enabled)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: restart_enabled must be a boolean.');
            }
        }

        $clearKey = null;
        if (array_key_exists('clear_cookies', $config)) {
            $clearKey = 'clear_cookies';
        } elseif (array_key_exists('simpletotp.clear_cookies', $config)) {
            $clearKey = 'simpletotp.clear_cookies';
        }
        if ($clearKey !== null) {
            $this->clear_cookies = $config[$clearKey];
            if (!is_array($this->clear_cookies)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: clear_cookies must be an array.');
            }
            foreach ($this->clear_cookies as $cookieName) {
                if (!is_string($cookieName) || $cookieName === '') {
                    throw new Exception('Invalid attribute name given to simpletotp::mfa filter: clear_cookies must contain non-empty strings.');
                }
            }
        }
    }

    /**
     * Apply SimpleTOTP MFA filter
     *
     * @param array &$state  The current state
     */
    public function process(&$state): void {
        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        $attributes =& $state['Attributes'];

        // check for secret_attr coming from user store and make sure it is not empty
        $secret_is_empty = false;
        if (array_key_exists($this->secret_attr, $attributes) && !empty($attributes[$this->secret_attr])) {
            $this->secret_val = $attributes[$this->secret_attr][0];
            if (is_string($this->secret_val) && trim($this->secret_val) === '') {
                $secret_is_empty = true;
                $this->secret_val = NULL;
            }
        }

        if ($secret_is_empty && $this->allow_empty_secret === true) {
            Logger::debug('User has empty MFA secret and allow_empty_secret is enabled. Continue.');
            return;
        }

        if ($this->secret_val === NULL && $this->enforce_mfa === true) {
            # MFA is enforced and user does not have it configured..
            Logger::debug('User with ID "' . $attributes['uid'][0] . '" does not have MFA configured when it is mandatory for an idP or a SP');

            //send user to custom error page if configured
            if ($this->not_configured_url !== NULL) {
                $httpUtils = new Utils\HTTP();
                $httpUtils->redirectUntrustedURL($this->not_configured_url);
            } else {
                $httpUtils = new Utils\HTTP();
                $httpUtils->redirectTrustedURL(Module::getModuleURL('simpletotp/not_configured.php'));
            }

        } elseif ($this->secret_val === NULL && $this->enforce_mfa === false) {
            Logger::debug('User with ID "' . $attributes['uid'][0] . '" does not have 2f configured but SP does not require it. Continue.');
            return;
        }

        //as the attribute is configurable, we need to store it in a consistent location
        $state['mfa_secret'] = $this->secret_val;
        $state['mfa_totp_window'] = $this->totp_window;
        $state['mfa_max_attempts'] = $this->max_attempts;
        $state['mfa_attempt_window'] = $this->attempt_window;
        $state['simpletotp_rate_limit_storage'] = $this->totp_rate_limit_storage;
        $state['simpletotp_rate_limit_key'] = $this->totp_rate_limit_key;
        $state['simpletotp_restart_enabled'] = $this->restart_enabled;
        $state['simpletotp_clear_cookies'] = $this->clear_cookies;

        //this means we have secret_val configured for this session, time to MFA
        $now = time();

        // check to see if MFA has been verified in the last hour
        $session = Session::getSessionFromRequest();
        $alldata = $session->getDataOfType('\SimpleSAML\Module\simpletotp');
        Logger::debug('MFA: alldata ' . implode(',', array_keys($alldata)));
        if ( array_key_exists('lastverified', $alldata) ) {
            Logger::debug('MFA: alldata lastverified ' . $alldata['lastverified']);
        }
        $lastverified = $session->getData('\SimpleSAML\Module\simpletotp', 'lastverified');
        Logger::debug('MFA: last verified ' . $lastverified);
        Logger::debug('MFA: time ' . $now);

		// validation_timeout is in minutes - needs to be converted to seconds
        if ( ($lastverified === NULL) || (($now - $lastverified) > (60 * $this->validation_timeout)) ){
            if ( $lastverified === NULL ) {
                $reason = 'new session';
            } else {
                $reason = ($now - $lastverified) . 's ago';
            }
            Logger::info('MFA: verification required.  New session or last verified more than an hour ago - ' . $reason);
        } else {
            // nothing more to do here
            Logger::info('MFA: already verified in the last hour - ' . ($now - $lastverified) . 's ago');
            return;
        }

        $id  = Auth\State::saveState($state, 'simpletotp:request');
        $url = Module::getModuleURL('simpletotp/authenticate.php');
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, array('StateId' => $id));

        return;
    }
}
