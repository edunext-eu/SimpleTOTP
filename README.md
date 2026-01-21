SimpleTOTP
==========
A SimpleSAMLphp auth processing filter that adds TOTP-based MFA on an IdP or SP.
Recommended placement is the IdP to keep TOTP secrets off SPs.
Only HMAC-SHA1 TOTP is supported for maximum compatibility with authenticator apps.

Key features
------------
- Works as an authproc filter (IdP or SP).
- Configurable secret attribute and validation timeout.
- Optional clock-drift window for TOTP verification.
- Basic per-session brute-force throttling.
- Optional bypass when secret is an empty string.

Installation
------------
### Via Git
Clone into the SimpleSAMLphp `modules/` directory.

### Via Composer
Install the module from Packagist:
```bash
composer require edunext-eu/simplesamlphp-module-simpletotp
```

Quick start (IdP recommended)
-----------------------------
Add to `authproc.idp` in `config.php` or IdP metadata:
```php
10 => array(
	'class' => 'simpletotp:mfa',
	'secret_attr' => 'totp_secret', // default
	'enforce_mfa' => false, // default
	'allow_empty_secret' => false, // default
	'not_configured_url' => NULL, // default
	'validation_timeout' => 60, // default (minutes)
	'totp_window' => 0, // default (30s steps)
	// Show a "start over" option in TOTP page (UX)
	'restart_enabled' => false, // default
	'clear_cookies' => [], // empty = use SimpleSAMLphp cookie names
	'max_attempts' => 5, // default
	'attempt_window' => 300, // default (seconds)
	// Optional hardening (requires Store configuration for 'store' or 'both')
	'totp_rate_limit_storage' => 'session', // session|store|both
	'totp_rate_limit_key' => 'uid', // uid|secret|ip|attr:<name>
),
```

Recommended hardening (read the Configuration notes below before enabling):
```php
10 => array(
	'class' => 'simpletotp:mfa',
	'totp_rate_limit_storage' => 'store',
	'totp_rate_limit_key' => 'uid',
	'restart_enabled' => true,
),
```

Remove the secret from outbound attributes (use a high priority like 98 if 99 is already taken):
```php
98 => array(
	'class' => 'core:AttributeAlter',
	'subject' => 'totp_secret',
	'pattern' => '/.*/',
	'%remove',
),
```

Module enablement
-----------------
Enable the module via `config.php` by setting:
```php
'module.enable' => [
	'simpletotp' => true,
],
```
This is preferred over the legacy `modules/<name>/enable` file because it is explicit
and visible in configuration management.

SP-side example (not recommended)
---------------------------------
Running on the SP requires sending the TOTP secret to the SP. This is not
recommended and not tested in this fork:
```php
10 => array(
	'class' => 'simpletotp:mfa',
	'secret_attr' => 'totp_secret',
),
```

Configuration notes
-------------------
- secret_attr: defaults to `totp_secret`. If your attributes use a different name (e.g. `ga_secret`), set it explicitly.
- enforce_mfa: when true, users without a configured secret are blocked (or redirected to `not_configured_url`).
- allow_empty_secret: when true, an empty-string secret is treated as "not configured" and the user is allowed to continue.
- Interaction: `allow_empty_secret` only applies when the secret attribute exists but is an empty string. It does not override `enforce_mfa` for truly missing secrets.
- Null vs empty: "missing" means the attribute is absent or null, while "empty" means the attribute exists but the value is an empty string. This lets you use empty strings as an explicit "MFA disabled" flag.
- Recommended for DB-backed secrets: if your DB uses empty strings (e.g., `two_factor_secret = ''`) for "no MFA", set `allow_empty_secret = true` and keep `enforce_mfa = false`. For strict MFA, set `enforce_mfa = true` and require non-empty secrets.
- validation_timeout: minutes to cache a successful MFA before re-prompting.
- totp_window: number of 30-second steps to accept before/after the current step.
  - 0 = only the current 30s step (strict, most secure)
  - 1 = accept codes from 30s before or after (90s total window)
  - 2 = accept codes from 60s before or after (150s total window)
- max_attempts / attempt_window: throttles brute-force attempts.
- Form fields: new integrations should post `totp` with `autocomplete="one-time-code"`; `code` is accepted for legacy forms.
- Start over button (UX): set `simpletotp.restart_enabled = true` and (optionally) `simpletotp.clear_cookies` to clear session cookies and reload the current page for a fresh login. These options can live in global `config.php` or inside the `simpletotp:mfa` authproc configuration.
  - If `simpletotp.clear_cookies` is omitted or empty, the module uses `session.cookie.name` and `session.authtoken.cookiename` from `config.php`.
- TOTP rate limit storage: defaults to session-only. To make rate limiting robust across sessions/servers, set `totp_rate_limit_storage` to `store` (or `both`) in the `simpletotp:mfa` config and ensure `store.type` is configured (redis/memcache/sql). Use `totp_rate_limit_key` to choose the key source (`secret`, `uid`, `ip`, or `attr:<name>`). The default key is `uid`.
  - If the configured key is missing at runtime, the limiter falls back to the TOTP secret and logs a warning.
  - `totp_rate_limit_key` uses built-in types (`uid`, `secret`, `ip`) or `attr:<name>` to refer to a specific attribute (e.g. `attr:mail`, `attr:eduPersonPrincipalName`). The attribute must exist in the user attributes for your IdP/SP, otherwise it falls back to the secret.
  - For federations that standardize identifiers (e.g. `eduPersonPrincipalName`, `eduPersonUniqueID`, `subject-id`, `pairwise-id`), prefer one of those stable identifiers via `attr:<name>`.
  - If `store.type` is not configured, SimpleSAMLphp falls back to `phpsession`, which is not shared across servers and can be reset by clearing cookies.
  - If `store.type` is set to an unavailable backend, store-based rate limiting falls back to session-only with a warning.
  - TOTP codes are fixed at 6 digits.
  - `clear_cookies` only uses admin-configured cookie names; it is not accepted from user input.
  - Cookie clearing only affects the current host; it does not clear cookies set on other subdomains or parent domains.

Security notes
--------------
- TOTP secrets should remain on the IdP. Remove them from outbound attributes.
- Keep totp_window small (default 0) to reduce acceptance of old codes.
- Basic brute-force throttling built in.
- Verification uses a timing-safe comparison and stricter base32 validation (backported from https://github.com/poetter-sebastian/SimpleThenticator/tree/main).

Translations
------------
All user-facing strings are translatable via gettext. Add or edit translations in
`locales/<lang>/LC_MESSAGES/simpletotp.po` (e.g. `locales/it/LC_MESSAGES/simpletotp.po` or
`locales/es/LC_MESSAGES/simpletotp.po`). SimpleSAMLphp selects the language based on the
user's locale settings.
Translations are best-effort and may need review by native speakers; some locales may still use English strings. Pull requests or issues to refine wording are welcome.

Fork notice
-----------
This repository is maintained at https://github.com/edunext-eu/SimpleTOTP and is a fork
of the original module. If you are upgrading from the original, update your Composer
package name to `edunext-eu/simplesamlphp-module-simpletotp`.

Changes in this fork
--------------------
- Fixed MFA bypass by setting lastverified only on successful TOTP verification.
- Updated BadRequest class for newer SimpleSAMLphp.
- Added empty-code validation and removed sensitive debug logging.
- Added totp_window for clock drift tolerance.
- Added rate limiting for TOTP attempts.
- Removed the legacy token generator endpoint.
- Tightened StateId handling to accept only GET/POST (no generic $_REQUEST).
- Added timing-safe code comparison and stricter base32 validation.
- Added translations and documentation improvements.
- Removed the legacy `default-enable` file; use `module.enable` in config.php instead.

Maintenance
-----------
Long-term maintenance for this module is not guaranteed. If you want to take stewardship, open an issue.

Disclaimer
----------
This software is provided "as is" without warranty of any kind; use at your own risk.
