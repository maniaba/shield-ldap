<?php

declare(strict_types=1);

/**
 * This file is part of Shield LDAP.
 *
 * Copyright (c) 2026 maniaba
 * SPDX-License-Identifier: MIT
 *
 * See the LICENSE file for the full copyright and license information.
 */

namespace Maniaba\ShieldLDAP\Authentication\LDAP;

use LDAP\Connection;
use Maniaba\ShieldLDAP\Tests\Support\LDAP\NativeLDAPStub;
use ReflectionClass;
use stdClass;

// Keep these shadow functions in an include used only by the isolated transport tests.
if (! \extension_loaded('ldap')) {
    class_alias(NativeLDAPStub::class, Connection::class);

    foreach ([
        'LDAP_OPT_NETWORK_TIMEOUT'    => 20_485,
        'LDAP_OPT_TIMEOUT'            => 20_482,
        'LDAP_OPT_X_TLS_REQUIRE_CERT' => 24_582,
        'LDAP_OPT_X_TLS_DEMAND'       => 2,
        'LDAP_OPT_X_TLS_HARD'         => 1,
        'LDAP_OPT_X_TLS_NEVER'        => 0,
        'LDAP_OPT_PROTOCOL_VERSION'   => 17,
        'LDAP_OPT_REFERRALS'          => 8,
        'LDAP_OPT_DEREF'              => 2,
        'LDAP_DEREF_NEVER'            => 0,
        'LDAP_OPT_DIAGNOSTIC_MESSAGE' => 50,
    ] as $option => $value) {
        define($option, $value);
    }
}

function extension_loaded(string $extension): bool
{
    return $extension === 'ldap' ? NativeLDAPStub::$available : \extension_loaded($extension);
}

function function_exists(string $function): bool
{
    return $function === 'ldap_start_tls' || \function_exists($function);
}

function ldap_connect(string $uri): Connection|false
{
    NativeLDAPStub::$connected[] = $uri;

    // The native constructor creates a handle without connecting to the URI.
    return \extension_loaded('ldap')
        ? \ldap_connect($uri)
        : (new ReflectionClass(Connection::class))->newInstance();
}

function ldap_get_option(Connection $connection, int $option, int|string|null &$value): bool
{
    $value = match ($option) {
        LDAP_OPT_X_TLS_REQUIRE_CERT => LDAP_OPT_X_TLS_DEMAND,
        LDAP_OPT_DIAGNOSTIC_MESSAGE => NativeLDAPStub::$diagnostic,
        default                     => null,
    };

    return $value !== null;
}

function ldap_set_option(Connection $connection, int $option, bool|int $value): bool
{
    return $option !== LDAP_OPT_X_TLS_REQUIRE_CERT || NativeLDAPStub::$certificateOptionSucceeds;
}

function ldap_start_tls(Connection $connection): bool
{
    NativeLDAPStub::$tlsStarts++;

    return true;
}

function ldap_bind(Connection $connection, string $dn, string $password): bool
{
    NativeLDAPStub::$operations[] = ['bind', $dn];

    $uri                       = NativeLDAPStub::$connected[array_key_last(NativeLDAPStub::$connected)];
    NativeLDAPStub::$lastError = NativeLDAPStub::$bindErrors[$uri] ?? 0;

    if (NativeLDAPStub::$lastError !== 0 && NativeLDAPStub::$warnOnBindFailure) {
        trigger_error('Untrusted LDAP bind diagnostic', E_USER_WARNING);
    }

    return NativeLDAPStub::$lastError === 0;
}

function ldap_unbind(Connection $connection): bool
{
    NativeLDAPStub::$unbound++;

    return true;
}

function ldap_errno(Connection $connection): int
{
    return NativeLDAPStub::$lastError;
}

/**
 * @param list<string> $attributes
 */
function ldap_search(Connection $connection, string $base, string $filter, array $attributes, int $attributesOnly, int $sizeLimit, int $timeLimit): false|stdClass
{
    NativeLDAPStub::$operations[] = ['search', $base];

    return scriptedSearch($base, $filter, $attributes);
}

/**
 * @param list<string> $attributes
 */
function ldap_read(Connection $connection, string $base, string $filter, array $attributes, int $attributesOnly, int $sizeLimit, int $timeLimit): false|stdClass
{
    NativeLDAPStub::$operations[] = ['read', $base];

    return scriptedSearch($base, $filter, $attributes);
}

/**
 * @param list<string> $attributes
 */
function scriptedSearch(string $base, string $filter, array $attributes): false|stdClass
{
    NativeLDAPStub::$queries[] = ['filter' => $filter, 'attributes' => $attributes];

    $code                      = NativeLDAPStub::$searchCodesByBase[$base] ?? NativeLDAPStub::$searchCode;
    NativeLDAPStub::$lastError = $code;

    return NativeLDAPStub::$searchFails ? false : (object) [
        'code'    => $code,
        'entries' => NativeLDAPStub::$entriesByBase[$base] ?? NativeLDAPStub::$entries,
    ];
}

function ldap_parse_result(Connection $connection, stdClass $result, ?int &$code): bool
{
    $code = $result->code;

    return true;
}

function ldap_first_reference(Connection $connection, stdClass $result): false|stdClass
{
    return NativeLDAPStub::$hasReference ? new stdClass() : false;
}

function ldap_count_entries(Connection $connection, stdClass $result): int
{
    return count($result->entries);
}

function ldap_first_entry(Connection $connection, stdClass $result): array|false
{
    return $result->entries === [] ? false : ['entries' => $result->entries, 'offset' => 0];
}

function ldap_next_entry(Connection $connection, array $entry): array|false
{
    $entry['offset']++;

    return isset($entry['entries'][$entry['offset']]) ? $entry : false;
}

function ldap_get_dn(Connection $connection, array $entry): string
{
    return $entry['entries'][$entry['offset']];
}

function ldap_get_values_len(Connection $connection, array $entry, string $attribute): array|false
{
    $dn     = $entry['entries'][$entry['offset']];
    $values = NativeLDAPStub::$attributesByDn[$dn][strtolower($attribute)] ?? null;

    return $values === null ? false : $values + ['count' => count($values)];
}
