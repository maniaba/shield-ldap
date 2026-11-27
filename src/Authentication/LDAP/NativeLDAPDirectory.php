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
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use SensitiveParameter;

/**
 * Implements directory operations with PHP's LDAP extension over TLS.
 *
 * @phpstan-type DirectoryEntry array{dn: string, attributes: array<string, list<string>>}
 */
final class NativeLDAPDirectory implements MultiBaseLDAPDirectoryInterface, LDAPUserLookupInterface
{
    private const TIME_LIMIT_EXCEEDED = 3;
    private const SIZE_LIMIT_EXCEEDED = 4;
    private const REFERRAL            = 10;
    private const ADMIN_LIMIT         = 11;
    private const NO_SUCH_OBJECT      = 32;
    private const INVALID_CREDENTIALS = 49;
    private const UNAVAILABLE         = 52;

    // OpenLDAP client-side result codes are not exposed by ext-ldap.
    private const SERVER_DOWN   = -1;
    private const TIMEOUT       = -5;
    private const FILTER_ERROR  = -7;
    private const CONNECT_ERROR = -11;

    /**
     * {@inheritDoc}
     *
     * For LDAPS, an anonymous Root DSE lookup triggers the TLS handshake.
     */
    public function testConnection(LDAPConnection $connection): void
    {
        $ldap = $this->open($connection, false);
        ldap_unbind($ldap);
    }

    /**
     * {@inheritDoc}
     */
    public function testBind(LDAPConnection $connection): void
    {
        $ldap = $this->open($connection, true);
        ldap_unbind($ldap);
    }

    /**
     * {@inheritDoc}
     *
     * Rechecks the immutable identity on the same endpoint after the user bind.
     */
    public function authenticate(
        LDAPConnection $connection,
        array|string $baseDn,
        string $filter,
        array $attributes,
        #[SensitiveParameter]
        string $password,
        string $eligibilityFilter = '(objectClass=*)',
    ): array {
        if ($password === '' || str_contains($password, "\0")) {
            throw new LDAPException('invalid_credentials');
        }

        $attributes[] = $connection->externalIdAttribute;
        $this->validateSearch($baseDn, $filter, $attributes);
        LDAPFilter::validate($eligibilityFilter);

        $ldap = $this->open($connection, true);

        try {
            $entry       = $this->findExactlyOne($ldap, $connection, $baseDn, $filter, $attributes);
            $eligibility = $this->eligibleEntryFilter($connection, $entry, $filter, $eligibilityFilter);

            // Keep all three binds on the selected endpoint, including behind load balancers.
            // Any failure terminates this connection in the finally block.
            $this->bind($ldap, $entry['dn'], $password, false);
            $this->bind($ldap, $connection->bindDn, $connection->bindPassword(), true);

            return $this->readEligibleEntry($ldap, $connection, $entry, $eligibility, $attributes);
        } finally {
            ldap_unbind($ldap);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function lookupUser(
        LDAPConnection $connection,
        array|string $baseDn,
        string $filter,
        string $eligibilityFilter = '(objectClass=*)',
    ): array {
        if (! $connection->verifyCertificate) {
            throw new LDAPException('tls_verification_required');
        }

        $attributes = [$connection->externalIdAttribute];
        $this->validateSearch($baseDn, $filter, $attributes);
        LDAPFilter::validate($eligibilityFilter);

        $ldap = $this->open($connection, true);

        try {
            $entry       = $this->findExactlyOne($ldap, $connection, $baseDn, $filter, $attributes);
            $eligibility = $this->eligibleEntryFilter($connection, $entry, $filter, $eligibilityFilter);

            return $this->readEligibleEntry($ldap, $connection, $entry, $eligibility, $attributes);
        } finally {
            ldap_unbind($ldap);
        }
    }

    /**
     * {@inheritDoc}
     *
     * Accepts a limit of one to 100 entries.
     */
    public function preview(
        LDAPConnection $connection,
        string $baseDn,
        string $filter,
        array $attributes,
        int $limit = 20,
    ): array {
        if ($limit < 1 || $limit > 100) {
            throw new LDAPException('invalid_search_limit');
        }

        $this->validateSearch($baseDn, $filter, $attributes);
        $ldap = $this->open($connection, true);

        try {
            return $this->search($ldap, $connection, $baseDn, $filter, $attributes, $limit);
        } finally {
            ldap_unbind($ldap);
        }
    }

    /**
     * Use the OpenLDAP client's process-level TLS policy. Changing CA options at
     * runtime can leave an older PHP build using a previously initialized context.
     */
    private function open(LDAPConnection $connection, bool $serviceBind): Connection
    {
        if (! extension_loaded('ldap')) {
            throw new LDAPException('extension_unavailable');
        }

        if (! defined('LDAP_OPT_NETWORK_TIMEOUT') || ! defined('LDAP_OPT_TIMEOUT')
                                                  || ! defined('LDAP_OPT_X_TLS_REQUIRE_CERT') || ! defined('LDAP_OPT_X_TLS_DEMAND')
                                                  || ! defined('LDAP_OPT_X_TLS_HARD') || ! function_exists('ldap_start_tls')
        ) {
            throw new LDAPException('unsupported_ldap_client');
        }

        $failure = new LDAPException('directory_unavailable');

        foreach ($connection->hosts as $host) {
            $ldap = @ldap_connect($connection->endpoint($host));

            if ($ldap === false) {
                throw new LDAPException('tls_context_failed');
            }

            try {
                $this->configure($ldap, $connection);

                if ($connection->encryption === 'starttls' && ! @ldap_start_tls($ldap)) {
                    throw new LDAPException($this->transportFailure($ldap, ldap_errno($ldap)) ?? 'tls_failed');
                }

                if ($serviceBind) {
                    $this->bind($ldap, $connection->bindDn, $connection->bindPassword(), true);
                } elseif ($connection->encryption === 'ldaps') {
                    // ldap_connect() does not perform I/O. Query the Root DSE without credentials.
                    $this->search($ldap, $connection, '', '(objectClass=*)', [], 1, true);
                }

                return $ldap;
            } catch (LDAPException $exception) {
                ldap_unbind($ldap);

                if (! in_array($exception->reason, ['directory_unavailable', 'connection_timeout', 'search_timeout'], true)) {
                    throw $exception;
                }

                $failure = $exception;
            }
        }

        throw $failure;
    }

    private function configure(Connection $ldap, LDAPConnection $connection): void
    {
        $this->configureCertificateVerification($ldap, $connection);

        if (! ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3)
            || ! ldap_set_option($ldap, LDAP_OPT_REFERRALS, false)
            || ! ldap_set_option($ldap, LDAP_OPT_DEREF, LDAP_DEREF_NEVER)
            || ! ldap_set_option($ldap, LDAP_OPT_NETWORK_TIMEOUT, $connection->connectTimeout)
            || ! ldap_set_option($ldap, LDAP_OPT_TIMEOUT, $connection->searchTimeout)
        ) {
            throw new LDAPException('connection_configuration_failed');
        }
    }

    private function configureCertificateVerification(Connection $ldap, LDAPConnection $connection): void
    {
        if ($connection->verifyCertificate) {
            if (! ldap_get_option($ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, $requireCert)
                || ! in_array($requireCert, [LDAP_OPT_X_TLS_DEMAND, LDAP_OPT_X_TLS_HARD], true)
            ) {
                throw new LDAPException('tls_verification_required');
            }

            return;
        }

        // Supported ext-ldap releases rebuild the TLS context per handle for StartTLS.
        // LDAPS uses a process-wide context and cannot safely apply this override.
        if ($connection->encryption !== 'starttls' || ! defined('LDAP_OPT_X_TLS_NEVER')
                                                   || PHP_VERSION_ID < 80322 || (PHP_VERSION_ID >= 80400 && PHP_VERSION_ID < 80408)
        ) {
            throw new LDAPException('tls_verification_override_unsupported');
        }

        if (! @ldap_set_option($ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER)) {
            throw new LDAPException('tls_context_failed');
        }
    }

    private function bind(Connection $ldap, string $dn, #[SensitiveParameter] string $password, bool $serviceAccount): void
    {
        // ext-ldap emits native warnings for rejected binds. Classify the result
        // by LDAP error code so directory diagnostics stay out of PHP error output.
        if (@ldap_bind($ldap, $dn, $password)) {
            return;
        }

        $code = ldap_errno($ldap);

        throw new LDAPException($this->transportFailure($ldap, $code)
            ?? (! $serviceAccount && $code === self::INVALID_CREDENTIALS
                ? 'invalid_credentials'
                : ($serviceAccount ? 'service_bind_failed' : 'user_bind_failed')));
    }

    /**
     * @param DirectoryEntry $entry
     */
    private function eligibleEntryFilter(LDAPConnection $connection, array $entry, string $filter, string $eligibilityFilter): string
    {
        $ids = $entry['attributes'][strtolower($connection->externalIdAttribute)] ?? [];

        if (count($ids) !== 1 || $ids[0] === '') {
            throw new LDAPException('invalid_external_identity');
        }

        return LDAPFilter::all($filter, $eligibilityFilter, LDAPFilter::equal($connection->externalIdAttribute, $ids[0]));
    }

    /**
     * @param DirectoryEntry $entry
     * @param list<string>   $attributes
     *
     * @return DirectoryEntry
     */
    private function readEligibleEntry(Connection $ldap, LDAPConnection $connection, array $entry, string $filter, array $attributes): array
    {
        $idAttribute = strtolower($connection->externalIdAttribute);
        $verified    = $this->findExactlyOne($ldap, $connection, $entry['dn'], $filter, $attributes, true);

        if (($verified['attributes'][$idAttribute] ?? []) !== $entry['attributes'][$idAttribute]) {
            throw new LDAPException('directory_identity_changed');
        }

        return $verified;
    }

    /**
     * @param list<string>|string $baseDn
     * @param list<string>        $attributes
     *
     * @return DirectoryEntry
     */
    private function findExactlyOne(
        Connection $ldap,
        LDAPConnection $connection,
        array|string $baseDn,
        string $filter,
        array $attributes,
        bool $baseOnly = false,
    ): array {
        $match       = null;
        $idAttribute = strtolower($connection->externalIdAttribute);

        foreach ((array) $baseDn as $base) {
            $entries = $this->search($ldap, $connection, $base, $filter, $attributes, 2, $baseOnly);

            if ($entries === []) {
                continue;
            }

            $entry = $entries[0];

            if (count($entries) > 1 || ($match !== null && (
                $match['dn'] !== $entry['dn']
                || ($match['attributes'][$idAttribute] ?? []) !== ($entry['attributes'][$idAttribute] ?? [])
            ))) {
                throw new LDAPException('ambiguous_user');
            }

            $match = $entry;
        }

        if ($match === null) {
            throw new LDAPException($baseOnly ? 'ineligible_user' : 'user_not_found');
        }

        return $match;
    }

    /**
     * @param list<string> $attributes
     *
     * @return list<DirectoryEntry>
     */
    private function search(
        Connection $ldap,
        LDAPConnection $connection,
        string $baseDn,
        string $filter,
        array $attributes,
        int $limit,
        bool $baseOnly = false,
    ): array {
        $attributes = $attributes === [] ? ['1.1'] : array_values(array_unique($attributes, SORT_STRING));
        $search     = $baseOnly ? ldap_read(...) : ldap_search(...);
        $result     = @$search($ldap, $baseDn, $filter, $attributes, 0, $limit, $connection->searchTimeout);

        if ($result === false) {
            $code = ldap_errno($ldap);

            if ($baseOnly && $baseDn !== '' && $code === self::NO_SUCH_OBJECT) {
                return [];
            }

            throw new LDAPException($this->searchFailure($ldap, $code));
        }

        if (! @ldap_parse_result($ldap, $result, $code) || ldap_first_reference($ldap, $result) !== false) {
            throw new LDAPException('incomplete_search');
        }

        // Only accept the client-side size boundary when we actually received
        // that many entries. A partial user search cannot establish uniqueness.
        if ($code !== 0
            && ($code !== self::SIZE_LIMIT_EXCEEDED || ldap_count_entries($ldap, $result) !== $limit)
        ) {
            throw new LDAPException($this->searchFailure($ldap, $code));
        }

        $entries = [];

        for ($row = ldap_first_entry($ldap, $result); $row !== false; $row = ldap_next_entry($ldap, $row)) {
            $dn = ldap_get_dn($ldap, $row);

            if ($dn === false || ($dn === '' && $baseDn !== '') || str_contains($dn, "\0")) {
                throw new LDAPException('invalid_directory_entry');
            }

            $values = [];

            foreach ($attributes as $attribute) {
                $found = @ldap_get_values_len($ldap, $row, $attribute);

                if ($found !== false) {
                    unset($found['count']);
                    $values[strtolower($attribute)] = array_values($found);
                }
            }

            $entries[] = ['dn' => $dn, 'attributes' => $values];
        }

        return $entries;
    }

    /**
     * @param list<string>|string $baseDn
     * @param list<string>        $attributes
     */
    private function validateSearch(array|string $baseDn, string $filter, array $attributes): void
    {
        if (! LDAPConnection::isValidBaseDn($baseDn) || count($attributes) > 64) {
            throw new LDAPException('invalid_search');
        }

        LDAPFilter::validate($filter);

        foreach ($attributes as $attribute) {
            LDAPFilter::validateAttribute($attribute);
        }
    }

    private function transportFailure(Connection $ldap, int $code): ?string
    {
        // These OpenLDAP errors also cover TLS validation failures. Recognize
        // known certificate diagnostics without exposing the native message.
        if (in_array($code, [self::SERVER_DOWN, self::CONNECT_ERROR], true)
            && defined('LDAP_OPT_DIAGNOSTIC_MESSAGE')
            && ldap_get_option($ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, $diagnostic)
            && is_string($diagnostic)
            && (str_starts_with($diagnostic, 'TLS: hostname does not match ')
                || str_starts_with($diagnostic, 'TLS: unable to get subjectAltName')
                || str_starts_with($diagnostic, 'TLS: peer cert untrusted')
                || str_contains($diagnostic, 'certificate verify failed'))
        ) {
            return 'certificate_verification_failed';
        }

        return match ($code) {
            self::TIMEOUT                                             => 'connection_timeout',
            self::SERVER_DOWN, self::CONNECT_ERROR, self::UNAVAILABLE => 'directory_unavailable',
            default                                                   => null,
        };
    }

    private function searchFailure(Connection $ldap, int $code): string
    {
        return match ($code) {
            self::TIMEOUT, self::TIME_LIMIT_EXCEEDED                     => 'search_timeout',
            self::SIZE_LIMIT_EXCEEDED, self::ADMIN_LIMIT, self::REFERRAL => 'incomplete_search',
            self::FILTER_ERROR                                           => 'invalid_filter',
            default                                                      => $this->transportFailure($ldap, $code) ?? 'search_failed',
        };
    }
}
