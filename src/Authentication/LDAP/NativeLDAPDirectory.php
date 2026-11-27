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
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;
use SensitiveParameter;

/**
 * Implements directory operations with PHP's LDAP extension over TLS.
 *
 * @phpstan-type DirectoryEntry array{dn: string, attributes: array<string, list<string>>}
 */
final class NativeLDAPDirectory implements MultiBaseLDAPDirectoryInterface, LDAPUserLookupInterface, LDAPUserEnumerationInterface
{
    private const TIME_LIMIT_EXCEEDED = 3;
    private const SIZE_LIMIT_EXCEEDED = 4;
    private const REFERRAL            = 10;
    private const ADMIN_LIMIT         = 11;
    private const NO_SUCH_OBJECT      = 32;
    private const INVALID_CREDENTIALS = 49;
    private const UNAVAILABLE         = 52;
    private const MAX_SCAN_PAGE_SIZE  = 1_000;
    private const MAX_SCAN_PAGES      = 10_000;

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
            throw new LDAPException(LDAPReason::InvalidCredentials);
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

            $verified = $this->readEligibleEntry($ldap, $connection, $entry, $eligibility, $attributes);

            if (($connection->groupMappings ?? []) !== []) {
                $verified['matchedGroups'] = $this->findMappedGroups($ldap, $connection, $verified['dn']);
            }

            return $verified;
        } finally {
            ldap_unbind($ldap);
        }
    }

    /**
     * @return list<string>
     */
    private function findMappedGroups(Connection $ldap, LDAPConnection $connection, string $userDn): array
    {
        $filter = LDAPFilter::any(
            LDAPFilter::all(
                '(|(objectClass=group)(objectClass=groupOfNames))',
                LDAPFilter::equal('member', $userDn),
            ),
            LDAPFilter::all(
                '(objectClass=groupOfUniqueNames)',
                LDAPFilter::equal('uniqueMember', $userDn),
            ),
        );
        $matched = [];

        foreach ($connection->groupMappings ?? [] as $group => $dn) {
            if ($this->search($ldap, $connection, $dn, $filter, [], 1, true) !== []) {
                $matched[] = $group;
            }
        }

        return $matched;
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
            throw new LDAPException(LDAPReason::TlsVerificationRequired);
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
     */
    public function scanUsers(LDAPConnection $connection, int $pageSize = 100): LDAPUserScan
    {
        return new LDAPUserScan(function () use ($connection, $pageSize): array {
            if (! $connection->verifyCertificate) {
                throw new LDAPException(LDAPReason::TlsVerificationRequired);
            }

            if ($pageSize < 1 || $pageSize > self::MAX_SCAN_PAGE_SIZE) {
                throw new LDAPException(LDAPReason::InvalidSearchLimit);
            }

            if (extension_loaded('ldap') && ! defined('LDAP_CONTROL_PAGEDRESULTS')) {
                throw new LDAPException(LDAPReason::UnsupportedLdapClient);
            }

            $baseDn     = $connection->userBaseDn ?? $connection->baseDn;
            $filter     = LDAPFilter::all($connection->loginFilter, $connection->eligibilityFilter);
            $attributes = array_values(array_unique([$connection->externalIdAttribute, ...array_values($connection->profileAttributes)]));
            $this->validateSearch($baseDn, $filter, $attributes);

            $ldap = $this->open($connection, true);

            return [$ldap, $this->scanEntries($ldap, $connection, $baseDn, $filter, $attributes, $pageSize)];
        });
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
            throw new LDAPException(LDAPReason::InvalidSearchLimit);
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
            throw new LDAPException(LDAPReason::ExtensionUnavailable);
        }

        if (! defined('LDAP_OPT_NETWORK_TIMEOUT') || ! defined('LDAP_OPT_TIMEOUT')
                                                  || ! defined('LDAP_OPT_X_TLS_REQUIRE_CERT') || ! defined('LDAP_OPT_X_TLS_DEMAND')
                                                  || ! defined('LDAP_OPT_X_TLS_HARD') || ! function_exists('ldap_start_tls')
        ) {
            throw new LDAPException(LDAPReason::UnsupportedLdapClient);
        }

        $failure = new LDAPException(LDAPReason::DirectoryUnavailable);

        foreach ($connection->hosts as $host) {
            $ldap = @ldap_connect($connection->endpoint($host));

            if ($ldap === false) {
                throw new LDAPException(LDAPReason::TlsContextFailed);
            }

            try {
                $this->configure($ldap, $connection);

                if ($connection->encryption === 'starttls' && ! @ldap_start_tls($ldap)) {
                    throw new LDAPException($this->transportFailure($ldap, ldap_errno($ldap)) ?? LDAPReason::TlsFailed);
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

                if ($exception->kind?->isRetryableEndpointFailure() !== true) {
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
            throw new LDAPException(LDAPReason::ConnectionConfigurationFailed);
        }
    }

    private function configureCertificateVerification(Connection $ldap, LDAPConnection $connection): void
    {
        if ($connection->verifyCertificate) {
            if (! ldap_get_option($ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, $requireCert)
                || ! in_array($requireCert, [LDAP_OPT_X_TLS_DEMAND, LDAP_OPT_X_TLS_HARD], true)
            ) {
                throw new LDAPException(LDAPReason::TlsVerificationRequired);
            }

            return;
        }

        // Supported ext-ldap releases rebuild the TLS context per handle for StartTLS.
        // LDAPS uses a process-wide context and cannot safely apply this override.
        if ($connection->encryption !== 'starttls' || ! defined('LDAP_OPT_X_TLS_NEVER')
                                                   || PHP_VERSION_ID < 80322 || (PHP_VERSION_ID >= 80400 && PHP_VERSION_ID < 80408)
        ) {
            throw new LDAPException(LDAPReason::TlsVerificationOverrideUnsupported);
        }

        if (! @ldap_set_option($ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER)) {
            throw new LDAPException(LDAPReason::TlsContextFailed);
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
                ? LDAPReason::InvalidCredentials
                : ($serviceAccount ? LDAPReason::ServiceBindFailed : LDAPReason::UserBindFailed)));
    }

    /**
     * @param DirectoryEntry $entry
     */
    private function eligibleEntryFilter(LDAPConnection $connection, array $entry, string $filter, string $eligibilityFilter): string
    {
        $ids = $entry['attributes'][strtolower($connection->externalIdAttribute)] ?? [];

        if (count($ids) !== 1 || $ids[0] === '') {
            throw new LDAPException(LDAPReason::InvalidExternalIdentity);
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
            throw new LDAPException(LDAPReason::DirectoryIdentityChanged);
        }

        return $verified;
    }

    /**
     * @param list<string>|string $baseDn
     * @param list<string>        $attributes
     *
     * @return iterable<int, DirectoryEntry>
     */
    private function scanEntries(
        Connection $ldap,
        LDAPConnection $connection,
        array|string $baseDn,
        string $filter,
        array $attributes,
        int $pageSize,
    ): iterable {
        $pagesRemaining = self::MAX_SCAN_PAGES;

        foreach ((array) $baseDn as $base) {
            $cookie = '';

            do {
                if ($pagesRemaining === 0) {
                    throw new LDAPException(LDAPReason::ScanLimitExceeded);
                }

                $pagesRemaining--;

                foreach ($this->search($ldap, $connection, $base, $filter, $attributes, $pageSize, pageCookie: $cookie) as $entry) {
                    yield $entry;
                }
            } while ($cookie !== '');
        }
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
                throw new LDAPException(LDAPReason::AmbiguousUser);
            }

            $match = $entry;
        }

        if ($match === null) {
            throw new LDAPException($baseOnly ? LDAPReason::IneligibleUser : LDAPReason::UserNotFound);
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
        ?string &$pageCookie = null,
    ): array {
        $attributes = $attributes === [] ? ['1.1'] : array_values(array_unique($attributes, SORT_STRING));
        $search     = $baseOnly ? ldap_read(...) : ldap_search(...);
        $paged      = $pageCookie !== null;
        $controls   = $paged ? [[
            'oid'        => LDAP_CONTROL_PAGEDRESULTS,
            'iscritical' => true,
            'value'      => ['size' => $limit, 'cookie' => $pageCookie],
        ]] : null;
        $result = @$search($ldap, $baseDn, $filter, $attributes, 0, $paged ? 0 : $limit, $connection->searchTimeout, LDAP_DEREF_NEVER, $controls);

        if ($result === false) {
            $code = ldap_errno($ldap);

            if ($baseOnly && $baseDn !== '' && $code === self::NO_SUCH_OBJECT) {
                return [];
            }

            throw new LDAPException($this->searchFailure($ldap, $code));
        }

        $parsed = $paged
            ? @ldap_parse_result($ldap, $result, $code, $matchedDn, $message, $referrals, $responseControls)
            : @ldap_parse_result($ldap, $result, $code);

        if (! $parsed || ldap_first_reference($ldap, $result) !== false || ($paged && $referrals !== [])) {
            throw new LDAPException(LDAPReason::IncompleteSearch);
        }

        // Only accept the client-side size boundary when we actually received
        // that many entries. A partial user search cannot establish uniqueness.
        if ($code !== 0
            && ($paged || $code !== self::SIZE_LIMIT_EXCEEDED || ldap_count_entries($ldap, $result) !== $limit)
        ) {
            throw new LDAPException($this->searchFailure($ldap, $code));
        }

        if ($paged) {
            $cookie = $responseControls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'] ?? null;
            if (! is_string($cookie) || ldap_count_entries($ldap, $result) > $limit) {
                throw new LDAPException(LDAPReason::IncompleteSearch);
            }

            $pageCookie = $cookie;
        }

        $entries = [];

        for ($row = ldap_first_entry($ldap, $result); $row !== false; $row = ldap_next_entry($ldap, $row)) {
            $dn = ldap_get_dn($ldap, $row);

            if ($dn === false || ($dn === '' && $baseDn !== '') || str_contains($dn, "\0")) {
                throw new LDAPException(LDAPReason::InvalidDirectoryEntry);
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
            throw new LDAPException(LDAPReason::InvalidSearch);
        }

        LDAPFilter::validate($filter);

        foreach ($attributes as $attribute) {
            LDAPFilter::validateAttribute($attribute);
        }
    }

    private function transportFailure(Connection $ldap, int $code): ?LDAPReason
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
            return LDAPReason::CertificateVerificationFailed;
        }

        return match ($code) {
            self::TIMEOUT                                             => LDAPReason::ConnectionTimeout,
            self::SERVER_DOWN, self::CONNECT_ERROR, self::UNAVAILABLE => LDAPReason::DirectoryUnavailable,
            default                                                   => null,
        };
    }

    private function searchFailure(Connection $ldap, int $code): LDAPReason
    {
        return match ($code) {
            self::TIMEOUT, self::TIME_LIMIT_EXCEEDED                     => LDAPReason::SearchTimeout,
            self::SIZE_LIMIT_EXCEEDED, self::ADMIN_LIMIT, self::REFERRAL => LDAPReason::IncompleteSearch,
            self::FILTER_ERROR                                           => LDAPReason::InvalidFilter,
            default                                                      => $this->transportFailure($ldap, $code) ?? LDAPReason::SearchFailed,
        };
    }
}
