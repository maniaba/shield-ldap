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

namespace Maniaba\ShieldLDAP\Tests\Authentication\LDAP;

use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\NativeLDAPDirectory;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Tests\Support\LDAP\NativeLDAPStub;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[PreserveGlobalState(false)]
#[RunTestsInSeparateProcesses]
final class NativeLDAPTransportTest extends TestCase
{
    private const FIRST_ENDPOINT  = 'ldaps://first.example.test:636';
    private const SECOND_ENDPOINT = 'ldaps://second.example.test:636';
    private const BASE_DN         = 'dc=example,dc=test';
    private const FIRST_BASE_DN   = 'ou=people,' . self::BASE_DN;
    private const SECOND_BASE_DN  = 'ou=contractors,' . self::BASE_DN;
    private const FIRST_ENTRY_DN  = 'uid=alice,' . self::FIRST_BASE_DN;
    private const SECOND_ENTRY_DN = 'uid=alice,' . self::SECOND_BASE_DN;

    protected function setUp(): void
    {
        parent::setUp();

        require __DIR__ . '/../../_support/LDAP/native_ldap_functions.inc';
    }

    public function testExtensionUnavailableDoesNotOpenAnEndpoint(): void
    {
        NativeLDAPStub::$available = false;

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('extension_unavailable');

        try {
            (new NativeLDAPDirectory())->testBind($this->connection());
        } finally {
            $this->assertSame([], NativeLDAPStub::$connected);
        }
    }

    #[DataProvider('provideMapsSearchErrors')]
    public function testMapsSearchErrors(int $code, bool $searchFails, string $reason): void
    {
        NativeLDAPStub::$searchCode  = $code;
        NativeLDAPStub::$searchFails = $searchFails;

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage($reason);

        (new NativeLDAPDirectory())->preview($this->connection(), 'dc=example,dc=test', '(uid=*)', ['uid']);
    }

    /**
     * @return iterable<string, array{int, bool, string}>
     */
    public static function provideMapsSearchErrors(): iterable
    {
        yield 'client timeout' => [-5, true, 'search_timeout'];

        yield 'server time limit' => [3, false, 'search_timeout'];

        yield 'administrative limit' => [11, false, 'incomplete_search'];

        yield 'referral result code' => [10, false, 'incomplete_search'];

        yield 'invalid filter' => [-7, true, 'invalid_filter'];

        yield 'server unavailable' => [52, false, 'directory_unavailable'];

        yield 'other search error' => [80, false, 'search_failed'];
    }

    public function testRejectsSearchReferenceEvenWithSuccessfulResultCode(): void
    {
        NativeLDAPStub::$hasReference = true;
        NativeLDAPStub::$entries      = [self::FIRST_ENTRY_DN];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('incomplete_search');

        (new NativeLDAPDirectory())->preview($this->connection(), 'dc=example,dc=test', '(uid=*)', ['uid']);
    }

    public function testSizeLimitReturnsSampleOnlyWhenRequestedNumberOfEntriesWereReceived(): void
    {
        NativeLDAPStub::$searchCode = 4;
        NativeLDAPStub::$entries    = [self::FIRST_ENTRY_DN, self::SECOND_ENTRY_DN];

        $result = (new NativeLDAPDirectory())->preview($this->connection(), 'dc=example,dc=test', '(uid=*)', ['uid'], 2);

        $this->assertSame([
            ['dn' => self::FIRST_ENTRY_DN, 'attributes' => []],
            ['dn' => self::SECOND_ENTRY_DN, 'attributes' => []],
        ], $result);
    }

    public function testRejectsSizeLimitWithFewerEntriesThanRequested(): void
    {
        NativeLDAPStub::$searchCode = 4;
        NativeLDAPStub::$entries    = [self::FIRST_ENTRY_DN];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('incomplete_search');

        (new NativeLDAPDirectory())->preview($this->connection(), 'dc=example,dc=test', '(uid=*)', ['uid'], 2);
    }

    /**
     * @param list<string> $firstMatches
     */
    #[DataProvider('provideFindsOneUserAcrossSearchBases')]
    public function testFindsOneUserAcrossSearchBases(string $firstBase, array $firstMatches): void
    {
        $connection = $this->connection();

        NativeLDAPStub::$entriesByBase = [
            $firstBase            => $firstMatches,
            self::SECOND_BASE_DN  => [self::SECOND_ENTRY_DN],
            self::SECOND_ENTRY_DN => [self::SECOND_ENTRY_DN],
        ];
        NativeLDAPStub::$attributesByDn = [self::SECOND_ENTRY_DN => ['entryuuid' => ['shared-directory-id']]];

        $entry = (new NativeLDAPDirectory())->authenticate(
            $connection,
            [$firstBase, self::SECOND_BASE_DN],
            '(uid=alice)',
            [],
            'user-password',
        );

        $this->assertSame(self::SECOND_ENTRY_DN, $entry['dn']);
        $this->assertSame(['shared-directory-id'], $entry['attributes']['entryuuid']);
        $this->assertSame([self::FIRST_ENDPOINT], NativeLDAPStub::$connected);
        $this->assertSame([
            ['bind', $connection->bindDn],
            ['search', $firstBase],
            ['search', self::SECOND_BASE_DN],
            ['bind', self::SECOND_ENTRY_DN],
            ['bind', $connection->bindDn],
            ['read', self::SECOND_ENTRY_DN],
        ], NativeLDAPStub::$operations);
        $this->assertSame(1, NativeLDAPStub::$unbound);
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function provideFindsOneUserAcrossSearchBases(): iterable
    {
        yield 'first base is empty' => [self::FIRST_BASE_DN, []];

        yield 'parent and child match the same user' => [self::BASE_DN, [self::SECOND_ENTRY_DN]];
    }

    #[DataProvider('provideRejectsDistinctEntriesAcrossSearchBases')]
    public function testRejectsDistinctEntriesAcrossSearchBases(string $secondExternalId): void
    {
        $connection = $this->connection();

        NativeLDAPStub::$entriesByBase = [
            self::FIRST_BASE_DN  => [self::FIRST_ENTRY_DN],
            self::SECOND_BASE_DN => [self::SECOND_ENTRY_DN],
        ];
        NativeLDAPStub::$attributesByDn = [
            self::FIRST_ENTRY_DN  => ['entryuuid' => ['first-directory-id']],
            self::SECOND_ENTRY_DN => ['entryuuid' => [$secondExternalId]],
        ];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('ambiguous_user');

        try {
            (new NativeLDAPDirectory())->authenticate($connection, [self::FIRST_BASE_DN, self::SECOND_BASE_DN], '(uid=alice)', [], 'user-password');
        } finally {
            $this->assertSame([
                ['bind', $connection->bindDn],
                ['search', self::FIRST_BASE_DN],
                ['search', self::SECOND_BASE_DN],
            ], NativeLDAPStub::$operations);
            $this->assertSame(1, NativeLDAPStub::$unbound);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRejectsDistinctEntriesAcrossSearchBases(): iterable
    {
        yield 'different immutable IDs' => ['second-directory-id'];

        yield 'same immutable ID at different entry DNs' => ['first-directory-id'];
    }

    public function testRejectsIncompleteSecondSearchBeforeCheckingPassword(): void
    {
        $connection = $this->connection();

        NativeLDAPStub::$entriesByBase     = [self::FIRST_BASE_DN => [self::FIRST_ENTRY_DN]];
        NativeLDAPStub::$attributesByDn    = [self::FIRST_ENTRY_DN => ['entryuuid' => ['first-directory-id']]];
        NativeLDAPStub::$searchCodesByBase = [self::SECOND_BASE_DN => 11];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('incomplete_search');

        try {
            (new NativeLDAPDirectory())->authenticate($connection, [self::FIRST_BASE_DN, self::SECOND_BASE_DN], '(uid=alice)', [], 'user-password');
        } finally {
            $this->assertSame([
                ['bind', $connection->bindDn],
                ['search', self::FIRST_BASE_DN],
                ['search', self::SECOND_BASE_DN],
            ], NativeLDAPStub::$operations);
            $this->assertSame(1, NativeLDAPStub::$unbound);
        }
    }

    public function testLookupConfirmsTheEligibleIdentityWithOneServiceBind(): void
    {
        $connection = $this->connection();
        $externalId = "\0(*\\)";

        NativeLDAPStub::$entriesByBase = [
            self::BASE_DN         => [self::SECOND_ENTRY_DN],
            self::SECOND_BASE_DN  => [self::SECOND_ENTRY_DN],
            self::SECOND_ENTRY_DN => [self::SECOND_ENTRY_DN],
        ];
        NativeLDAPStub::$attributesByDn = [self::SECOND_ENTRY_DN => [
            'entryuuid' => [$externalId],
            'mail'      => ['alice@example.test'],
        ]];

        $entry = (new NativeLDAPDirectory())->lookupUser($connection, [self::BASE_DN, self::SECOND_BASE_DN], '(uid=alice)', '(objectClass=person)');

        $this->assertSame(['dn' => self::SECOND_ENTRY_DN, 'attributes' => ['entryuuid' => [$externalId]]], $entry);
        $this->assertSame([
            ['bind', $connection->bindDn],
            ['search', self::BASE_DN],
            ['search', self::SECOND_BASE_DN],
            ['read', self::SECOND_ENTRY_DN],
        ], NativeLDAPStub::$operations);
        $this->assertSame([
            ['filter' => '(uid=alice)', 'attributes' => ['entryUUID']],
            ['filter' => '(uid=alice)', 'attributes' => ['entryUUID']],
            ['filter' => '(&(uid=alice)(objectClass=person)(entryUUID=\00\28\2a\5c\29))', 'attributes' => ['entryUUID']],
        ], NativeLDAPStub::$queries);
        $this->assertSame(1, NativeLDAPStub::$unbound);
    }

    public function testLookupRejectsAmbiguityBeforeApplyingEligibility(): void
    {
        $connection = $this->connection();

        NativeLDAPStub::$entriesByBase = [
            self::FIRST_BASE_DN  => [self::FIRST_ENTRY_DN],
            self::SECOND_BASE_DN => [self::SECOND_ENTRY_DN],
        ];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('ambiguous_user');

        try {
            (new NativeLDAPDirectory())->lookupUser($connection, [self::FIRST_BASE_DN, self::SECOND_BASE_DN], '(uid=alice)', '(objectClass=person)');
        } finally {
            $this->assertSame([
                ['bind', $connection->bindDn],
                ['search', self::FIRST_BASE_DN],
                ['search', self::SECOND_BASE_DN],
            ], NativeLDAPStub::$operations);
            $this->assertSame(['(uid=alice)', '(uid=alice)'], array_column(NativeLDAPStub::$queries, 'filter'));
            $this->assertSame(1, NativeLDAPStub::$unbound);
        }
    }

    public function testLookupRequiresCertificateVerificationBeforeOpeningAnEndpoint(): void
    {
        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('tls_verification_required');

        try {
            (new NativeLDAPDirectory())->lookupUser($this->connection(verifyCertificate: false), self::BASE_DN, '(uid=alice)');
        } finally {
            $this->assertSame([], NativeLDAPStub::$connected);
        }
    }

    public function testScanUsesCriticalPagingAndResetsTheCookieForEachBase(): void
    {
        $connection = $this->scanConnection();
        $cookie     = "\0continuation";

        NativeLDAPStub::$pages = [
            ['entries' => [self::FIRST_ENTRY_DN], 'cookie' => $cookie],
            ['entries' => [self::SECOND_ENTRY_DN], 'cookie' => ''],
            ['entries' => [self::SECOND_ENTRY_DN], 'cookie' => ''],
        ];
        NativeLDAPStub::$attributesByDn = [
            self::FIRST_ENTRY_DN  => ['entryuuid' => ['first-id'], 'uid' => ['alice'], 'mail' => ['alice@example.test']],
            self::SECOND_ENTRY_DN => ['entryuuid' => ['second-id'], 'uid' => ['other-alice']],
        ];

        $entries = iterator_to_array((new NativeLDAPDirectory())->scanUsers($connection, 1));

        $this->assertSame([self::FIRST_ENTRY_DN, self::SECOND_ENTRY_DN, self::SECOND_ENTRY_DN], array_column($entries, 'dn'));
        $this->assertSame(['entryuuid' => ['first-id'], 'uid' => ['alice']], $entries[0]['attributes']);
        $this->assertSame([self::FIRST_ENDPOINT], NativeLDAPStub::$connected);
        $this->assertSame([
            ['bind', $connection->bindDn],
            ['search', self::BASE_DN],
            ['search', self::BASE_DN],
            ['search', self::SECOND_BASE_DN],
        ], NativeLDAPStub::$operations);
        $requests = NativeLDAPStub::$pagedRequests;
        $this->assertSame([0, 0, 0], array_column($requests, 'sizeLimit'));
        $this->assertSame(array_fill(0, 3, '(&(objectClass=person)(accountStatus=active))'), array_column($requests, 'filter'));
        $this->assertSame(array_fill(0, 3, ['entryUUID', 'uid']), array_column($requests, 'attributes'));
        $this->assertSame(array_map(
            static fn (string $value): array => [[
                'oid'        => LDAP_CONTROL_PAGEDRESULTS,
                'iscritical' => true,
                'value'      => ['size' => 1, 'cookie' => $value],
            ]],
            ['', $cookie, ''],
        ), array_column($requests, 'controls'));
        $this->assertSame(1, NativeLDAPStub::$unbound);
    }

    /**
     * @param array{entries: list<string>, cookie?: int|string, code?: int, referrals?: list<string>} $page
     */
    #[DataProvider('provideRejectsIncompletePagedResults')]
    public function testRejectsIncompletePagedResults(array $page): void
    {
        NativeLDAPStub::$pages = [$page];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('incomplete_search');

        try {
            foreach ((new NativeLDAPDirectory())->scanUsers($this->scanConnection(), 1) as $entry) {
                $this->fail('The incomplete page yielded entry ' . $entry['dn']);
            }
        } finally {
            $this->assertSame(1, NativeLDAPStub::$unbound);
        }
    }

    /**
     * @return iterable<string, array{array{entries: list<string>, cookie?: int|string, code?: int, referrals?: list<string>}}>
     */
    public static function provideRejectsIncompletePagedResults(): iterable
    {
        yield 'missing control' => [['entries' => [self::FIRST_ENTRY_DN]]];

        yield 'malformed cookie' => [['entries' => [self::FIRST_ENTRY_DN], 'cookie' => 1]];

        yield 'size limit with a full page' => [['entries' => [self::FIRST_ENTRY_DN], 'cookie' => '', 'code' => 4]];

        yield 'response referrals with a success code' => [[
            'entries'   => [self::FIRST_ENTRY_DN],
            'cookie'    => '',
            'referrals' => ['ldap://other.example.test'],
        ]];

        yield 'oversized page' => [['entries' => [self::FIRST_ENTRY_DN, self::SECOND_ENTRY_DN], 'cookie' => '']];
    }

    public function testScanRequiresVerifiedTlsBeforeOpeningAnEndpoint(): void
    {
        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('tls_verification_required');

        try {
            iterator_to_array((new NativeLDAPDirectory())->scanUsers($this->scanConnection(verifyCertificate: false)));
        } finally {
            $this->assertSame([], NativeLDAPStub::$connected);
        }
    }

    #[DataProvider('provideRetriesAlternativeEndpointOnTransportFailure')]
    public function testRetriesAlternativeEndpointOnTransportFailure(int $code): void
    {
        NativeLDAPStub::$bindErrors = [self::FIRST_ENDPOINT => $code];

        (new NativeLDAPDirectory())->testBind($this->connection());

        $this->assertSame([self::FIRST_ENDPOINT, self::SECOND_ENDPOINT], NativeLDAPStub::$connected);
        $this->assertSame(2, NativeLDAPStub::$unbound);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideRetriesAlternativeEndpointOnTransportFailure(): iterable
    {
        yield 'server down' => [-1];

        yield 'connection timeout' => [-5];

        yield 'client connection error' => [-11];

        yield 'server unavailable' => [52];
    }

    public function testReportsConnectionTimeoutWhenEndpointsAreExhausted(): void
    {
        NativeLDAPStub::$bindErrors = [self::FIRST_ENDPOINT => -1, self::SECOND_ENDPOINT => -5];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('connection_timeout');

        try {
            (new NativeLDAPDirectory())->testBind($this->connection());
        } finally {
            $this->assertSame([self::FIRST_ENDPOINT, self::SECOND_ENDPOINT], NativeLDAPStub::$connected);
            $this->assertSame(2, NativeLDAPStub::$unbound);
        }
    }

    public function testCertificateVerificationFailureStopsFailoverAndRedactsTheDiagnostic(): void
    {
        NativeLDAPStub::$bindErrors = [self::FIRST_ENDPOINT => -11];
        NativeLDAPStub::$diagnostic = 'TLS: hostname does not match private-diagnostic.example.test';

        try {
            (new NativeLDAPDirectory())->testBind($this->connection());
            $this->fail('Expected a certificate verification failure.');
        } catch (LDAPException $exception) {
            $this->assertSame('certificate_verification_failed', $exception->reason);
            $this->assertStringNotContainsString('private-diagnostic.example.test', $exception->getMessage());
        }

        $this->assertSame([self::FIRST_ENDPOINT], NativeLDAPStub::$connected);
        $this->assertSame(1, NativeLDAPStub::$unbound);
    }

    public function testInvalidServiceCredentialsStopFailover(): void
    {
        NativeLDAPStub::$bindErrors        = [self::FIRST_ENDPOINT => 49];
        NativeLDAPStub::$warnOnBindFailure = true;

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('service_bind_failed');

        try {
            (new NativeLDAPDirectory())->testBind($this->connection());
        } finally {
            $this->assertSame([self::FIRST_ENDPOINT], NativeLDAPStub::$connected);
            $this->assertSame(1, NativeLDAPStub::$unbound);
        }
    }

    public function testDoesNotStartTlsOrBindWhenCertificateVerificationOverrideCannotBeApplied(): void
    {
        $connection = new LDAPConnection(
            'test',
            ['first.example.test'],
            self::BASE_DN,
            'cn=reader,' . self::BASE_DN,
            'readerPassword!',
            'starttls',
            verifyCertificate: false,
        );
        NativeLDAPStub::$certificateOptionSucceeds = false;

        $supported = PHP_VERSION_ID >= 80408 || (PHP_VERSION_ID >= 80322 && PHP_VERSION_ID < 80400);
        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage($supported ? 'tls_context_failed' : 'tls_verification_override_unsupported');

        try {
            (new NativeLDAPDirectory())->testBind($connection);
        } finally {
            $this->assertSame(0, NativeLDAPStub::$tlsStarts);
            $this->assertSame([], NativeLDAPStub::$operations);
        }
    }

    public function testNativeTraceRedactsSubmittedAndServicePasswords(): void
    {
        $this->assertNotFalse(ini_set('zend.exception_ignore_args', '0'));

        NativeLDAPStub::$bindErrors = [self::FIRST_ENDPOINT => 49];
        $connection                 = $this->connection();

        try {
            (new NativeLDAPDirectory())->authenticate(
                $connection,
                $connection->baseDn,
                '(uid=alice)',
                ['uid'],
                'synthetic-user-password',
            );
            $this->fail('Expected a bind failure.');
        } catch (LDAPException $exception) {
            $frames = array_filter(
                $exception->getTrace(),
                static fn (array $frame): bool => ($frame['class'] ?? null) === NativeLDAPDirectory::class,
            );
            $arguments = array_column($frames, 'args', 'function');

            $this->assertSame('service_bind_failed', $exception->reason);
            $this->assertSame('SensitiveParameterValue', get_debug_type($arguments['authenticate'][4]));
            $this->assertSame('SensitiveParameterValue', get_debug_type($arguments['bind'][2]));
        }
    }

    private function connection(bool $verifyCertificate = true): LDAPConnection
    {
        return new LDAPConnection(
            'test',
            ['first.example.test', 'second.example.test'],
            self::BASE_DN,
            'cn=reader,dc=example,dc=test',
            'readerPassword!',
            verifyCertificate: $verifyCertificate,
        );
    }

    private function scanConnection(bool $verifyCertificate = true): LDAPConnection
    {
        return new LDAPConnection(
            'test',
            ['first.example.test', 'second.example.test'],
            self::BASE_DN,
            'cn=reader,dc=example,dc=test',
            'readerPassword!',
            userBaseDn: [self::BASE_DN, self::SECOND_BASE_DN],
            profileAttributes: ['username' => 'uid'],
            eligibilityFilter: '(accountStatus=active)',
            verifyCertificate: $verifyCertificate,
        );
    }
}
