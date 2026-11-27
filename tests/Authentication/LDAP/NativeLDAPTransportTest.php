<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
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

    private function connection(): LDAPConnection
    {
        return new LDAPConnection(
            'test',
            ['first.example.test', 'second.example.test'],
            self::BASE_DN,
            'cn=reader,dc=example,dc=test',
            'readerPassword!',
        );
    }
}
