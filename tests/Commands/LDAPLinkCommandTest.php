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

namespace Maniaba\ShieldLDAP\Tests\Commands;

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\StreamFilterTrait;
use Config\Services;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserLookupInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @internal
 */
final class LDAPLinkCommandTest extends DatabaseTestCase
{
    use StreamFilterTrait;

    private const COMMAND          = 'shield:ldap-link';
    private const GUID             = '00112233-4455-6677-8899-aabbccddeeff';
    private const OTHER_GUID       = 'ffeeddcc-bbaa-9988-7766-554433221100';
    private const OTHER_GUID_BYTES = "\xcc\xdd\xee\xff\xaa\xbb\x88\x99\x77\x66\x55\x44\x33\x22\x11\x00";
    private const USER_BASES       = ['ou=employees,dc=ad,dc=example,dc=test', 'ou=contractors,dc=ad,dc=example,dc=test'];

    protected $refresh = true;
    private AuthLDAP $config;
    private LDAPUserLookupInterface&MockObject $directory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->config              = new AuthLDAP();
        $this->config->connections = ['corporate' => [
            'hosts'               => ['ad.example.test'],
            'baseDn'              => 'dc=ad,dc=example,dc=test',
            'bindDn'              => 'cn=reader,dc=ad,dc=example,dc=test',
            'bindPassword'        => 'command-test-bind-password',
            'userBaseDn'          => self::USER_BASES,
            'loginFilter'         => '(objectClass=person)',
            'eligibilityFilter'   => '(accountStatus=active)',
            'loginAttributes'     => ['sAMAccountName', 'userPrincipalName'],
            'profileAttributes'   => ['username' => 'sAMAccountName'],
            'externalIdAttribute' => 'objectGUID',
        ]];
        Factories::injectMock('config', 'AuthLDAP', $this->config);

        $this->directory = $this->createMock(LDAPUserLookupInterface::class);
        $this->directory->expects($this->never())->method('authenticate');
        Services::injectMock('ldapDirectory', $this->directory);
    }

    public function testScanReportsCandidatesAndMissingEntriesWithoutCreatingLinks(): void
    {
        $this->createUser('alice');
        $this->createUser('unmatched');

        $this->directory->expects($this->exactly(2))->method('lookupUser')->willReturnCallback(
            function (LDAPConnection $connection, array|string $baseDn, string $filter, string $eligibilityFilter): array {
                $this->assertSame('corporate', $connection->id);
                $this->assertSame(self::USER_BASES, $baseDn);
                $this->assertStringContainsString('(objectClass=person)', $filter);
                $this->assertSame('(accountStatus=active)', $eligibilityFilter);

                if (str_contains($filter, '(sAMAccountName=alice)')) {
                    return $this->directoryEntry();
                }

                $this->assertStringContainsString('(sAMAccountName=unmatched)', $filter);

                throw new LDAPException('user_not_found');
            },
        );

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate']));
        $this->assertStringContainsString('alice', $this->getStreamFilterBuffer());
        $this->assertStringContainsString('user_not_found', $this->getStreamFilterBuffer());
        $this->assertNoDirectoryLink();
    }

    public function testNamedScanUsesTheSoleLoginAttributeWithoutAUsernameMapping(): void
    {
        $this->createUser('alice');
        $this->createUser('not-selected');
        $this->config->connections['corporate']['profileAttributes'] = [];
        $this->config->connections['corporate']['loginAttributes']   = ['uid'];
        $this->directory->expects($this->once())->method('lookupUser')->with(
            $this->isInstanceOf(LDAPConnection::class),
            self::USER_BASES,
            '(&(objectClass=person)(uid=alice))',
            '(accountStatus=active)',
        )->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate', 'alice']));
        $this->assertStringContainsString('candidate', $this->getStreamFilterBuffer());
        $this->assertNoDirectoryLink();
    }

    public function testApplyLinksCanonicalGuidAndKeepsAnExistingLinkFromAnotherConnection(): void
    {
        $user     = $this->createUser('alice');
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $resolver->link('another', self::OTHER_GUID, $user->id);

        $this->directory->expects($this->once())->method('lookupUser')->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null]));
        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => LDAPUserResolver::ID_TYPE,
            'name'    => 'corporate',
            'secret'  => hash('sha256', "corporate\0" . self::GUID),
        ]);
        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => LDAPUserResolver::ID_TYPE,
            'name'    => 'another',
            'secret'  => hash('sha256', "another\0" . self::OTHER_GUID),
        ]);
        $this->assertSame($user->id, $resolver->resolve('corporate', self::GUID)->id);
    }

    public function testApplyKeepsTheDirectoryGuidAlreadyLinkedToAnotherUser(): void
    {
        $owner  = $this->createUser('owner');
        $target = $this->createUser('alice');
        (new LDAPUserResolver(model(UserModel::class)))->link('corporate', self::GUID, $owner->id);
        $this->directory->expects($this->once())->method('lookupUser')->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null]));
        $this->assertStringContainsString('identity_conflict', $this->getStreamFilterBuffer());
        $this->dontSeeInDatabase($this->tables['identities'], ['user_id' => $target->id, 'type' => LDAPUserResolver::ID_TYPE]);
        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $owner->id,
            'type'    => LDAPUserResolver::ID_TYPE,
            'secret'  => hash('sha256', "corporate\0" . self::GUID),
        ]);
    }

    public function testApplyCannotReplaceTheUsersExistingLinkForTheSameConnection(): void
    {
        $user = $this->createUser('alice');
        (new LDAPUserResolver(model(UserModel::class)))->link('corporate', self::OTHER_GUID, $user->id);
        $this->directory->expects($this->once())->method('lookupUser')->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null]));
        $this->assertStringContainsString('identity_conflict', $this->getStreamFilterBuffer());
        $this->seeNumRecords(1, $this->tables['identities'], ['user_id' => $user->id, 'type' => LDAPUserResolver::ID_TYPE]);
        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => LDAPUserResolver::ID_TYPE,
            'secret'  => hash('sha256', "corporate\0" . self::OTHER_GUID),
        ]);
    }

    public function testPreviewReportsAStaleLinkWithoutChangingIt(): void
    {
        $user     = $this->createUser('alice');
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $resolver->link('corporate', self::OTHER_GUID, $user->id);
        $this->directory->expects($this->once())->method('lookupUser')->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate', 'alice']));
        $this->assertStringContainsString('stale_link', $this->getStreamFilterBuffer());
        $this->assertSame($user->id, $resolver->resolve('corporate', self::OTHER_GUID)->id);
        $this->seeNumRecords(1, $this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }

    public function testBulkApplyPreflightsAllUsersBeforeWritingAndSkipsMissingEntries(): void
    {
        $alice = $this->createUser('alice');
        $bob   = $this->createUser('bob');
        $this->createUser('unmatched');
        $lookups = [];

        $this->directory->expects($this->exactly(5))->method('lookupUser')->willReturnCallback(
            function (LDAPConnection $connection, array|string $baseDn, string $filter) use (&$lookups): array {
                $lookups[] = $filter;
                if (count($lookups) <= 3) {
                    $this->assertNoDirectoryLink();
                }

                if (str_contains($filter, '(sAMAccountName=unmatched)')) {
                    throw new LDAPException('user_not_found');
                }

                return str_contains($filter, '(sAMAccountName=alice)')
                    ? $this->directoryEntry()
                    : $this->directoryEntry(self::OTHER_GUID_BYTES);
            },
        );

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate', 'all' => null, 'apply' => null]));
        $this->assertSame([
            '(&(objectClass=person)(sAMAccountName=alice))',
            '(&(objectClass=person)(sAMAccountName=bob))',
            '(&(objectClass=person)(sAMAccountName=unmatched))',
            '(&(objectClass=person)(sAMAccountName=alice))',
            '(&(objectClass=person)(sAMAccountName=bob))',
        ], $lookups);
        $this->assertStringContainsString('linked=2 skipped=1 conflicts=0', $this->getStreamFilterBuffer());
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $this->assertSame($alice->id, $resolver->resolve('corporate', self::GUID)->id);
        $this->assertSame($bob->id, $resolver->resolve('corporate', self::OTHER_GUID)->id);
    }

    public function testBulkApplyRejectsCaseVariantsOfTheSameLocalUsername(): void
    {
        if (model(UserModel::class)->builder()->db()->DBDriver !== 'SQLite3') {
            $this->markTestSkipped('The case-sensitive username fixture requires SQLite.');
        }

        $this->createUser('Alice');
        $this->createUser('alice');
        $this->directory->method('lookupUser')->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'all' => null, 'apply' => null]));
        $this->assertStringContainsString('ambiguous_local_user', $this->getStreamFilterBuffer());
        $this->assertStringContainsString('linked=0 skipped=0 conflicts=2', $this->getStreamFilterBuffer());
        $this->assertNoDirectoryLink();
    }

    public function testBulkApplyRejectsDuplicateDirectoryIds(): void
    {
        $this->createUser('bob');
        $this->createUser('carol');
        $this->directory->expects($this->exactly(2))->method('lookupUser')->willReturn($this->directoryEntry());

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'all' => null, 'apply' => null]));
        $this->assertStringContainsString('duplicate_directory_identity', $this->getStreamFilterBuffer());
        $this->assertStringContainsString('linked=0 skipped=0 conflicts=2', $this->getStreamFilterBuffer());
        $this->assertNoDirectoryLink();
    }

    public function testBulkApplyCanResumeAfterDirectoryFailureDuringRevalidation(): void
    {
        $alice      = $this->createUser('alice');
        $bob        = $this->createUser('bob');
        $bobLookups = 0;
        $this->directory->expects($this->exactly(7))->method('lookupUser')->willReturnCallback(
            function (LDAPConnection $connection, array|string $baseDn, string $filter) use (&$bobLookups): array {
                if (str_contains($filter, '(sAMAccountName=alice)')) {
                    return $this->directoryEntry();
                }

                if (++$bobLookups === 2) {
                    throw new LDAPException('directory_unavailable');
                }

                return $this->directoryEntry(self::OTHER_GUID_BYTES);
            },
        );

        $params   = ['corporate', 'all' => null, 'apply' => null];
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, $params));
        $this->assertStringContainsString('directory_unavailable', $this->getStreamFilterBuffer());
        $this->assertSame($alice->id, $resolver->resolve('corporate', self::GUID)->id);
        $this->dontSeeInDatabase($this->tables['identities'], ['user_id' => $bob->id, 'type' => LDAPUserResolver::ID_TYPE]);

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, $params));
        $this->assertSame($alice->id, $resolver->resolve('corporate', self::GUID)->id);
        $this->assertSame($bob->id, $resolver->resolve('corporate', self::OTHER_GUID)->id);
        $this->assertStringContainsString('linked=1 skipped=1 conflicts=0', $this->getStreamFilterBuffer());
        $this->seeNumRecords(2, $this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }

    public function testReplaceWritesTheExpectedGuidAndPreservesUnrelatedLinks(): void
    {
        $user     = $this->createUser('alice');
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $resolver->link('corporate', self::OTHER_GUID, $user->id);
        $resolver->link('another', self::OTHER_GUID, $user->id);
        $oldKey   = hash('sha256', "corporate\0" . self::OTHER_GUID);
        $previous = model(UserIdentityModel::class)->getIdentityBySecret(LDAPUserResolver::ID_TYPE, $oldKey);
        $this->assertNotNull($previous);
        $this->directory->expects($this->once())->method('lookupUser')->willReturn($this->directoryEntry());

        $params = ['corporate', 'alice', 'apply' => null, 'replace' => self::GUID];
        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, $params));
        $this->assertStringContainsString('replaced', $this->getStreamFilterBuffer());
        $this->seeInDatabase($this->tables['identities'], [
            'id'     => $previous->id,
            'secret' => hash('sha256', "corporate\0" . self::GUID),
        ]);
        $this->dontSeeInDatabase($this->tables['identities'], ['secret' => $oldKey]);
        $this->assertSame($user->id, $resolver->resolve('corporate', self::GUID)->id);
        $this->assertSame($user->id, $resolver->resolve('another', self::OTHER_GUID)->id);
    }

    #[DataProvider('provideRefusesUnsafeReplacement')]
    public function testRefusesUnsafeReplacement(string $expectedId, bool $alreadyOwned, string $reason): void
    {
        $user     = $this->createUser('alice');
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $resolver->link('corporate', self::OTHER_GUID, $user->id);

        $owner = null;
        if ($alreadyOwned) {
            $owner = $this->createUser('owner');
            $resolver->link('corporate', self::GUID, $owner->id);
        }
        $this->directory->expects($this->once())->method('lookupUser')->willReturn($this->directoryEntry());

        $params = ['corporate', 'alice', 'apply' => null, 'replace' => $expectedId];
        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, $params));
        $this->assertStringContainsString($reason, $this->getStreamFilterBuffer());
        $this->assertSame($user->id, $resolver->resolve('corporate', self::OTHER_GUID)->id);
        if ($owner !== null) {
            $this->assertSame($owner->id, $resolver->resolve('corporate', self::GUID)->id);
        }
        $this->seeNumRecords($alreadyOwned ? 2 : 1, $this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }

    /**
     * @return iterable<string, array{string, bool, string}>
     */
    public static function provideRefusesUnsafeReplacement(): iterable
    {
        yield 'expected ID differs from directory' => [self::OTHER_GUID, false, 'directory_identity_changed'];

        yield 'verified ID is linked to another Shield user' => [self::GUID, true, 'identity_conflict'];
    }

    #[DataProvider('provideApplyRequiresASingleDirectoryMatch')]
    public function testApplyRequiresASingleDirectoryMatch(string $reason): void
    {
        $this->createUser('alice');
        $this->directory->expects($this->once())->method('lookupUser')->willThrowException(new LDAPException($reason));

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null]));
        $this->assertStringContainsString($reason, $this->getStreamFilterBuffer());
        $this->assertNoDirectoryLink();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideApplyRequiresASingleDirectoryMatch(): iterable
    {
        yield 'missing entry' => ['user_not_found'];

        yield 'ambiguous entry' => ['ambiguous_user'];
    }

    public function testApplyCannotOperateOnAllAccountsOrMatchAPartialLocalUsername(): void
    {
        $this->createUser('alice');
        $this->directory->expects($this->never())->method('lookupUser');

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'ali', 'apply' => null]));
        $this->assertNoDirectoryLink();
    }

    public function testReplaceRequiresApplyAndASingleUsername(): void
    {
        $this->createUser('alice');
        $this->directory->expects($this->never())->method('lookupUser');

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'replace' => self::GUID]));
        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'all' => null, 'apply' => null, 'replace' => self::GUID]));
        $this->assertNoDirectoryLink();
    }

    public function testApplyRejectsAConnectionWithCertificateVerificationDisabled(): void
    {
        $this->createUser('alice');
        $this->config->connections['corporate']['verifyCertificate'] = false;
        $this->directory->expects($this->never())->method('lookupUser');

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null]));
        $this->assertNoDirectoryLink();
    }

    public function testApplyRejectsAReservedLocalAccountById(): void
    {
        $user                        = $this->createUser('alice');
        $this->config->localAccounts = ['operator-alias' => $user->id];
        $this->directory->expects($this->never())->method('lookupUser');

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null]));
        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'alice', 'apply' => null, 'replace' => self::GUID]));
        $this->assertNoDirectoryLink();
    }

    private function createUser(string $username): User
    {
        $users = model(UserModel::class);
        $id    = $users->insert($users->createNewUser(['username' => $username, 'active' => true]));
        $user  = $users->findById($id);
        $this->assertInstanceOf(User::class, $user);

        return $user;
    }

    /**
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private function directoryEntry(string $objectGuid = "\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"): array
    {
        return [
            'dn'         => 'cn=Alice,ou=employees,dc=ad,dc=example,dc=test',
            'attributes' => [
                'samaccountname' => ['ALICE'],
                'objectguid'     => [$objectGuid],
            ],
        ];
    }

    private function assertNoDirectoryLink(): void
    {
        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }
}
