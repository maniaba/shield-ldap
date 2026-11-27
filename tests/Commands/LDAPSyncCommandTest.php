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
use CodeIgniter\Events\Events;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\StreamFilterTrait;
use Config\Services;
use Generator;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserEnumerationInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @internal
 */
final class LDAPSyncCommandTest extends DatabaseTestCase
{
    use StreamFilterTrait;

    private const COMMAND = 'shield:ldap-sync';

    protected $refresh = true;
    private AuthLDAP $config;
    private LDAPUserEnumerationInterface&MockObject $directory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->config              = new AuthLDAP();
        $this->config->connections = ['corporate' => [
            'hosts'              => ['ldap.example.test'],
            'baseDn'             => 'dc=example,dc=test',
            'bindDn'             => 'cn=reader,dc=example,dc=test',
            'bindPassword'       => 'test-bind-password',
            'userBaseDn'         => ['ou=people,dc=example,dc=test', 'ou=contractors,dc=example,dc=test'],
            'profileAttributes'  => ['username' => 'uid'],
            'provisionUsers'     => true,
            'syncProfileOnLogin' => false,
        ]];
        Factories::injectMock('config', 'AuthLDAP', $this->config);

        $this->directory = $this->createMock(LDAPUserEnumerationInterface::class);
        $this->directory->expects($this->never())->method('authenticate');
        Services::injectMock('ldapDirectory', $this->directory);
    }

    public function testPreviewAndApplyShareProvisioningAndProfilePolicies(): void
    {
        $users = auth()->getProvider();
        $id    = $users->insert(['username' => 'oldname', 'active' => true]);
        $user  = $users->findById($id);
        $this->assertNotNull($user);
        $user->createEmailIdentity(['email' => 'local@example.test', 'password' => 'local-test-password']);
        $user->addGroup('user');

        $resolver = new LDAPUserResolver($users);
        $resolver->link('corporate', 'existing-id', $id);

        $entries = [self::entry('alice', 'new-id'), self::entry('renamed', 'existing-id')];
        $this->directory->expects($this->exactly(2))->method('scanUsers')->with($this->isInstanceOf(LDAPConnection::class))->willReturn($entries);

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate']));
        $this->assertStringContainsString('would_create=1 would_update=1', $this->getStreamFilterBuffer());
        $this->assertNull($users->findByCredentials(['username' => 'alice']));
        $this->assertSame('oldname', $users->findById($id)?->username);

        $unexpectedEvent = static function (): void {
            self::fail('Administrative provisioning triggered a web authentication event.');
        };
        Events::on('register', $unexpectedEvent);
        Events::on('login', $unexpectedEvent);

        try {
            $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        } finally {
            Events::removeListener('register', $unexpectedEvent);
            Events::removeListener('login', $unexpectedEvent);
        }

        $this->assertStringContainsString('created=1 updated=1', $this->getStreamFilterBuffer());
        $this->assertSame('alice', $resolver->resolve('corporate', 'new-id')->username);
        $this->assertSame($id, $resolver->resolve('corporate', 'existing-id')->id);
        $updated = $users->findById($id);
        $this->assertSame('renamed', $updated->username);
        $this->assertTrue($updated->inGroup('user'));
        $identity = model(UserIdentityModel::class)->getIdentityByType($updated, Session::ID_TYPE_EMAIL_PASSWORD);
        $this->assertSame('local@example.test', $identity?->secret);
        $this->assertNotNull($identity->secret2);
        $this->assertTrue(password_verify('local-test-password', $identity->secret2));
    }

    public function testConflictWithUnlinkedLocalUsernameDoesNotWriteAnIdentity(): void
    {
        model(UserModel::class)->insert(['username' => 'alice', 'active' => true]);
        $this->directory->expects($this->once())->method('scanUsers')->willReturn([self::entry('alice', 'other-person')]);

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        $this->assertStringContainsString('conflicts=1', $this->getStreamFilterBuffer());
        $this->seeNumRecords(0, $this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }

    public function testDirectoryInterruptionAfterEntriesPreventsLocalWrites(): void
    {
        $this->directory->expects($this->once())->method('scanUsers')->willReturnCallback(function (): Generator {
            yield self::entry('alice', 'one');

            $this->seeNumRecords(0, $this->tables['users'], []);

            throw new LDAPException('incomplete_search');
        });

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        $this->assertStringContainsString('incomplete_search', $this->getStreamFilterBuffer());
        $this->seeNumRecords(0, $this->tables['users'], []);
    }

    public function testOverlappingBasesCountTheSameDirectoryEntryOnce(): void
    {
        $entry = self::entry('alice', 'one');
        $this->directory->expects($this->once())->method('scanUsers')->willReturn([$entry, $entry]);

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        $this->assertStringContainsString('created=1 updated=0 unchanged=0 skipped=0 conflicts=0', $this->getStreamFilterBuffer());
        $this->seeNumRecords(1, $this->tables['users'], []);
    }

    /**
     * @param list<array{dn: string, attributes: array<string, list<string>>}> $entries
     */
    #[DataProvider('provideAmbiguousDirectoryEntriesAreNotProvisioned')]
    public function testAmbiguousDirectoryEntriesAreNotProvisioned(array $entries, string $reason): void
    {
        $this->directory->expects($this->once())->method('scanUsers')->willReturn($entries);

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        $this->assertStringContainsString($reason, $this->getStreamFilterBuffer());
        $this->seeNumRecords(0, $this->tables['users'], []);
    }

    /**
     * @return iterable<string, array{list<array{dn: string, attributes: array<string, list<string>>}>, string}>
     */
    public static function provideAmbiguousDirectoryEntriesAreNotProvisioned(): iterable
    {
        yield 'duplicate immutable ID' => [[self::entry('alice', 'one'), self::entry('bob', 'one')], 'ambiguous_user'];

        yield 'duplicate local username' => [[self::entry('alice', 'one'), self::entry('Alice', 'two')], 'identity_conflict'];
    }

    public function testSyncRejectsUnverifiedConnectionBeforeReadingDirectory(): void
    {
        $this->config->connections['corporate']['verifyCertificate'] = false;
        $this->directory->expects($this->never())->method('scanUsers');

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'apply' => null]));
        $this->assertStringContainsString('tls_verification_required', $this->getStreamFilterBuffer());
    }

    /**
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private static function entry(string $username, string $externalId): array
    {
        return [
            'dn'         => 'uid=' . $username . ',ou=people,dc=example,dc=test',
            'attributes' => ['uid' => [$username], 'entryuuid' => [$externalId]],
        ];
    }
}
