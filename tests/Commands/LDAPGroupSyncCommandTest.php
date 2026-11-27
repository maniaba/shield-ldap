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
use CodeIgniter\Test\StreamFilterTrait;
use Config\Services;
use Generator;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPGroupEnumerationInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @internal
 */
final class LDAPGroupSyncCommandTest extends DatabaseTestCase
{
    use StreamFilterTrait;

    private const COMMAND = 'shield:ldap-sync';

    protected $refresh   = true;
    protected $namespace = ['\\CodeIgniter\\Shield', '\\Maniaba\\ShieldLDAP'];
    private LDAPGroupEnumerationInterface&MockObject $directory;

    protected function setUp(): void
    {
        parent::setUp();

        $config              = new AuthLDAP();
        $config->connections = ['corporate' => [
            'hosts'             => ['ldap.example.test'],
            'baseDn'            => 'dc=example,dc=test',
            'bindDn'            => 'cn=reader,dc=example,dc=test',
            'bindPassword'      => 'test-bind-password',
            'profileAttributes' => ['username' => 'uid'],
            'provisionUsers'    => true,
            'groupMappings'     => ['developer' => 'cn=developers,dc=example,dc=test'],
        ]];
        Factories::injectMock('config', 'AuthLDAP', $config);
        $this->directory = $this->createMock(LDAPGroupEnumerationInterface::class);
        $this->directory->expects($this->never())->method('authenticate');
        Services::injectMock('ldapDirectory', $this->directory);
    }

    public function testPreviewAndApplyChangeOnlyMappedGroupGrants(): void
    {
        $users = auth()->getProvider();
        $id    = $users->insert(['username' => 'existing', 'active' => true]);
        $user  = $users->findById($id);
        $this->assertNotNull($user);
        $user->addGroup('beta');
        (new LDAPUserResolver($users))->link('corporate', 'linked', $id);

        $member = self::entry('linked', ['developer']);
        $this->directory->expects($this->exactly(3))->method('scanGroupMemberships')->willReturnOnConsecutiveCalls(
            [$member, self::entry('unlinked', ['developer'])],
            [$member, $member, self::entry('unlinked', ['developer'])],
            [self::entry('linked', [])],
        );
        $preview = ['corporate', 'groups-only' => null];
        $apply   = $preview + ['apply' => null];

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, $preview));
        $this->assertStringContainsString('would_update=1 unchanged=0 skipped=1', $this->getStreamFilterBuffer());
        $this->dontSeeInDatabase($this->tables['groups_users'], ['user_id' => $id, 'group' => 'developer']);

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, $apply));
        $this->assertStringContainsString('updated=1 unchanged=0 skipped=1', $this->getStreamFilterBuffer());
        $this->seeNumRecords(1, $this->tables['groups_users'], ['user_id' => $id, 'group' => 'developer']);
        $this->seeNumRecords(1, $this->tables['users'], []);
        $this->assertSame('existing', $users->findById($id)?->username);

        $this->assertSame(EXIT_SUCCESS, service('commands')->run(self::COMMAND, $apply));
        $this->dontSeeInDatabase($this->tables['groups_users'], ['user_id' => $id, 'group' => 'developer']);
        $this->seeNumRecords(1, $this->tables['groups_users'], ['user_id' => $id, 'group' => 'beta']);
    }

    public function testIncompleteScanLeavesPreviouslyGrantedMembershipInPlace(): void
    {
        $users    = auth()->getProvider();
        $id       = $users->insert(['username' => 'existing', 'active' => true]);
        $resolver = new LDAPUserResolver($users);
        $resolver->link('corporate', 'linked', $id);
        $resolver->resolve('corporate', 'linked', groups: ['developer']);
        $this->directory->expects($this->once())->method('scanGroupMemberships')->willReturnCallback(static function (): Generator {
            yield self::entry('linked', []);

            throw new LDAPException(LDAPReason::IncompleteSearch);
        });

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'groups-only' => null, 'apply' => null]));
        $this->assertStringContainsString('incomplete_search', $this->getStreamFilterBuffer());
        $this->seeNumRecords(1, $this->tables['groups_users'], ['user_id' => $id, 'group' => 'developer']);
    }

    public function testRejectsMultipleEligibleIdentitiesLinkedToTheSameUser(): void
    {
        $users    = auth()->getProvider();
        $id       = $users->insert(['username' => 'existing', 'active' => true]);
        $resolver = new LDAPUserResolver($users);
        $resolver->link('corporate', 'first', $id);
        $resolver->link('corporate', 'second', $id);
        $this->directory->expects($this->once())->method('scanGroupMemberships')->willReturn([
            self::entry('first', ['developer']),
            self::entry('second', []),
        ]);

        $this->assertSame(EXIT_ERROR, service('commands')->run(self::COMMAND, ['corporate', 'groups-only' => null, 'apply' => null]));
        $this->assertStringContainsString('identity_conflict', $this->getStreamFilterBuffer());
        $this->dontSeeInDatabase($this->tables['groups_users'], ['user_id' => $id, 'group' => 'developer']);
    }

    /**
     * @param list<string> $groups
     *
     * @return array{dn: string, attributes: array<string, list<string>>, matchedGroups: list<string>}
     */
    private static function entry(string $id, array $groups): array
    {
        return [
            'dn'            => 'uid=' . $id . ',dc=example,dc=test',
            'attributes'    => ['entryuuid' => [$id], 'uid' => ['directory-' . $id]],
            'matchedGroups' => $groups,
        ];
    }
}
