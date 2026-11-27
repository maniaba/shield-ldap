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

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Authentication\Actions\EmailActivator;
use CodeIgniter\Shield\Config\Auth;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Config\Database;
use Config\Services;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;
use RuntimeException;

/**
 * @internal
 */
final class LDAPUserResolverTest extends DatabaseTestCase
{
    protected $refresh = true;

    public function testProvisioningStoresOnlyTheStableDirectoryIdentity(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);

        $user = $resolver->resolve('corporate', 'immutable-object', ['username' => 'DirUser'], true);

        $this->assertSame('diruser', $user->username);
        $this->assertNull($user->email);
        $this->assertNull($user->password_hash);

        $this->seeInDatabase($this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => LDAPUserResolver::ID_TYPE,
            'name'    => 'corporate',
            'secret'  => hash('sha256', "corporate\0immutable-object"),
            'secret2' => null,
        ]);
        $this->seeNumRecords(1, $this->tables['identities'], ['user_id' => $user->id]);
    }

    public function testEntryRenameChangesOnlyTheConfiguredProfile(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'original'], true);

        $users->update($user->id, ['status_message' => 'Local account note']);

        $this->assertSame('original', $resolver->resolve(
            'corporate',
            'immutable-object',
            ['username' => 'renamed'],
            updateProfile: false,
        )->username);

        $renamed = $resolver->resolve('corporate', 'immutable-object', ['username' => 'renamed']);

        $this->assertSame($user->id, $renamed->id);
        $this->assertSame('renamed', $renamed->username);
        $this->assertSame('Local account note', $renamed->status_message);
        $this->seeNumRecords(1, $this->tables['identities'], ['user_id' => $user->id]);
    }

    public function testUsernameCollisionDoesNotLinkToLocalAccount(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);

        $userId = $users->insert(['username' => 'Existing']);

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'existing'], true);
            $this->fail('A colliding username was accepted.');
        } catch (LDAPException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->seeNumRecords(1, $this->tables['users'], ['id' => $userId]);
        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }

    public function testCustomProviderCanSynchronizeAWritableProfileColumn(): void
    {
        $users = new class () extends UserModel {
            protected $allowedFields = ['username', 'first_name'];
        };

        $forge = Database::forge($users->builder()->db());
        $this->assertTrue($forge->addColumn($this->tables['users'], [
            'first_name' => ['type' => 'varchar', 'constraint' => 100, 'null' => true],
        ]));

        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', [
            'username'   => 'directory',
            'first_name' => 'Initial',
        ], true);
        $changed = $resolver->resolve('corporate', 'immutable-object', ['first_name' => 'Updated']);

        $this->assertSame($user->id, $changed->id);
        $this->assertSame('Updated', $changed->first_name);
        $this->assertSame('directory', $changed->username);
    }

    public function testConnectionScopesExternalIdentity(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));

        $corporate = $resolver->resolve('corporate', 'shared-id', ['username' => 'corporate.user'], true);
        $partner   = $resolver->resolve('partner', 'shared-id', ['username' => 'partner.user'], true);

        $this->assertNotSame($corporate->id, $partner->id);
        $this->assertSame($corporate->id, $resolver->resolve('corporate', 'shared-id')->id);
        $this->assertSame($partner->id, $resolver->resolve('partner', 'shared-id')->id);
    }

    public function testExplicitLinkIsIdempotentAndPreservesTheLocalPassword(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);

        $userId = $users->insert($users->createNewUser([
            'username' => 'existing',
            'email'    => 'existing@example.test',
            'password' => 'local-password',
        ]));
        $user = $users->findById($userId);

        $resolver->link('corporate', 'immutable-object', $userId);
        $resolver->link('corporate', 'immutable-object', $userId);
        $resolved = $resolver->resolve('corporate', 'immutable-object');

        $this->assertSame($user->id, $resolved->id);
        $this->assertSame($user->email, $resolved->email);
        $this->assertSame($user->password_hash, $resolved->password_hash);
        $this->assertTrue(password_verify('local-password', $resolved->password_hash));
        $this->seeNumRecords(1, $this->tables['identities'], [
            'user_id' => $userId,
            'type'    => LDAPUserResolver::ID_TYPE,
        ]);
    }

    public function testSynchronizationPreviewAndApplyProvisionTheSameStableIdentity(): void
    {
        $resolver   = new LDAPUserResolver(model(UserModel::class));
        $connection = $this->syncConnection();
        $profile    = ['username' => 'Directory.User'];

        $this->assertSame('create', $resolver->synchronize($connection, 'immutable-id', $profile, [], false));
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory.user']);
        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);

        $this->assertSame('create', $resolver->synchronize($connection, 'immutable-id', $profile, [], true));
        $user = $resolver->resolve('corporate', 'immutable-id');
        $this->assertSame('directory.user', $user->username);
        $this->assertNull($user->password_hash);
        $this->assertSame('unchanged', $resolver->synchronize($connection, 'immutable-id', $profile, [], true));
        $this->seeNumRecords(1, $this->tables['identities'], ['user_id' => $user->id, 'type' => LDAPUserResolver::ID_TYPE]);
    }

    public function testSynchronizationUpdatesTheLinkedUserAndPreservesLocalCredentialsAndGroups(): void
    {
        $users      = model(UserModel::class);
        $resolver   = new LDAPUserResolver($users);
        $connection = $this->syncConnection(provisionUsers: false);
        $userId     = $users->insert($users->createNewUser([
            'username' => 'original',
            'email'    => 'local@example.test',
            'password' => 'local-password',
        ]));
        $user = $resolver->link('corporate', 'immutable-id', $userId);
        $user->addGroup('admin');

        $this->assertSame('update', $resolver->synchronize($connection, 'immutable-id', ['username' => 'renamed'], [], false));
        $this->assertSame('original', $resolver->resolve('corporate', 'immutable-id')->username);
        $this->assertSame('update', $resolver->synchronize($connection, 'immutable-id', ['username' => 'renamed'], [], true));
        $updated = $resolver->resolve('corporate', 'immutable-id');

        $this->assertSame($userId, $updated->id);
        $this->assertSame('renamed', $updated->username);
        $this->assertSame('local@example.test', $updated->email);
        $this->assertTrue(password_verify('local-password', $updated->password_hash));
        $this->assertSame(['admin'], $updated->getGroups());
    }

    public function testSynchronizationHonorsConnectionProvisioningAndUpdatePolicies(): void
    {
        $resolver   = new LDAPUserResolver(model(UserModel::class));
        $connection = $this->syncConnection(provisionUsers: false, updateProfile: false);
        $resolver->resolve('corporate', 'linked-id', ['username' => 'original'], true);

        $this->assertSame('skipped', $resolver->synchronize($connection, 'unlinked-id', ['username' => 'unlinked'], [], true));
        $this->assertSame('skipped', $resolver->synchronize($connection, 'linked-id', ['username' => 'renamed'], [], true));
        $this->assertSame('original', $resolver->resolve('corporate', 'linked-id')->username);
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'unlinked']);
    }

    public function testSynchronizationSkipsReservedLocalIdsAndDirectoryUsernames(): void
    {
        $resolver   = new LDAPUserResolver(model(UserModel::class));
        $connection = $this->syncConnection();
        $local      = $resolver->resolve('corporate', 'local-id', ['username' => 'local'], true);
        $regular    = $resolver->resolve('corporate', 'regular-id', ['username' => 'regular'], true);
        $reserved   = ['emergency' => $local->id];

        $this->assertSame('skipped', $resolver->synchronize($connection, 'local-id', ['username' => 'attempted'], $reserved, true));
        $this->assertSame('skipped', $resolver->synchronize($connection, 'regular-id', ['username' => 'Emergency'], $reserved, true));
        $this->assertSame('skipped', $resolver->synchronize($connection, 'new-id', ['username' => 'Emergency'], $reserved, true));
        $this->assertSame('local', $resolver->resolve('corporate', 'local-id')->username);
        $this->assertSame($regular->username, $resolver->resolve('corporate', 'regular-id')->username);
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'emergency']);
    }

    public function testSynchronizationLeavesBannedAndInactiveUsersUnchanged(): void
    {
        $users      = model(UserModel::class);
        $resolver   = new LDAPUserResolver($users);
        $connection = $this->syncConnection();
        $banned     = $resolver->resolve('corporate', 'banned-id', ['username' => 'banned'], true);
        $resolver->resolve('corporate', 'inactive-id', ['username' => 'inactive'], true);
        $users->update($banned->id, ['status' => 'banned', 'active' => true]);

        $auth                      = config(Auth::class);
        $auth->actions['register'] = EmailActivator::class;

        $this->assertSame('skipped', $resolver->synchronize($connection, 'banned-id', ['username' => 'renamed'], [], true));
        $this->assertSame('skipped', $resolver->synchronize($connection, 'inactive-id', ['username' => 'renamed'], [], true));
        $this->assertTrue($resolver->resolve('corporate', 'banned-id')->isBanned());
        $this->assertFalse($resolver->resolve('corporate', 'inactive-id')->isActivated());
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'renamed']);
    }

    public function testSynchronizationRejectsAnUnlinkedLocalUsernameInPreviewAndOnApply(): void
    {
        $users      = model(UserModel::class);
        $resolver   = new LDAPUserResolver($users);
        $connection = $this->syncConnection();
        $users->insert(['username' => 'Existing']);

        foreach ([false, true] as $apply) {
            try {
                $resolver->synchronize($connection, 'immutable-id', ['username' => 'existing'], [], $apply);
                $this->fail('A colliding username was accepted.');
            } catch (LDAPException $exception) {
                $this->assertSame('identity_conflict', $exception->reason);
            }
        }

        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }

    public function testSynchronizationPreviewRejectsAnUnwritableProfileField(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_profile');

        $resolver->synchronize($this->syncConnection(), 'immutable-id', [
            'username'   => 'directory',
            'first_name' => 'First',
        ], [], false);
    }

    public function testCannotMoveAnExistingDirectoryIdentityToAnotherUser(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true);
        $otherId  = $users->insert(['username' => 'another']);

        try {
            $resolver->link('corporate', 'immutable-object', $otherId);
            $this->fail('A linked identity was reassigned.');
        } catch (LDAPException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->assertSame($user->id, $resolver->resolve('corporate', 'immutable-object')->id);
    }

    public function testInspectLinkReportsTheStateOfTheSelectedConnection(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve('partner', 'partner-id', ['username' => 'existing'], true);

        $this->assertSame('candidate', $resolver->inspectLink($user, 'corporate', 'old-id'));

        $resolver->link('corporate', 'old-id', $user->id);

        $this->assertSame('already_linked', $resolver->inspectLink($user, 'corporate', 'old-id'));
        $this->assertSame('stale_link', $resolver->inspectLink($user, 'corporate', 'new-id'));
    }

    public function testReplaceLinkUpdatesOnlyTheSelectedIdentityAndIsIdempotent(): void
    {
        $users      = model(UserModel::class);
        $identities = model(UserIdentityModel::class);
        $resolver   = new LDAPUserResolver($users, $identities);
        $userId     = $users->insert($users->createNewUser([
            'username' => 'existing',
            'email'    => 'existing@example.test',
            'password' => 'local-password',
        ]));
        $resolver->link('partner', 'partner-id', $userId);
        $resolver->link('corporate', 'old-id', $userId);
        $oldKey = hash('sha256', "corporate\0old-id");
        $old    = $identities->getIdentityBySecret(LDAPUserResolver::ID_TYPE, $oldKey);
        $this->assertInstanceOf(UserIdentity::class, $old);
        $identities->update($old->id, new UserIdentity(['extra' => 'Local metadata']));

        $this->assertTrue($resolver->replaceLink('corporate', 'new-id', $userId, 'existing'));
        $this->assertFalse($resolver->replaceLink('corporate', 'new-id', $userId, 'existing'));
        $this->assertNull($identities->getIdentityBySecret(LDAPUserResolver::ID_TYPE, $oldKey));

        $updated = $identities->find($old->id);
        $this->assertInstanceOf(UserIdentity::class, $updated);
        $this->assertSame(hash('sha256', "corporate\0new-id"), $updated->secret);
        $this->assertSame('Local metadata', $updated->extra);
        $this->assertSame($userId, $resolver->resolve('partner', 'partner-id')->id);

        $resolved = $resolver->resolve('corporate', 'new-id');
        $this->assertSame($userId, $resolved->id);
        $this->assertSame('existing@example.test', $resolved->email);
        $this->assertTrue(password_verify('local-password', $resolved->password_hash));
        $this->seeNumRecords(3, $this->tables['identities'], ['user_id' => $userId]);
    }

    public function testCannotReplaceMissingLink(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve('partner', 'partner-id', ['username' => 'existing'], true);

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('identity_conflict');

        $resolver->replaceLink('corporate', 'new-id', $user->id, 'existing');
    }

    public function testCannotReplaceLinkAfterLocalUsernameChanges(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'old-id', ['username' => 'existing'], true);
        $users->update($user->id, ['username' => 'renamed']);

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('identity_conflict');

        $resolver->replaceLink('corporate', 'new-id', $user->id, 'existing');
    }

    public function testCannotInspectOrReplaceAnAmbiguousLink(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve('corporate', 'old-id', ['username' => 'existing'], true);
        $resolver->link('corporate', 'new-id', $user->id);

        try {
            $resolver->inspectLink($user, 'corporate', 'new-id');
            $this->fail('A user with multiple links for the connection was accepted.');
        } catch (LDAPException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('identity_conflict');

        $resolver->replaceLink('corporate', 'new-id', $user->id, 'existing');
    }

    public function testCannotReplaceLinkWithAnIdentifierOwnedByAnotherUser(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve('corporate', 'old-id', ['username' => 'existing'], true);
        $another  = $resolver->resolve('corporate', 'new-id', ['username' => 'another'], true);

        try {
            $resolver->replaceLink('corporate', 'new-id', $user->id, 'existing');
            $this->fail('A link was replaced using a directory identifier owned by another user.');
        } catch (LDAPException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->assertSame($user->id, $resolver->resolve('corporate', 'old-id')->id);
        $this->assertSame($another->id, $resolver->resolve('corporate', 'new-id')->id);
    }

    public function testReplacementDetectsAChangedSecretBeforeWrite(): void
    {
        $users      = model(UserModel::class);
        $identities = model(UserIdentityModel::class);
        $resolver   = new LDAPUserResolver($users, $identities);
        $user       = $resolver->resolve('corporate', 'current-id', ['username' => 'existing'], true);

        $staleRead = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['getIdentitiesByTypes'])->getMock();
        $staleRead->expects($this->once())->method('getIdentitiesByTypes')->willReturnCallback(
            static function (User $user, array $types) use ($identities): array {
                $links            = $identities->getIdentitiesByTypes($user, $types);
                $links[0]->secret = hash('sha256', "corporate\0outdated-id");

                return $links;
            },
        );

        try {
            (new LDAPUserResolver($users, $staleRead))->replaceLink('corporate', 'new-id', $user->id, 'existing');
            $this->fail('The replacement overwrote a link changed since the read.');
        } catch (LDAPException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
        }

        $this->assertSame($user->id, $resolver->resolve('corporate', 'current-id')->id);
    }

    public function testReplacementRollsBackWhenTheUpdatedIdentityCannotBeRead(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'old-id', ['username' => 'existing'], true);
        $noRead   = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['getIdentityBySecret'])->getMock();
        $noRead->expects($this->exactly(2))->method('getIdentityBySecret')->willReturn(null);

        try {
            (new LDAPUserResolver($users, $noRead))->replaceLink('corporate', 'new-id', $user->id, 'existing');
            $this->fail('The replacement succeeded with no corresponding identity.');
        } catch (LDAPException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
        }

        $this->assertSame($user->id, $resolver->resolve('corporate', 'old-id')->id);
    }

    public function testUnlinkedUserIsRejectedWhenProvisioningIsOff(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('user_not_provisioned');

        $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory']);
    }

    public function testProvisioningRollsBackWhenIdentityCannotBeStored(): void
    {
        $identities = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['create'])->getMock();
        $identities->expects($this->once())->method('create')->willThrowException(new RuntimeException('private data'));
        $resolver = new LDAPUserResolver(model(UserModel::class), $identities);

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'rolledback'], true);
            $this->fail('Provisioning succeeded without recording an identity.');
        } catch (LDAPException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
            $this->assertNull($exception->getPrevious());
            $this->assertStringNotContainsString('private data', $exception->getMessage());
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'rolledback']);
    }

    public function testFailedDirectoryWriteDoesNotPoisonTheSharedConnection(): void
    {
        $users      = model(UserModel::class);
        $identities = model(UserIdentityModel::class);
        $failed     = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['create'])->getMock();
        $failed->expects($this->once())->method('create')->willReturnCallback(static function (UserIdentity $identity) use ($identities): void {
            $identities->create($identity);
            $identities->create($identity);
        });

        $resolver = new LDAPUserResolver($users, $failed);

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'rolledback'], true);
            $this->fail('A duplicate LDAP identity was stored.');
        } catch (LDAPException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'rolledback']);
        $this->assertTrue($users->builder()->db()->transStrict);

        $resolved = (new LDAPUserResolver($users))->resolve('corporate', 'immutable-object', ['username' => 'retried'], true);

        $this->assertSame('retried', $resolved->username);
    }

    public function testConcurrentProvisioningKeepsOneUserAndDirectoryIdentity(): void
    {
        if (! extension_loaded('sqlite3')) {
            $this->markTestSkipped('The setup for overlapping transactions requires SQLite3.');
        }

        $file = tmpfile();
        $this->assertIsResource($file);

        $original = config(Database::class);
        $config   = new class () extends Database {
            /**
             * @var array<string, mixed>
             */
            public array $ldapProvisioningFirst = [];

            /**
             * @var array<string, mixed>
             */
            public array $ldapProvisioningSecond = [];
        };
        $config->ldapProvisioningFirst = $config->ldapProvisioningSecond = [
            'DBDriver' => 'SQLite3',
            'database' => stream_get_meta_data($file)['uri'],
            'DBDebug'  => false,
        ];

        Factories::injectMock('config', Database::class, $config);

        $auth          = config(Auth::class);
        $originalGroup = $auth->DBGroup;
        $first         = Database::connect('ldapProvisioningFirst');
        $second        = Database::connect('ldapProvisioningSecond');

        try {
            $mode = $first->query('PRAGMA journal_mode = WAL');
            $this->assertNotFalse($mode);
            $this->assertSame('wal', $mode->getRowArray()['journal_mode']);

            $auth->DBGroup = 'ldapProvisioningFirst';
            $migrations    = Services::migrations(db: $first, getShared: false);
            $this->assertTrue($migrations->setNamespace('CodeIgniter\Shield')->latest($auth->DBGroup));

            $users       = new UserModel();
            $identities  = new UserIdentityModel();
            $firstLookup = $this->getMockBuilder(UserIdentityModel::class)->onlyMethods(['getIdentityBySecret'])->getMock();

            $auth->DBGroup = 'ldapProvisioningSecond';
            $concurrent    = new LDAPUserResolver(new UserModel(), new UserIdentityModel());
            $profile       = ['username' => 'directory.user'];
            $winner        = null;

            $firstLookup->expects($this->once())->method('getIdentityBySecret')->willReturnCallback(
                static function (string $type, ?string $secret) use ($identities, $concurrent, $profile, &$winner): ?UserIdentity {
                    // The first transaction's snapshot contains no link. Commit the
                    // competing login before the first transaction tries its write.
                    $identity = $identities->getIdentityBySecret($type, $secret);
                    $winner   = $concurrent->resolve('corporate', 'immutable-object', $profile, true);

                    return $identity;
                },
            );

            try {
                (new LDAPUserResolver($users, $firstLookup))->resolve('corporate', 'immutable-object', $profile, true);
                $this->fail('Both concurrent attempts provisioned the same directory identity.');
            } catch (LDAPException $exception) {
                $this->assertSame('synchronization_conflict', $exception->reason);
            }

            $this->assertNotNull($winner);
            $retried = (new LDAPUserResolver($users, $identities))->resolve('corporate', 'immutable-object', $profile, true);
            $this->assertSame($winner->id, $retried->id);
            $this->assertSame(1, $first->table($this->tables['users'])->countAllResults());
            $this->assertSame(1, $first->table($this->tables['identities'])->countAllResults());
        } finally {
            $auth->DBGroup = $originalGroup;
            Factories::injectMock('config', Database::class, $original);
            $first->close();
            $second->close();
            fclose($file);
        }
    }

    public function testProfileCannotOverwriteLocalEmailOrPassword(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_profile');

        $resolver->resolve('corporate', 'immutable-object', [
            'username' => 'directory',
            'email'    => 'directory@example.test',
        ], true);
    }

    public function testUnwritableProfileFieldRollsBackProvisioning(): void
    {
        $resolver = new LDAPUserResolver(model(UserModel::class));

        try {
            $resolver->resolve('corporate', 'immutable-object', [
                'username'   => 'directory',
                'first_name' => 'First',
            ], true);
            $this->fail('The unmapped profile field was silently ignored.');
        } catch (LDAPException $exception) {
            $this->assertSame('invalid_profile', $exception->reason);
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory']);
    }

    public function testProvisioningDoesNotJoinAnExistingTransaction(): void
    {
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $database = $users->builder()->db();

        $this->assertTrue($database->transBegin());

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true);
            $this->fail('The resolver joined the active transaction.');
        } catch (LDAPException $exception) {
            $this->assertSame('synchronization_conflict', $exception->reason);
        } finally {
            $this->assertTrue($database->transRollback());
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory']);
    }

    public function testActiveDirectoryGuidUsesCanonicalByteOrder(): void
    {
        $bytes = hex2bin('785634123412cdab891023456789abcd');

        $this->assertSame('12345678-1234-abcd-8910-23456789abcd', LDAPUserResolver::normalizeObjectGuid($bytes));
    }

    private function syncConnection(bool $provisionUsers = true, bool $updateProfile = true): LDAPConnection
    {
        return new LDAPConnection(
            id: 'corporate',
            hosts: ['directory.example.test'],
            baseDn: 'dc=example,dc=test',
            bindDn: 'cn=reader,dc=example,dc=test',
            bindPassword: 'test-secret',
            provisionUsers: $provisionUsers,
            updateProfile: $updateProfile,
        );
    }
}
