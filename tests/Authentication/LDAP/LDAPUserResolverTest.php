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

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Config\Auth;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Config\Database;
use Config\Services;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testSynchronizedAddressUsesTheShieldEmailIdentityWithoutAllowingPasswordLogin(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);

        $user = $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true, email: 'Directory@Example.Test');

        $this->assertSame('directory@example.test', $user->email);
        $this->assertSame(Session::ID_TYPE_EMAIL_PASSWORD, $user->getEmailIdentity()?->type);
        $this->assertFalse((new Session($users))->check([
            'email'    => $user->email,
            'password' => 'directory-password',
        ])->isOK());
        $sameAddress = $resolver->resolve('corporate', 'immutable-object', email: 'DIRECTORY@example.test');
        $this->assertSame($user->getEmailIdentity()->id, $sameAddress->getEmailIdentity()?->id);

        $renamed = $resolver->resolve('corporate', 'immutable-object', email: 'Renamed@Example.Test');

        $this->assertSame($user->id, $renamed->id);
        $this->assertSame($user->getEmailIdentity()->id, $renamed->getEmailIdentity()?->id);
        $this->assertSame('renamed@example.test', $renamed->email);
        $this->assertSame($renamed->email, $resolver->resolve('corporate', 'immutable-object')->email);
        $this->seeNumRecords(1, $this->tables['identities'], [
            'user_id' => $user->id,
            'type'    => Session::ID_TYPE_EMAIL_PASSWORD,
        ]);
    }

    public function testDisabledProfileUpdatesLeaveTheEmailOnAnExistingAccount(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve(
            'corporate',
            'immutable-object',
            ['username' => 'directory'],
            true,
            updateProfile: false,
            email: 'original@example.test',
        );

        $this->assertSame('original@example.test', $user->email);
        $this->assertSame('original@example.test', $resolver->resolve(
            'corporate',
            'immutable-object',
            updateProfile: false,
            email: 'changed@example.test',
        )->email);
    }

    public function testEmailSyncCanBeEnabledForAnExistingDirectoryAccount(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true);

        $this->assertNull($user->email);

        $updated = $resolver->resolve('corporate', 'immutable-object', email: 'directory@example.test');

        $this->assertSame($user->id, $updated->id);
        $this->assertSame('directory@example.test', $updated->email);
    }

    public function testEmailCollisionIsCaseInsensitiveAndRollsBackProvisioning(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $localId  = $users->insert($users->createNewUser([
            'username' => 'local',
            'email'    => 'Existing@Example.Test',
            'password' => 'local-password',
        ]));

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true, email: 'existing@example.test');
            $this->fail('An address owned by another account was accepted.');
        } catch (LDAPException $exception) {
            $this->assertSame('identity_conflict', $exception->reason);
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory']);
        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
        $this->assertSame('Existing@Example.Test', $users->findById($localId)?->email);
    }

    public function testEmailSyncPreservesAnExistingLocalIdentity(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $userId   = $users->insert($users->createNewUser([
            'username' => 'local',
            'email'    => 'local@example.test',
            'password' => 'local-password',
        ]));
        $resolver->link('corporate', 'immutable-object', $userId);

        $user = $resolver->resolve('corporate', 'immutable-object', email: 'directory@example.test');

        $this->assertSame('local@example.test', $user->email);
        $this->assertTrue(password_verify('local-password', $user->password_hash));
        $this->seeNumRecords(1, $this->tables['identities'], [
            'user_id' => $userId,
            'type'    => Session::ID_TYPE_EMAIL_PASSWORD,
        ]);
    }

    public function testLocalEmailChangeTakesPrecedenceOverThePreviousDirectoryAddress(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true, email: 'original@example.test');

        $user->email = 'managed-locally@example.test';
        $users->save($user);

        $resolved = $resolver->resolve('corporate', 'immutable-object', email: 'changed@example.test');

        $this->assertSame('managed-locally@example.test', $resolved->email);
    }

    public function testAddingALocalPasswordStopsUpdatesToTheDirectoryAddress(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $users    = model(UserModel::class);
        $resolver = new LDAPUserResolver($users);
        $user     = $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true, email: 'original@example.test');

        $user->setPassword('local-password');
        $users->save($user);

        $resolved = $resolver->resolve('corporate', 'immutable-object', email: 'changed@example.test');

        $this->assertSame('original@example.test', $resolved->email);
        $this->assertTrue(password_verify('local-password', $resolved->password_hash));
    }

    public function testASecondLinkedDirectoryCannotChangeTheSynchronizedAddress(): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $resolver = new LDAPUserResolver(model(UserModel::class));
        $user     = $resolver->resolve('corporate', 'shared-id', ['username' => 'directory'], true, email: 'corporate@example.test');
        $resolver->link('partner', 'shared-id', $user->id);

        $this->assertSame('corporate@example.test', $resolver->resolve('partner', 'shared-id', email: 'partner@example.test')->email);
        $this->assertSame('renamed@example.test', $resolver->resolve('corporate', 'shared-id', email: 'renamed@example.test')->email);
    }

    #[DataProvider('provideInvalidDirectoryAddressCannotBeStored')]
    public function testInvalidDirectoryAddressCannotBeStored(string $email): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $resolver = new LDAPUserResolver(model(UserModel::class));

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_profile');

        $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true, email: $email);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidDirectoryAddressCannotBeStored(): iterable
    {
        yield 'address list' => ['one@example.test,two@example.test'];

        yield 'header injection' => ["one@example.test\r\nBcc: two@example.test"];

        yield 'over storage limit' => ['one@' . str_repeat(str_repeat('a', 60) . '.', 4) . 'example.test'];
    }

    public function testMagicLinkConfigurationRejectsDirectoryEmailSync(): void
    {
        setting('Auth.allowMagicLinkLogins', true);
        $resolver = new LDAPUserResolver(model(UserModel::class));

        try {
            $resolver->resolve('corporate', 'immutable-object', ['username' => 'directory'], true, email: 'directory@example.test');
            $this->fail('The address would also enable magic-link login.');
        } catch (LDAPException $exception) {
            $this->assertSame('invalid_configuration', $exception->reason);
        }

        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory']);
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
}
