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

namespace Maniaba\ShieldLDAP\Tests\Commands;

use CodeIgniter\Config\Factories;
use CodeIgniter\Shield\Entities\User;
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

    private const COMMAND    = 'shield:ldap-link';
    private const GUID       = '00112233-4455-6677-8899-aabbccddeeff';
    private const OTHER_GUID = 'ffeeddcc-bbaa-9988-7766-554433221100';
    private const USER_BASES = ['ou=employees,dc=ad,dc=example,dc=test', 'ou=contractors,dc=ad,dc=example,dc=test'];

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
    private function directoryEntry(): array
    {
        return [
            'dn'         => 'cn=Alice,ou=employees,dc=ad,dc=example,dc=test',
            'attributes' => [
                'samaccountname' => ['ALICE'],
                'objectguid'     => ["\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"],
            ],
        ];
    }

    private function assertNoDirectoryLink(): void
    {
        $this->dontSeeInDatabase($this->tables['identities'], ['type' => LDAPUserResolver::ID_TYPE]);
    }
}
