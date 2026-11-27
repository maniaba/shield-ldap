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

namespace Maniaba\ShieldLDAP\Tests\Controllers;

use CodeIgniter\Config\Factories;
use CodeIgniter\Email\Email;
use CodeIgniter\Shield\Authentication\Actions\Email2FA;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\FeatureTestTrait;
use Config\Services;
use Maniaba\ShieldLDAP\Authentication\Authenticators\LDAP;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @internal
 */
final class LDAPLoginTest extends DatabaseTestCase
{
    use FeatureTestTrait;

    protected $refresh = true;
    private User $user;
    private AuthLDAP $ldap;
    private LDAPDirectoryInterface&MockObject $directory;

    protected function setUp(): void
    {
        parent::setUp();

        $users = model(UserModel::class);
        $id    = $users->insert($users->createNewUser(['username' => 'local-user', 'active' => true]));
        $user  = $users->findById($id);
        $this->assertInstanceOf(User::class, $user);
        $this->user = $user;

        $auth                                    = config('Auth');
        $auth->authenticators['ldap']            = LDAP::class;
        $auth->sessionConfig['allowRemembering'] = false;

        $this->ldap                         = new AuthLDAP();
        $this->ldap->enabled                = true;
        $this->ldap->defaultConnection      = 'example';
        $this->ldap->connections['example'] = [
            'hosts'             => ['ldap.example.com'],
            'baseDn'            => 'dc=example,dc=com',
            'bindDn'            => 'cn=reader,dc=example,dc=com',
            'bindPassword'      => 'example-test-service-password',
            'profileAttributes' => ['username' => 'uid'],
            'provisionUsers'    => true,
        ];
        Factories::injectMock('config', 'AuthLDAP', $this->ldap);

        $this->directory = $this->createMock(LDAPDirectoryInterface::class);
        Services::injectMock('ldapDirectory', $this->directory);

        $routes = service('routes');
        auth()->routes($routes, ['except' => ['login']]);
        $routes->get('login', '\CodeIgniter\Shield\Controllers\LoginController::loginView', ['as' => 'login']);
        $routes->post('login', '\Maniaba\ShieldLDAP\Tests\Support\LDAP\LoginController::loginAction');
        Services::injectMock('routes', $routes);
    }

    public function testDirectoryLoginUsesShieldSessionAndDoesNotRememberPassword(): void
    {
        $this->directory->expects($this->once())->method('authenticate')->with(
            $this->isInstanceOf(LDAPConnection::class),
            $this->anything(),
            $this->anything(),
            $this->equalToCanonicalizing(['entryUUID', 'uid']),
        )->willReturn($this->entry(attributes: ['mail' => ['directory-user@example.com']]));

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $response->assertSessionMissing('error');
        $this->assertTrue(auth('session')->loggedIn());
        $user = auth('session')->user();
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame('directory-user', $user->username);
        $this->assertNull($user->getEmailIdentity());
        $this->seeInDatabase($this->tables['logins'], ['user_id' => $user->id, 'success' => 1]);
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $user->id]);
        $this->assertNull(session('_ci_old_input'));
    }

    public function testMappedDirectoryEmailSupportsShieldEmailMfaWithoutALocalPassword(): void
    {
        $address = 'directory-user@example.com';
        setting('Auth.allowMagicLinkLogins', false);
        config('Auth')->actions['login']                              = Email2FA::class;
        $this->ldap->connections['example']['emailIdentityAttribute'] = 'mail';

        $this->directory->expects($this->once())->method('authenticate')->with(
            $this->isInstanceOf(LDAPConnection::class),
            $this->anything(),
            $this->anything(),
            $this->equalToCanonicalizing(['entryUUID', 'uid', 'mail']),
        )->willReturn($this->entry(attributes: ['mail' => [$address]]));

        $mailer = $this->createMock(Email::class);
        $mailer->method('initialize')->willReturnSelf();
        $mailer->method('setFrom')->willReturnSelf();
        $mailer->expects($this->once())->method('setTo')->with($address)->willReturnSelf();
        $mailer->expects($this->once())->method('send')->with(false)->willReturn(true);
        Services::injectMock('email', $mailer);

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertRedirectTo(site_url('auth/a/show'));
        $this->assertFalse(auth('session')->loggedIn());
        $authenticator = auth('session')->getAuthenticator();
        $this->assertInstanceOf(Session::class, $authenticator);
        $user = $authenticator->getPendingUser();
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame($address, $user->email);
        $identity = $user->getEmailIdentity();
        $this->assertNotNull($identity);
        $this->assertSame(Session::ID_TYPE_EMAIL_PASSWORD, $identity->type);
        $this->assertNotSame('directory-secret', $identity->secret2);
        $this->assertFalse($authenticator->check(['email' => $address, 'password' => 'directory-secret'])->isOK());

        $response = $this->withSession(['user' => session('user')])->post('/auth/a/handle', ['email' => $address]);

        $response->assertStatus(200);
        $this->assertFalse(auth('session')->loggedIn());
        $code = model(UserIdentityModel::class)->getIdentityByType($user, Session::ID_TYPE_EMAIL_2FA);
        $this->assertNotNull($code);
        $response = $this->withSession(['user' => session('user')])->post('/auth/a/verify', ['token' => $code->secret]);

        $response->assertStatus(302);
        $this->assertSame($user->id, auth('session')->id());
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    #[DataProvider('provideInvalidMappedDirectoryEmailPreventsProvisioning')]
    public function testInvalidMappedDirectoryEmailPreventsProvisioning(array $attributes): void
    {
        setting('Auth.allowMagicLinkLogins', false);
        $this->ldap->connections['example']['emailIdentityAttribute'] = 'mail';
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry(attributes: $attributes));

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory-user']);
    }

    /**
     * @return iterable<array{array<string, list<string>>}>
     */
    public static function provideInvalidMappedDirectoryEmailPreventsProvisioning(): iterable
    {
        yield 'missing address' => [[]];

        yield 'multiple addresses' => [['mail' => ['directory-user@example.com', 'other@example.com']]];

        yield 'invalid address' => [['mail' => ['directory-user']]];
    }

    public function testMappedDirectoryEmailRequiresMagicLinksToBeDisabled(): void
    {
        config('Auth')->allowMagicLinkLogins = false;
        setting('Auth.allowMagicLinkLogins', true);
        $this->ldap->connections['example']['emailIdentityAttribute'] = 'mail';
        $this->directory->method('authenticate')->willReturn($this->entry(attributes: ['mail' => ['directory-user@example.com']]));

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory-user']);
    }

    public function testLinkedDirectoryAccountStillRequiresConfiguredLoginAction(): void
    {
        config('Auth')->actions['login'] = Email2FA::class;
        $this->user->createEmailIdentity(['email' => 'safe-contact@example.com', 'password' => 'local-password']);
        $this->user->addGroup('admin');
        (new LDAPUserResolver(auth()->getProvider()))->link('example', 'stable-id', $this->user->id);
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry($this->user->username));

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $this->assertSame(site_url('auth/a/show'), $response->getRedirectUrl());
        $authenticator = auth('session')->getAuthenticator();
        $this->assertSame(Session::class, $authenticator::class);
        $this->assertTrue($authenticator->isPending());
        $this->assertFalse(auth('session')->loggedIn());
        $this->assertTrue($authenticator->getPendingUser()->inGroup('admin'));
        $this->seeInDatabase($this->tables['identities'], [
            'user_id'      => $this->user->id,
            'type'         => LDAP::ID_TYPE_EMAIL_PASSWORD,
            'last_used_at' => null,
        ]);
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testReservedLocalAccountRequiresConfiguredMfaWithoutQueryingDirectory(): void
    {
        config('Auth')->actions['login'] = Email2FA::class;
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->ldap->localAccounts[$this->user->username] = $this->user->id;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', [
            'username' => strtoupper($this->user->username),
            'password' => 'local-password',
            'remember' => '1',
        ]);

        $response->assertStatus(302);
        $this->assertSame(site_url('auth/a/show'), $response->getRedirectUrl());
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $identity = model(UserIdentityModel::class)->getIdentityByType($this->user, Session::ID_TYPE_EMAIL_2FA);
        $this->assertNotNull($identity);
        $response = $this->withSession(['user' => session('user')])
            ->post('/auth/a/verify', ['token' => $identity->secret]);

        $response->assertStatus(302);
        $this->assertSame($this->user->id, auth('session')->id());
    }

    public function testReservedLocalAccountWithoutAnApplicableActionCannotSignIn(): void
    {
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->ldap->localAccounts[$this->user->username] = $this->user->id;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'local-password']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
    }

    public function testReservedUsernameWithNoMatchingLocalAccountFailsClosed(): void
    {
        $this->ldap->localAccounts['missing-operator'] = $this->user->id + 1000;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'missing-operator', 'password' => 'local-password']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
    }

    public function testReservedLocalAccountIdentifiersCannotDifferOnlyByCase(): void
    {
        $this->ldap->localAccounts = ['Operator' => 1, 'operator' => 2];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_configuration');

        auth('ldap')->getAuthenticator();
    }

    #[DataProvider('provideDirectoryFailureNeverFallsBackOrFlashesPassword')]
    public function testDirectoryFailureNeverFallsBackOrFlashesPassword(string $reason): void
    {
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->directory->expects($this->once())->method('authenticate')->willThrowException(new LDAPException($reason));

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'local-password']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $response->assertSessionMissing('_ci_old_input');
    }

    /**
     * @return iterable<list<string>>
     */
    public static function provideDirectoryFailureNeverFallsBackOrFlashesPassword(): iterable
    {
        yield ['invalid_credentials'];

        yield ['ambiguous_user'];

        yield ['tls_failed'];

        yield ['directory_unavailable'];

        yield ['ineligible_user'];
    }

    public function testEmptyPasswordFailsBeforeDirectoryAccess(): void
    {
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => '']);

        $response->assertStatus(302);
        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $response->assertSessionMissing('_ci_old_input');
    }

    public function testDisabledAuthenticatorFailsClosed(): void
    {
        $this->ldap->enabled = false;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
    }

    public function testUpnRoutesToNamedConnectionAndEscapesAssertionValue(): void
    {
        $this->ldap->connections['corporate'] = [
            'hosts'               => ['ad.example.com'],
            'baseDn'              => 'dc=ad,dc=example,dc=com',
            'bindDn'              => 'cn=reader,dc=ad,dc=example,dc=com',
            'bindPassword'        => 'corporate-test-service-password',
            'loginAttributes'     => ['sAMAccountName', 'userPrincipalName'],
            'externalIdAttribute' => 'objectGUID',
        ];
        $this->ldap->loginDomains['ad.example.com'] = 'corporate';
        $this->directory->expects($this->once())->method('authenticate')->with(
            $this->isInstanceOf(LDAPConnection::class),
            'dc=ad,dc=example,dc=com',
            '(&(objectClass=person)(|(sAMAccountName=a\28\2a\29@AD.EXAMPLE.COM)(userPrincipalName=a\28\2a\29@AD.EXAMPLE.COM)))',
            ['objectGUID'],
            'directory-secret',
            '(objectClass=*)',
        )->willReturnCallback(static function (LDAPConnection $connection): never {
            self::assertSame('corporate', $connection->id);
            self::assertSame(['ad.example.com'], $connection->hosts);
            self::assertSame('corporate-test-service-password', $connection->bindPassword());

            throw new LDAPException('user_not_found');
        });

        $response = $this->post('/login', ['username' => 'a(*)@AD.EXAMPLE.COM', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
    }

    public function testDirectoryGuidResolvesTheExplicitLinkAfterLoginRename(): void
    {
        $this->ldap->connections['example'] = [
            'hosts'               => ['ad.example.com'],
            'baseDn'              => 'dc=ad,dc=example,dc=com',
            'bindDn'              => 'cn=reader,dc=ad,dc=example,dc=com',
            'bindPassword'        => 'example-test-service-password',
            'loginAttributes'     => ['userPrincipalName'],
            'externalIdAttribute' => 'objectGUID',
        ];
        (new LDAPUserResolver(auth()->getProvider()))->link(
            'example',
            '00112233-4455-6677-8899-aabbccddeeff',
            $this->user->id,
        );
        $this->directory->expects($this->once())->method('authenticate')->willReturn([
            'dn'         => 'cn=New Name,dc=ad,dc=example,dc=com',
            'attributes' => ['objectguid' => ["\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"]],
        ]);

        $response = $this->post('/login', ['username' => 'renamed@ad.example.com', 'password' => 'directory-secret']);

        $response->assertSessionMissing('error');
        $this->assertSame($this->user->id, auth('session')->id());
    }

    /**
     * @param array<string, list<string>> $attributes
     *
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private function entry(string $uid = 'directory-user', array $attributes = []): array
    {
        return [
            'dn'         => 'uid=' . $uid . ',dc=example,dc=com',
            'attributes' => ['uid' => [$uid], 'entryuuid' => ['stable-id'], ...$attributes],
        ];
    }
}
