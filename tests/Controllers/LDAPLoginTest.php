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

namespace Maniaba\ShieldLDAP\Tests\Controllers;

use CodeIgniter\Config\Factories;
use CodeIgniter\Cookie\Cookie;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\Shield\Authentication\Actions\Email2FA;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Authentication\Passwords;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Test\FeatureTestTrait;
use Config\Services;
use Maniaba\ShieldLDAP\Authentication\Authenticators\LDAP;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Authentication\LDAP\MultiBaseLDAPDirectoryInterface;
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
        $this->directory->expects($this->once())->method('authenticate')->with($this->isInstanceOf(LDAPConnection::class), 'dc=example,dc=com')->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $response->assertCookieMissing('remember');
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

    public function testDirectoryLoginGrantsMappedGroupsFromTheSelectedConnection(): void
    {
        setting('AuthGroups.defaultGroup', 'beta');
        $mappings = [
            'user'       => 'cn=users,ou=groups,dc=example,dc=com',
            'developer'  => 'cn=developers,ou=groups,dc=example,dc=com',
            'superadmin' => 'cn=senior-admins,ou=groups,dc=example,dc=com',
        ];
        $this->ldap->connections['example']['groupMappings'] = ['admin' => 'cn=admins,dc=example,dc=com'];
        $this->ldap->connections['research']                 = ['groupMappings' => $mappings] + $this->ldap->connections['example'];
        $this->ldap->loginDomains['research.example.com']    = 'research';
        $this->directory->expects($this->once())->method('authenticate')->willReturnCallback(
            function (LDAPConnection $connection) use ($mappings): array {
                $this->assertSame('research', $connection->id);
                $this->assertSame($mappings, $connection->groupMappings);

                return $this->entry() + ['matchedGroups' => ['user', 'developer']];
            },
        );

        $response = $this->post('/login', ['username' => 'directory-user@research.example.com', 'password' => 'directory-secret']);

        $response->assertSessionMissing('error');
        $user = auth('session')->user();
        $this->assertInstanceOf(User::class, $user);
        $this->assertTrue($user->inGroup('user'));
        $this->assertTrue($user->inGroup('developer'));
        $this->assertTrue($user->inGroup('beta'));
        $this->assertFalse($user->inGroup('admin', 'superadmin'));
        $this->seeNumRecords(3, $this->tables['groups_users'], ['user_id' => $user->id]);
    }

    public function testDirectoryChecksAddGroupsToALinkedUserWithoutRemovingOrDuplicatingMemberships(): void
    {
        $this->user->addGroup('beta');
        $this->ldap->connections['example']['groupMappings']  = ['developer' => 'cn=developers,dc=example,dc=com'];
        $this->ldap->connections['example']['provisionUsers'] = false;
        $this->ldap->connections['example']['updateProfile']  = false;
        (new LDAPUserResolver(model(UserModel::class)))->link('example', 'stable-id', $this->user->id);
        $this->directory->expects($this->exactly(3))->method('authenticate')->willReturnOnConsecutiveCalls(
            $this->entry() + ['matchedGroups' => ['developer']],
            $this->entry() + ['matchedGroups' => ['developer']],
            $this->entry() + ['matchedGroups' => []],
        );

        $ldap        = new LDAP(model(UserModel::class), $this->ldap, $this->directory);
        $credentials = ['username' => 'directory-user', 'password' => 'directory-secret'];

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $result = $ldap->check($credentials);
            $this->assertTrue($result->isOK());
            $this->assertSame($this->user->id, $result->extraInfo()->id);
            $this->assertSame('local-user', $result->extraInfo()->username);
        }

        $this->seeNumRecords(1, $this->tables['groups_users'], ['user_id' => $this->user->id, 'group' => 'developer']);
        $this->seeNumRecords(1, $this->tables['groups_users'], ['user_id' => $this->user->id, 'group' => 'beta']);
    }

    public function testRejectsMappingToAnUnknownShieldGroupBeforeQueryingLdap(): void
    {
        $this->ldap->connections['example']['groupMappings'] = ['unknown' => 'cn=users,dc=example,dc=com'];
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory-user']);
    }

    /**
     * @param array{matchedGroups?: list<string>} $groups
     */
    #[DataProvider('provideRejectsDirectoryResultsWithoutAValidGroupReport')]
    public function testRejectsDirectoryResultsWithoutAValidGroupReport(array $groups): void
    {
        $this->ldap->connections['example']['groupMappings'] = ['user' => 'cn=users,dc=example,dc=com'];
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry() + $groups);

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['users'], ['username' => 'directory-user']);
    }

    /**
     * @return iterable<string, array{array{matchedGroups?: list<string>}}>
     */
    public static function provideRejectsDirectoryResultsWithoutAValidGroupReport(): iterable
    {
        yield 'missing group report' => [[]];

        yield 'group from outside the mapping' => [['matchedGroups' => ['admin']]];
    }

    public function testDirectoryLoginPassesConfiguredUserBaseDnsToASupportingDirectory(): void
    {
        $userBaseDns                                      = ['ou=employees,dc=example,dc=com', 'ou=contractors,dc=example,dc=com'];
        $this->ldap->connections['example']['userBaseDn'] = $userBaseDns;
        $directory                                        = $this->createMock(MultiBaseLDAPDirectoryInterface::class);
        Services::injectMock('ldapDirectory', $directory);
        $directory->expects($this->once())->method('authenticate')->with($this->isInstanceOf(LDAPConnection::class), $userBaseDns)->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionMissing('error');
        $this->assertSame('directory-user', auth('session')->user()?->username);
    }

    public function testExplicitUserBaseDnTakesPrecedenceWithALegacyDirectory(): void
    {
        $userBaseDn                                       = 'ou=users,dc=example,dc=com';
        $this->ldap->connections['example']['userBaseDn'] = $userBaseDn;
        $this->directory->expects($this->once())->method('authenticate')->with($this->isInstanceOf(LDAPConnection::class), $userBaseDn)->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionMissing('error');
        $this->assertSame('directory-user', auth('session')->user()?->username);
    }

    public function testLegacyDirectoryRejectsAUserBaseDnListWithoutSearching(): void
    {
        $this->ldap->connections['example']['userBaseDn'] = ['ou=employees,dc=example,dc=com', 'ou=contractors,dc=example,dc=com'];
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->assertLogged('debug', 'Shield LDAP login rejected (invalid_configuration).');
    }

    public function testRememberedDirectoryLoginUsesShieldTokenRotationAndLogout(): void
    {
        config('Auth')->sessionConfig['allowRemembering']   = true;
        config('Auth')->sessionConfig['rememberCookieName'] = 'ldap_remember';
        config('Cookie')->prefix                            = 'app_';
        config('Cookie')->secure                            = true;
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $response->assertCookie('ldap_remember', null, 'app_');
        $userId = auth('session')->id();
        $this->assertNotNull($userId);
        $cookie = $response->response()->getCookie('ldap_remember', 'app_');
        $this->assertInstanceOf(Cookie::class, $cookie);
        $this->assertTrue($cookie->isHTTPOnly());
        $this->assertTrue($cookie->isSecure());
        [$selector, $validator] = explode(':', $cookie->getValue());
        $this->seeInDatabase($this->tables['remember_tokens'], [
            'user_id'         => $userId,
            'selector'        => $selector,
            'hashedValidator' => hash('sha256', $validator),
        ]);

        $this->resetAuthenticationServices();
        session()->remove('user');
        $request = service('incomingrequest', null, false);
        $request->setGlobal('cookie', ['app_ldap_remember' => $cookie->getValue()]);
        Services::injectMock('request', $request);

        $this->assertTrue(auth('session')->loggedIn());
        $this->assertSame($userId, auth('session')->id());
        $rotated = service('response')->getCookie('ldap_remember', 'app_');
        $this->assertInstanceOf(Cookie::class, $rotated);
        [$sameSelector, $newValidator] = explode(':', $rotated->getValue());
        $this->assertSame($selector, $sameSelector);
        $this->assertNotSame($validator, $newValidator);
        $this->seeInDatabase($this->tables['remember_tokens'], [
            'user_id'         => $userId,
            'selector'        => $selector,
            'hashedValidator' => hash('sha256', $newValidator),
        ]);

        $this->resetAuthenticationServices();
        $this->withSession(['user' => session('user')])->get('/logout')->assertStatus(302);
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $userId]);
    }

    public function testDirectoryLoginWithoutRememberChoiceDoesNotIssueAToken(): void
    {
        config('Auth')->sessionConfig['allowRemembering'] = true;
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertStatus(302);
        $response->assertCookieMissing('remember');
        $this->assertTrue(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => auth('session')->id()]);
    }

    public function testRememberedDirectoryLoginStillRequiresConfiguredLoginAction(): void
    {
        config('Auth')->actions['login']                  = Email2FA::class;
        config('Auth')->sessionConfig['allowRemembering'] = true;
        $this->user->createEmailIdentity(['email' => 'safe-contact@example.com', 'password' => 'local-password']);
        $this->user->addGroup('admin');
        (new LDAPUserResolver(auth()->getProvider()))->link('example', 'stable-id', $this->user->id);
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry($this->user->username));

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'directory-secret', 'remember' => '1']);

        $response->assertStatus(302);
        $response->assertCookie('remember');
        $cookie = $response->response()->getCookie('remember');
        $this->assertInstanceOf(Cookie::class, $cookie);
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
        $this->seeNumRecords(1, $this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $identity = model(UserIdentityModel::class)->getIdentityByType($this->user, Session::ID_TYPE_EMAIL_2FA);
        $this->assertNotNull($identity);

        $this->resetAuthenticationServices();
        session()->remove('user');
        $request = $this->createMock(IncomingRequest::class);
        $request->method('getCookie')->with('remember')->willReturn($cookie->getValue());
        Services::injectMock('request', $request);

        $authenticator = auth('session')->getAuthenticator();
        $this->assertInstanceOf(Session::class, $authenticator);
        $this->assertFalse($authenticator->loggedIn());
        $this->assertTrue($authenticator->isPending());

        $this->resetAuthenticationServices();
        $invalid = $this->withSession(['user' => session('user')])
            ->post('/auth/a/verify', ['token' => '000000']);

        $invalid->assertStatus(200);
        $invalid->assertCookieMissing('remember');
        $this->assertFalse(auth('session')->loggedIn());
        $this->seeNumRecords(1, $this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $this->resetAuthenticationServices();
        $verified = $this->withSession(['user' => session('user')])
            ->post('/auth/a/verify', ['token' => $identity->secret]);

        $verified->assertStatus(302);
        $verified->assertCookieMissing('remember');
        $this->assertSame($this->user->id, auth('session')->id());
        $this->seeNumRecords(1, $this->tables['remember_tokens'], ['user_id' => $this->user->id]);
    }

    public function testReservedLocalAccountRequiresConfiguredMfaWithoutQueryingDirectory(): void
    {
        config('Auth')->actions['login']                  = Email2FA::class;
        config('Auth')->sessionConfig['allowRemembering'] = true;
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->ldap->localAccounts[$this->user->username] = $this->user->id;
        $this->directory->expects($this->never())->method('authenticate');

        $response = $this->post('/login', [
            'username' => strtoupper($this->user->username),
            'password' => 'local-password',
            'remember' => '1',
        ]);

        $response->assertStatus(302);
        $response->assertCookieMissing('remember');
        $this->assertSame(site_url('auth/a/show'), $response->getRedirectUrl());
        $this->assertFalse(auth('session')->loggedIn());
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);

        $identity = model(UserIdentityModel::class)->getIdentityByType($this->user, Session::ID_TYPE_EMAIL_2FA);
        $this->assertNotNull($identity);
        $response = $this->withSession(['user' => session('user')])
            ->post('/auth/a/verify', ['token' => $identity->secret]);

        $response->assertStatus(302);
        $response->assertCookieMissing('remember');
        $this->assertSame($this->user->id, auth('session')->id());
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
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

    public function testReservedLocalAccountCannotUseAnExistingDirectoryLinkToSignIn(): void
    {
        $this->ldap->localAccounts[$this->user->username] = $this->user->id;
        $resolver                                         = new LDAPUserResolver(auth()->getProvider());
        $resolver->link('example', 'stable-id', $this->user->id);
        $this->directory->expects($this->once())->method('authenticate')->willReturn($this->entry());

        $response = $this->post('/login', ['username' => 'directory-user', 'password' => 'directory-secret']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $this->assertFalse(auth('session')->loggedIn());
        $this->assertSame($this->user->username, $resolver->resolve('example', 'stable-id')->username);
    }

    public function testReservedUsernameWithNoMatchingLocalAccountFailsClosed(): void
    {
        $this->ldap->localAccounts['missing-operator'] = $this->user->id + 1000;
        $this->directory->expects($this->never())->method('authenticate');

        $authOptions = get_object_vars(config('Auth'));
        $dummyHash   = $authOptions['dummyPasswordHash'] ?? null;
        $passwords   = $this->createMock(Passwords::class);
        $passwords->expects($this->never())->method('hash');
        if ($dummyHash !== null) {
            $passwords->expects($this->once())->method('verify')->with('local-password', $dummyHash)->willReturn(true);
        } else {
            $passwords->expects($this->never())->method('verify');
        }
        Services::injectMock('passwords', $passwords);

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
        config('Auth')->sessionConfig['allowRemembering'] = true;
        $this->user->createEmailIdentity(['email' => 'operator@example.com', 'password' => 'local-password']);
        $this->directory->expects($this->once())->method('authenticate')->willThrowException(new LDAPException($reason));

        $response = $this->post('/login', ['username' => $this->user->username, 'password' => 'local-password', 'remember' => '1']);

        $response->assertSessionHas('error', lang('Auth.badAttempt'));
        $response->assertCookieMissing('remember');
        $this->assertFalse(auth('session')->loggedIn());
        $response->assertSessionMissing('_ci_old_input');
        $this->dontSeeInDatabase($this->tables['remember_tokens'], ['user_id' => $this->user->id]);
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

    private function resetAuthenticationServices(): void
    {
        Services::resetSingle('auth');
        Services::resetSingle('response');
        Services::resetSingle('redirectresponse');
    }

    /**
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private function entry(string $uid = 'directory-user'): array
    {
        return [
            'dn'         => 'uid=' . $uid . ',dc=example,dc=com',
            'attributes' => ['uid' => [$uid], 'entryuuid' => ['stable-id']],
        ];
    }
}
