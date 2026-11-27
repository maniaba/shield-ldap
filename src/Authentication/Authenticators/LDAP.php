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

namespace Maniaba\ShieldLDAP\Authentication\Authenticators;

use CodeIgniter\Events\Events;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Authentication\Passwords;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use CodeIgniter\Shield\Result;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPFilter;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Authentication\LDAP\MultiBaseLDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Uses verified LDAP identities with Shield's session and login action lifecycle.
 */
class LDAP extends Session
{
    private readonly AuthLDAP $ldapConfig;
    private readonly LDAPDirectoryInterface $directory;
    private readonly LDAPUserResolver $resolver;

    /**
     * @var array<string, int|string>
     */
    private readonly array $localAccounts;

    /**
     * Uses the application configuration and directory service unless equivalents are supplied.
     *
     * @throws LDAPException If reserved local identifiers collide after case normalization.
     */
    public function __construct(
        UserModel $provider,
        ?AuthLDAP $config = null,
        ?LDAPDirectoryInterface $directory = null,
        ?LDAPUserResolver $resolver = null,
    ) {
        parent::__construct($provider);

        $this->ldapConfig    = $config ?? config('AuthLDAP');
        $this->directory     = $directory ?? service('ldapDirectory');
        $this->resolver      = $resolver ?? new LDAPUserResolver($provider);
        $this->localAccounts = array_change_key_case($this->ldapConfig->localAccounts);

        if (count($this->localAccounts) !== count($this->ldapConfig->localAccounts)) {
            throw new LDAPException('invalid_configuration');
        }
    }

    /**
     * Verify credentials and begin a Shield session, subject to configured login actions.
     *
     * @param array<array-key, mixed> $credentials
     */
    public function attempt(array $credentials): Result
    {
        $identifier = $credentials['username'] ?? '';

        if (! $this->validIdentifier($identifier) || $this->getSessionUserKey('id') !== null) {
            return $this->failedResult();
        }

        $result = $this->check($credentials);
        $user   = $result->extraInfo();

        if (! $result->isOK() || ! $user instanceof User) {
            return $this->rejectLogin($identifier);
        }

        $this->user = $user;
        $started    = $this->startUpAction('login', $user);
        $local      = isset($this->localAccounts[strtolower($identifier)]);

        if ($local && ! $started) {
            return $this->rejectLogin($identifier);
        }

        // Resolve pending actions before the session receives a user ID.
        $pending = $this->hasAction();
        if ($started && ! $pending) {
            return $this->rejectLogin($identifier);
        }

        $this->recordAttempt($identifier, $user);
        if (! $pending) {
            parent::login($user);

            return $result;
        }

        $this->startLogin($user);

        if ($local && ($identity = $user->getEmailIdentity()) !== null) {
            $user->touchIdentity($identity);
        }

        // Match Session::attempt() by issuing the token before the login action completes.
        if (! $local && $this->shouldRemember && setting('Auth.sessionConfig')['allowRemembering']) {
            $this->rememberUser($user);
            $this->remember(false);
        }

        return $result;
    }

    /**
     * Verify credentials and resolve the user for a subsequent session login.
     *
     * A successful directory check may provision or update the local user.
     *
     * @param array<array-key, mixed> $credentials
     */
    public function check(array $credentials): Result
    {
        $identifier = $credentials['username'] ?? '';
        $password   = $credentials['password'] ?? '';

        if (! $this->ldapConfig->enabled || ! $this->validIdentifier($identifier)
                                         || ! is_string($password) || $password === '' || strlen($password) > 4096 || str_contains($password, "\0")
        ) {
            return $this->failedResult();
        }

        $localId = $this->localAccounts[strtolower($identifier)] ?? null;
        if ($localId !== null) {
            return $this->checkLocalAccount($identifier, $password, $localId);
        }

        try {
            $user = $this->resolveUser($identifier, $password);

            if ($user->isBanned() || ! $user->isActivated()) {
                return $this->failedResult();
            }

            return new Result(['success' => true, 'extraInfo' => $user]);
        } catch (LDAPException $exception) {
            log_message('debug', 'Shield LDAP login rejected ({reason}).', ['reason' => $exception->reason]);

            return $this->failedResult();
        }
    }

    private function rejectLogin(string $identifier): Result
    {
        $this->user = null;
        $this->recordAttempt($identifier, null);
        Events::trigger('failedLogin', ['username' => $identifier]);

        return $this->failedResult();
    }

    private function recordAttempt(string $identifier, ?User $user): void
    {
        /** @var IncomingRequest $request */
        $request = service('request');
        $this->loginModel->recordLoginAttempt(
            self::ID_TYPE_USERNAME,
            $identifier,
            $user !== null,
            $request->getIPAddress(),
            (string) $request->getUserAgent(),
            $user?->id,
        );
    }

    private function resolveUser(string $identifier, string $password): User
    {
        $separator    = strrpos($identifier, '@');
        $domain       = $separator === false ? '' : strtolower(substr($identifier, $separator + 1));
        $connectionId = $this->ldapConfig->loginDomains[$domain] ?? $this->ldapConfig->defaultConnection;
        $connection   = $this->ldapConfig->getConnection($connectionId);

        if ($connection->id !== $connectionId) {
            throw new LDAPException('invalid_configuration');
        }

        $predicates = [];

        foreach ($connection->loginAttributes as $attribute) {
            $predicates[] = LDAPFilter::equal($attribute, $identifier);
        }

        $baseDn    = $connection->userBaseDn ?? $connection->baseDn;
        $directory = $this->directory;

        if (is_array($baseDn) && ! $directory instanceof MultiBaseLDAPDirectoryInterface) {
            throw new LDAPException('invalid_configuration');
        }

        $filter = LDAPFilter::all($connection->loginFilter, LDAPFilter::any(...$predicates));
        $entry  = $directory->authenticate(
            $connection,
            $baseDn,
            $filter,
            array_values(array_unique([$connection->externalIdAttribute, ...array_values($connection->profileAttributes)])),
            $password,
            $connection->eligibilityFilter,
        );

        return $this->resolver->resolve(
            $connection->id,
            LDAPUserResolver::externalId($connection, $entry['attributes']),
            LDAPUserResolver::profile($connection, $entry['attributes']),
            $connection->provisionUsers,
            $connection->updateProfile,
        );
    }

    private function checkLocalAccount(string $identifier, string $password, int|string $expectedId): Result
    {
        $user = $this->provider->findByCredentials(['username' => $identifier]);
        $hash = $user?->password_hash;

        /** @var Passwords $passwords */
        $passwords = service('passwords');

        if ($user === null || (string) $user->id !== (string) $expectedId || $hash === null || $hash === '') {
            $authOptions = get_object_vars(config('Auth'));
            $dummyHash   = $authOptions['dummyPasswordHash'] ?? null;

            if ($dummyHash !== null) {
                $passwords->verify($password, $dummyHash);
            }

            return $this->failedResult();
        }

        if (! $passwords->verify($password, $hash) || $user->isBanned() || ! $user->isActivated()) {
            return $this->failedResult();
        }

        if ($passwords->needsRehash($hash)) {
            $user->password_hash = $passwords->hash($password);
            $this->provider->save($user);
        }

        return new Result(['success' => true, 'extraInfo' => $user]);
    }

    private function validIdentifier(mixed $identifier): bool
    {
        return is_string($identifier) && $identifier !== '' && strlen($identifier) <= 255
            && preg_match('/^[^\p{Cc}]+$/uD', $identifier) === 1;
    }

    private function failedResult(): Result
    {
        return new Result(['success' => false, 'reason' => lang('Auth.badAttempt')]);
    }
}
