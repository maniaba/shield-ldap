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

namespace Maniaba\ShieldLDAP\Authentication\LDAP;

use Closure;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Throwable;

/**
 * Resolves verified directory identities to Shield users.
 */
final readonly class LDAPUserResolver
{
    public const ID_TYPE = 'ldap';

    private UserIdentityModel $identities;

    /**
     * Uses the standard identity model unless the caller supplies one.
     */
    public function __construct(private UserModel $users, ?UserIdentityModel $identities = null)
    {
        $this->identities = $identities ?? model(UserIdentityModel::class);
    }

    /**
     * Resolve an immutable directory ID after credential and access checks.
     *
     * Profile keys must be explicitly mapped to writable UserModel columns.
     * LDAP contact addresses cannot modify the local email/password identity.
     *
     * @param array<string, string|null> $profile
     */
    public function resolve(
        string $connectionId,
        string $externalId,
        array $profile = [],
        bool $provision = false,
        bool $updateProfile = true,
    ): User {
        $key     = $this->identityKey($connectionId, $externalId);
        $profile = $this->validateProfile($profile);

        return $this->atomically(function () use ($connectionId, $key, $profile, $provision, $updateProfile): User {
            $plan = $this->plan($key, $profile, $provision, $updateProfile);
            if ($plan['user'] === null && $plan['status'] === 'skipped') {
                throw new LDAPException('user_not_provisioned');
            }

            return $this->saveProfile($connectionId, $key, $plan['user'], $plan['changes']);
        });
    }

    /**
     * Preview or apply the synchronization of an eligible, service-account-verified directory entry.
     *
     * @param array<string, string|null>   $profile
     * @param array<array-key, int|string> $localAccounts
     *
     * @return 'create'|'skipped'|'unchanged'|'update'
     */
    public function synchronize(
        LDAPConnection $connection,
        string $externalId,
        array $profile,
        array $localAccounts,
        bool $apply,
    ): string {
        $key     = $this->identityKey($connection->id, $externalId);
        $profile = $this->validateProfile($profile);

        $operation = function () use ($connection, $key, $profile, $localAccounts, $apply): string {
            $plan = $this->plan($key, $profile, $connection->provisionUsers, $connection->updateProfile, $localAccounts);
            if ($plan['changes'] !== []) {
                $this->checkWritableFields($plan['changes']);
                if ($apply) {
                    $this->saveProfile($connection->id, $key, $plan['user'], $plan['changes']);
                }
            }

            return $plan['status'];
        };

        if ($apply) {
            return $this->atomically($operation);
        }

        try {
            return $operation();
        } catch (LDAPException $e) {
            throw $e;
        } catch (Throwable) {
            throw new LDAPException('synchronization_conflict');
        }
    }

    /**
     * Explicitly associate a verified directory ID with a selected Shield user.
     *
     * The caller must authorize the link and verify the external ID. For a
     * username-based link, provide the expected local username to verify it at
     * write time and refuse a different existing link on this connection.
     */
    public function link(string $connectionId, string $externalId, int|string $userId, ?string $expectedUsername = null): User
    {
        $key = $this->identityKey($connectionId, $externalId);

        return $this->atomically(function () use ($connectionId, $key, $userId, $expectedUsername): User {
            $user = $this->findUser($userId);

            if ($expectedUsername !== null && $user->username !== $expectedUsername) {
                throw new LDAPException('identity_conflict');
            }

            if (! $this->hasMatchingLink($user, $connectionId, $key, $expectedUsername !== null)) {
                $this->createIdentity($connectionId, $key, $userId);
            }

            return $user;
        });
    }

    /**
     * Check whether a proposed username-based link already exists.
     *
     * @throws LDAPException If either side already has a conflicting link.
     */
    public function isLinked(User $user, string $connectionId, string $externalId): bool
    {
        return $this->hasMatchingLink($user, $connectionId, $this->identityKey($connectionId, $externalId), true);
    }

    /**
     * Report the state of a proposed link for an existing Shield user.
     *
     * @return 'already_linked'|'candidate'|'stale_link'
     *
     * @throws LDAPException If the link is ambiguous or the key is already assigned elsewhere.
     */
    public function inspectLink(User $user, string $connectionId, string $externalId): string
    {
        $key      = $this->identityKey($connectionId, $externalId);
        $identity = $this->identityForLink($user, $connectionId, $key);

        if ($identity === null) {
            return 'candidate';
        }

        return $identity->secret === $key ? 'already_linked' : 'stale_link';
    }

    /**
     * Replace one existing link after the caller verifies the new directory ID and authorizes the change.
     *
     * @return bool Whether the link was changed.
     */
    public function replaceLink(
        string $connectionId,
        string $externalId,
        int|string $userId,
        string $expectedUsername,
    ): bool {
        $key = $this->identityKey($connectionId, $externalId);

        return $this->atomically(function () use ($connectionId, $key, $userId, $expectedUsername): bool {
            $user = $this->findUser($userId);
            if ($user->username !== $expectedUsername) {
                throw new LDAPException('identity_conflict');
            }

            $identity = $this->identityForLink($user, $connectionId, $key);
            if ($identity?->id === null) {
                throw new LDAPException('identity_conflict');
            }

            if ($identity->secret === $key) {
                return false;
            }

            $this->identities->where([
                'user_id' => $userId,
                'type'    => self::ID_TYPE,
                'name'    => $connectionId,
                'secret'  => $identity->secret,
            ])->update($identity->id, new UserIdentity(['secret' => $key]));

            if ($this->identities->builder()->db()->affectedRows() !== 1) {
                throw new LDAPException('synchronization_conflict');
            }

            $updated = $this->identities->getIdentityBySecret(self::ID_TYPE, $key);
            if ($updated?->id !== $identity->id
                || (string) $updated->user_id !== (string) $userId
                || $updated->name !== $connectionId
                || $updated->secret !== $key
            ) {
                throw new LDAPException('synchronization_conflict');
            }

            return true;
        });
    }

    /**
     * Read the configured immutable identifier and normalize binary Active Directory GUIDs.
     *
     * @param array<string, list<string>> $attributes
     */
    public static function externalId(LDAPConnection $connection, array $attributes): string
    {
        $ids = $attributes[strtolower($connection->externalIdAttribute)] ?? [];

        if (count($ids) !== 1 || $ids[0] === '') {
            throw new LDAPException('invalid_identity');
        }

        return strcasecmp($connection->externalIdAttribute, 'objectGUID') === 0
            ? self::normalizeObjectGuid($ids[0])
            : $ids[0];
    }

    /**
     * Map present, single-valued directory attributes to local profile fields.
     *
     * @param array<string, list<string>> $attributes
     *
     * @return array<string, string>
     */
    public static function profile(LDAPConnection $connection, array $attributes): array
    {
        $profile = [];

        foreach ($connection->profileAttributes as $field => $attribute) {
            $values = $attributes[strtolower($attribute)] ?? [];

            if (count($values) > 1) {
                throw new LDAPException('invalid_profile');
            }

            if ($values !== []) {
                $profile[$field] = $values[0];
            }
        }

        return $profile;
    }

    /**
     * Convert AD's mixed-endian, 16-byte objectGUID to a canonical UUID.
     */
    public static function normalizeObjectGuid(string $bytes): string
    {
        if (strlen($bytes) !== 16) {
            throw new LDAPException('invalid_identity');
        }

        return bin2hex(strrev(substr($bytes, 0, 4)))
            . '-' . bin2hex(strrev(substr($bytes, 4, 2)))
            . '-' . bin2hex(strrev(substr($bytes, 6, 2)))
            . '-' . bin2hex(substr($bytes, 8, 2))
            . '-' . bin2hex(substr($bytes, 10));
    }

    private function hasMatchingLink(User $user, string $connectionId, string $key, bool $checkUserLinks): bool
    {
        $identity = $this->identities->getIdentityBySecret(self::ID_TYPE, $key);
        if ($identity !== null && (string) $identity->user_id !== (string) $user->id) {
            throw new LDAPException('identity_conflict');
        }

        if ($checkUserLinks) {
            foreach ($this->identities->getIdentitiesByTypes($user, [self::ID_TYPE]) as $localIdentity) {
                if ($localIdentity->name === $connectionId && $localIdentity->secret !== $key) {
                    throw new LDAPException('identity_conflict');
                }
            }
        }

        return $identity !== null;
    }

    private function identityForLink(User $user, string $connectionId, string $key): ?UserIdentity
    {
        $selected = null;

        foreach ($this->identities->getIdentitiesByTypes($user, [self::ID_TYPE]) as $identity) {
            if ($identity->name !== $connectionId) {
                continue;
            }

            if ($selected !== null) {
                throw new LDAPException('identity_conflict');
            }

            $selected = $identity;
        }

        $owner = $this->identities->getIdentityBySecret(self::ID_TYPE, $key);
        if ($owner !== null && ($selected === null
            || $selected->id !== $owner->id
            || (string) $owner->user_id !== (string) $user->id
            || $owner->secret !== $key)
        ) {
            throw new LDAPException('identity_conflict');
        }

        return $selected;
    }

    private function identityKey(string $connectionId, string $externalId): string
    {
        if (preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $connectionId) !== 1 || $externalId === '' || strlen($externalId) > 1024) {
            throw new LDAPException('invalid_identity');
        }

        return hash('sha256', $connectionId . "\0" . $externalId);
    }

    /**
     * @param array<string, string|null>   $profile
     * @param array<array-key, int|string> $localAccounts
     *
     * @return array{status: 'create'|'skipped'|'unchanged'|'update', user: User|null, changes: array<string, string|null>}
     */
    private function plan(
        string $key,
        array $profile,
        bool $provision,
        bool $updateProfile,
        array $localAccounts = [],
    ): array {
        $identity = $this->identities->getIdentityBySecret(self::ID_TYPE, $key);
        $user     = $identity === null ? null : $this->findUser($identity->user_id);
        $username = $profile['username'] ?? null;

        if (($user === null && ! $provision)
            || ($user !== null && (! $updateProfile || $user->isBanned() || ! $user->isActivated()))
            || $this->isReservedAccount($user, $username, $localAccounts)
        ) {
            return ['status' => 'skipped', 'user' => $user, 'changes' => []];
        }

        if ($user === null && $username === null) {
            throw new LDAPException('invalid_profile');
        }

        if ($user !== null) {
            $stored = $user->toRawArray();

            foreach ($profile as $field => $value) {
                if (array_key_exists($field, $stored) && $stored[$field] === $value) {
                    unset($profile[$field]);
                }
            }
        }

        if (isset($profile['username'])) {
            $this->checkUsername($profile['username'], $identity?->user_id);
        }

        $status = match (true) {
            $user === null  => 'create',
            $profile !== [] => 'update',
            default         => 'unchanged',
        };

        return ['status' => $status, 'user' => $user, 'changes' => $profile];
    }

    /**
     * @param array<array-key, int|string> $localAccounts
     */
    private function isReservedAccount(?User $user, ?string $username, array $localAccounts): bool
    {
        $userId         = $user?->id;
        $storedUsername = $user?->username;

        foreach ($localAccounts as $localUsername => $localId) {
            if (($userId !== null && (string) $userId === (string) $localId)
                || ($username !== null && strcasecmp($username, (string) $localUsername) === 0)
                || ($storedUsername !== null && strcasecmp($storedUsername, (string) $localUsername) === 0)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, string|null> $changes
     */
    private function checkWritableFields(array $changes): void
    {
        $builder   = $this->users->builder();
        $fields    = $builder->db()->getFieldNames($builder->getTable());
        $protected = $this->users->__get('protectFields') === true;
        $allowed   = $this->users->__get('allowedFields');

        foreach (array_keys($changes) as $field) {
            if (! in_array($field, $fields, true)
                || ($protected && (! is_array($allowed) || ! in_array($field, $allowed, true)))
            ) {
                throw new LDAPException('invalid_profile');
            }
        }
    }

    /**
     * @param array<string, string|null> $profile
     */
    private function saveProfile(string $connectionId, string $key, ?User $user, array $profile): User
    {
        if ($user === null) {
            $userId = $this->users->insert($profile);
            if ($userId === true) {
                throw new LDAPException('synchronization_conflict');
            }

            $user = $this->readBackProfile($userId, $profile);
            $this->createIdentity($connectionId, $key, $userId);

            return $user;
        }

        if ($profile === []) {
            return $user;
        }

        $userId = $user->id;
        if ($userId === null) {
            throw new LDAPException('synchronization_conflict');
        }

        $this->users->update($userId, $profile);

        return $this->readBackProfile($userId, $profile);
    }

    /**
     * @param array<string, string|null> $profile
     *
     * @return array<string, string|null>
     */
    private function validateProfile(array $profile): array
    {
        $reserved = [
            'id', 'userid', 'email', 'password', 'passwordhash', 'secret', 'secret2',
            'identities', 'active', 'status', 'statusmessage', 'forcereset',
            'groups', 'permissions', 'createdat', 'updatedat', 'deletedat', 'lastactive',
        ];

        foreach (array_keys($profile) as $field) {
            $collapsed = str_replace('_', '', strtolower($field));

            if (preg_match('/\A[a-zA-Z][a-zA-Z0-9_]*\z/', $field) !== 1
                || in_array($collapsed, $reserved, true)
                || ($collapsed === 'username' && $field !== 'username')
            ) {
                throw new LDAPException('invalid_profile');
            }
        }

        if (array_key_exists('username', $profile)) {
            $username = $profile['username'];

            if ($username === null
                || trim($username) === ''
                || str_contains($username, "\0")
                || ! mb_check_encoding($username, 'UTF-8')
                || mb_strlen($username, 'UTF-8') > 30
            ) {
                throw new LDAPException('invalid_profile');
            }

            $profile['username'] = strtolower($username);
        }

        return $profile;
    }

    private function checkUsername(string $username, int|string|null $ownerId = null): void
    {
        $owner = $this->users->findByCredentials(['username' => $username]);
        if ($owner !== null && ($ownerId === null || (string) $owner->id !== (string) $ownerId)) {
            throw new LDAPException('identity_conflict');
        }
    }

    private function findUser(int|string $userId): User
    {
        $user = $this->users->findById($userId);
        if ($user === null) {
            throw new LDAPException('identity_conflict');
        }

        return $user;
    }

    /**
     * @param array<string, string|null> $profile
     */
    private function readBackProfile(int|string $userId, array $profile): User
    {
        $user   = $this->findUser($userId);
        $stored = $user->toRawArray();

        foreach ($profile as $field => $value) {
            if (! array_key_exists($field, $stored) || $stored[$field] !== $value) {
                throw new LDAPException('invalid_profile');
            }
        }

        return $user;
    }

    private function createIdentity(string $connectionId, string $key, int|string $userId): void
    {
        $this->identities->create(new UserIdentity([
            'user_id' => $userId,
            'type'    => self::ID_TYPE,
            'name'    => $connectionId,
            'secret'  => $key,
        ]));

        $identity = $this->identities->getIdentityBySecret(self::ID_TYPE, $key);
        if ($identity === null || (string) $identity->user_id !== (string) $userId) {
            throw new LDAPException('synchronization_conflict');
        }
    }

    /**
     * @template T of bool|string|User
     *
     * @param Closure(): T $operation
     *
     * @return T
     */
    private function atomically(Closure $operation): bool|string|User
    {
        try {
            $database = $this->users->builder()->db();
            // CodeIgniter does not independently roll back nested transactions.
            if ($database !== $this->identities->builder()->db()
                || $database->transDepth !== 0
                || ! $database->transStatus()
                || ! $database->transBegin()
            ) {
                throw new LDAPException('synchronization_conflict');
            }

            $strict = $database->transStrict;
            $database->transStrict(false);

            try {
                $result = $operation();
                if (! $database->transComplete()) {
                    throw new LDAPException('synchronization_conflict');
                }

                return $result;
            } finally {
                try {
                    if ($database->transDepth !== 0) {
                        $this->rollBack($database);
                    }
                } finally {
                    $database->transStrict($strict);
                }
            }
        } catch (LDAPException $e) {
            throw $e;
        } catch (Throwable) {
            // Model exceptions can contain SQL with directory and local account data.
            throw new LDAPException('synchronization_conflict');
        }
    }

    private function rollBack(BaseConnection $database): void
    {
        if ($database->transStatus()) {
            $database->transRollback();
        } else {
            // Completing a failed non-strict transaction rolls back and resets its status.
            $database->transComplete();
        }
    }
}
