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
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;
use Throwable;

/**
 * Provisions eligible directory users and synchronizes their mapped local fields.
 *
 * @phpstan-type ProfileChange array{status: SyncStatus, user: ?User, fields: array<string, string|null>, loginFailure?: LDAPReason, contact?: array{identity: ?UserIdentity, extra: ?string}}
 */
final readonly class LDAPProfileSynchronizer
{
    private LDAPIdentityPersistence $identities;

    /**
     * Use the configured user provider and identity model.
     */
    public function __construct(private UserModel $users, ?UserIdentityModel $identities = null)
    {
        $this->identities = new LDAPIdentityPersistence($users, $identities);
    }

    /**
     * Resolve the identity after directory credentials and access have been verified.
     *
     * @param array<string, string|null>              $profile
     * @param array<array-key, int|string>            $localAccounts
     * @param list<string>|null                       $groups              Verified Shield group keys
     * @param (Closure(): array<string, string>)|null $provisioningProfile
     */
    public function resolve(
        string $connectionId,
        string $externalId,
        array $profile = [],
        bool $provision = false,
        bool $updateProfile = true,
        array $localAccounts = [],
        ?array $groups = null,
        ?Closure $provisioningProfile = null,
        ?LDAPContactEmail $contactEmail = null,
    ): User {
        $key     = LDAPIdentityPersistence::key($connectionId, $externalId);
        $profile = $this->validateProfile($profile);

        return $this->identities->transaction(function () use ($connectionId, $key, $profile, $provision, $updateProfile, $localAccounts, $groups, $provisioningProfile, $contactEmail): User {
            $change = $this->prepareChange($key, $profile, $provision, $updateProfile, $localAccounts, $provisioningProfile, $contactEmail);

            if (isset($change['loginFailure'])) {
                throw new LDAPException($change['loginFailure']);
            }

            $user = $this->saveChange($connectionId, $key, $change);

            if ($groups !== null && ! $user->isBanned() && $user->isActivated()) {
                (new LDAPGroupSynchronizer())->synchronize($this->users->builder()->db(), $user, $connectionId, $groups);
            }

            return $user;
        });
    }

    /**
     * Preview synchronization for an eligible directory entry without writing to Shield.
     *
     * @param array<string, string|null>   $profile
     * @param array<array-key, int|string> $localAccounts
     */
    public function plan(
        LDAPConnection $connection,
        string $externalId,
        array $profile,
        array $localAccounts,
        ?LDAPContactEmail $contactEmail = null,
    ): LDAPProfilePlan {
        $key     = LDAPIdentityPersistence::key($connection->id, $externalId);
        $profile = $this->validateProfile($profile);

        try {
            $change = $this->prepareSynchronization($connection, $key, $profile, $localAccounts, $contactEmail);

            return new LDAPProfilePlan($connection, $externalId, $profile, $localAccounts, $change['status'], $contactEmail);
        } catch (LDAPException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new LDAPException(LDAPReason::SynchronizationConflict, $e);
        }
    }

    /**
     * Recheck and apply the planned entry using the current local state.
     */
    public function apply(LDAPProfilePlan $plan): SyncStatus
    {
        $key     = LDAPIdentityPersistence::key($plan->connection->id, $plan->externalId);
        $profile = $this->validateProfile($plan->profile);

        return $this->identities->transaction(function () use ($plan, $key, $profile): SyncStatus {
            $change = $this->prepareSynchronization($plan->connection, $key, $profile, $plan->localAccounts, $plan->contactEmail);
            if ($change['status'] === SyncStatus::Create || $change['status'] === SyncStatus::Update) {
                $this->saveChange($plan->connection->id, $key, $change);
            }

            return $change['status'];
        });
    }

    /**
     * @param array<string, string|null>   $profile
     * @param array<array-key, int|string> $localAccounts
     *
     * @return ProfileChange
     */
    private function prepareSynchronization(
        LDAPConnection $connection,
        string $key,
        array $profile,
        array $localAccounts,
        ?LDAPContactEmail $contactEmail,
    ): array {
        $change = $this->prepareChange($key, $profile, $connection->provisionUsers, $connection->updateProfile, $localAccounts, contactEmail: $contactEmail);
        if ($change['fields'] !== []) {
            $this->checkWritableFields($change['fields']);
        }

        return $change;
    }

    /**
     * @param array<string, string|null>              $profile
     * @param array<array-key, int|string>            $localAccounts
     * @param (Closure(): array<string, string>)|null $provisioningProfile
     *
     * @return ProfileChange
     */
    private function prepareChange(
        string $key,
        array $profile,
        bool $provision,
        bool $updateProfile,
        array $localAccounts,
        ?Closure $provisioningProfile = null,
        ?LDAPContactEmail $contactEmail = null,
    ): array {
        $identity = $this->identities->findIdentity($key);
        $user     = $identity === null ? null : $this->identities->findUser($identity->user_id);

        if ($user === null && $provision && $provisioningProfile !== null) {
            $profile = $this->validateProfile($provisioningProfile());
        }

        $username = $profile['username'] ?? null;

        if (LDAPIdentityPersistence::isReservedAccount($user, $username, $localAccounts)) {
            return ['status' => SyncStatus::Skipped, 'user' => $user, 'fields' => [], 'loginFailure' => LDAPReason::ReservedLocalAccount];
        }

        if ($user === null && ! $provision) {
            return ['status' => SyncStatus::Skipped, 'user' => null, 'fields' => [], 'loginFailure' => LDAPReason::UserNotProvisioned];
        }

        if ($user !== null && (! $updateProfile || $user->isBanned() || ! $user->isActivated())) {
            return ['status' => SyncStatus::Skipped, 'user' => $user, 'fields' => []];
        }

        if ($user === null && $username === null) {
            throw new LDAPException(LDAPReason::InvalidProfile);
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

        $extra        = $identity?->extra;
        $updatedExtra = $contactEmail === null ? $extra : $contactEmail->updateExtra($extra);
        $status       = match (true) {
            $user === null                              => SyncStatus::Create,
            $profile !== [] || $updatedExtra !== $extra => SyncStatus::Update,
            default                                     => SyncStatus::Unchanged,
        };

        $change = ['status' => $status, 'user' => $user, 'fields' => $profile];
        if ($updatedExtra !== $extra) {
            $change['contact'] = ['identity' => $identity, 'extra' => $updatedExtra];
        }

        return $change;
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
                throw new LDAPException(LDAPReason::InvalidProfile);
            }
        }
    }

    /**
     * @param ProfileChange $change
     */
    private function saveChange(string $connectionId, string $key, array $change): User
    {
        $user    = $change['user'];
        $profile = $change['fields'];
        $contact = $change['contact'] ?? null;

        if ($user === null) {
            $userId = $this->users->insert($profile);
            if ($userId === true) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }

            $user = $this->readBackProfile($userId, $profile);
            $this->identities->create($connectionId, $key, $userId, $contact['extra'] ?? null);
            $this->users->addToDefaultGroup($user);

            return $user;
        }

        if ($contact !== null && $contact['identity'] !== null) {
            $this->identities->updateExtra($contact['identity'], $contact['extra']);
        }

        if ($profile === []) {
            return $user;
        }

        $userId = $user->id;
        if ($userId === null) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
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
                throw new LDAPException(LDAPReason::InvalidProfile);
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
                throw new LDAPException(LDAPReason::InvalidProfile);
            }

            $profile['username'] = strtolower($username);
        }

        return $profile;
    }

    private function checkUsername(string $username, int|string|null $ownerId = null): void
    {
        $owner = $this->users->findByCredentials(['username' => $username]);
        if ($owner !== null && ($ownerId === null || (string) $owner->id !== (string) $ownerId)) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }
    }

    /**
     * @param array<string, string|null> $profile
     */
    private function readBackProfile(int|string $userId, array $profile): User
    {
        $user   = $this->identities->findUser($userId);
        $stored = $user->toRawArray();

        foreach ($profile as $field => $value) {
            if (! array_key_exists($field, $stored) || $stored[$field] !== $value) {
                throw new LDAPException(LDAPReason::InvalidProfile);
            }
        }

        return $user;
    }
}
