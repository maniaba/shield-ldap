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
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;
use Throwable;

/**
 * Stores LDAP identity links in Shield's configured identity table.
 *
 * @internal
 */
final readonly class LDAPIdentityPersistence
{
    public const TYPE = 'ldap';

    private UserIdentityModel $identities;

    /**
     * Use Shield's identity model by default.
     */
    public function __construct(private UserModel $users, ?UserIdentityModel $identities = null)
    {
        $this->identities = $identities ?? model(UserIdentityModel::class);
    }

    /**
     * Scope the immutable identifier to one connection.
     */
    public static function key(string $connectionId, string $externalId): string
    {
        if (preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $connectionId) !== 1 || $externalId === '' || strlen($externalId) > 1024) {
            throw new LDAPException(LDAPReason::InvalidIdentity);
        }

        return hash('sha256', $connectionId . "\0" . $externalId);
    }

    /**
     * Look up a stored link by its scoped key.
     */
    public function findIdentity(string $key): ?UserIdentity
    {
        return $this->identities->getIdentityBySecret(self::TYPE, $key);
    }

    /**
     * List the LDAP identities associated with the given Shield user.
     *
     * @return list<UserIdentity>
     */
    public function identitiesForUser(User $user): array
    {
        return $this->identities->getIdentitiesByTypes($user, [self::TYPE]);
    }

    /**
     * Require the local user to exist and be visible to the user provider.
     */
    public function findUser(int|string $userId): User
    {
        $user = $this->users->findById($userId);
        if ($user === null) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        return $user;
    }

    /**
     * Check whether a local account or a mapped username is reserved.
     *
     * @param array<array-key, int|string> $localAccounts
     */
    public static function isReservedAccount(?User $user, ?string $username, array $localAccounts): bool
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
     * Store the link and verify its owner before the calling transaction commits.
     */
    public function create(string $connectionId, string $key, int|string $userId, ?string $extra = null): void
    {
        $this->identities->create(new UserIdentity([
            'user_id' => $userId,
            'type'    => self::TYPE,
            'name'    => $connectionId,
            'secret'  => $key,
            ...($extra === null ? [] : ['extra' => $extra]),
        ]));

        $identity = $this->findIdentity($key);
        if ($identity === null || (string) $identity->user_id !== (string) $userId || ($extra !== null && $identity->extra !== $extra)) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }
    }

    /**
     * Write contact metadata only while the original LDAP link and metadata still match.
     */
    public function updateExtra(UserIdentity $identity, ?string $extra): void
    {
        if ($identity->id === null) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        $this->identities->where([
            'user_id' => $identity->user_id,
            'type'    => self::TYPE,
            'name'    => $identity->name,
            'secret'  => $identity->secret,
        ]);
        $this->expectExtra($identity->extra);
        $this->identities->update($identity->id, new UserIdentity(['extra' => $extra]));

        if ($this->identities->builder()->db()->affectedRows() !== 1) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }
    }

    /**
     * Replace the key only if the selected, previously read identity still matches.
     */
    public function replace(UserIdentity $identity, string $connectionId, string $key, int|string $userId): void
    {
        if ($identity->id === null) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        $extra   = (new LDAPContactEmail(null))->updateExtra($identity->extra);
        $changes = ['secret' => $key];
        if ($extra !== $identity->extra) {
            $changes['extra'] = $extra;
        }

        $this->expectExtra($identity->extra);
        $this->identities->where([
            'user_id' => $userId,
            'type'    => self::TYPE,
            'name'    => $connectionId,
            'secret'  => $identity->secret,
        ])->update($identity->id, new UserIdentity($changes));

        if ($this->identities->builder()->db()->affectedRows() !== 1) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }

        $updated = $this->findIdentity($key);
        if ($updated?->id !== $identity->id
            || (string) $updated->user_id !== (string) $userId
            || $updated->name !== $connectionId
            || $updated->secret !== $key
            || (array_key_exists('extra', $changes) && $updated->extra !== $extra)
        ) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }
    }

    private function expectExtra(?string $extra): void
    {
        if ($extra === null) {
            $this->identities->where('extra', null);

            return;
        }

        $database = $this->identities->builder()->db();
        $column   = $database->protectIdentifiers('extra');
        $field    = match ($database->getPlatform()) {
            'MySQLi' => 'CAST(' . $column . ' AS BINARY)',
            'SQLSRV' => 'CAST(' . $column . ' AS NVARCHAR(MAX))',
            default  => 'extra',
        };

        $this->identities->where($field . ' =', $extra);
    }

    /**
     * Use one top-level transaction for changes to users and identities.
     *
     * @template T
     *
     * @param Closure(): T $operation
     *
     * @return T
     */
    public function transaction(Closure $operation): mixed
    {
        try {
            $database = $this->users->builder()->db();
            // CodeIgniter does not independently roll back nested transactions.
            if ($database !== $this->identities->builder()->db()
                || $database->transDepth !== 0
                || ! $database->transStatus()
                || ! $database->transBegin()
            ) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }

            $strict = $database->transStrict;
            $database->transStrict(false);

            try {
                $result = $operation();
                if (! $database->transComplete()) {
                    throw new LDAPException(LDAPReason::SynchronizationConflict);
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
        } catch (Throwable $e) {
            throw new LDAPException(LDAPReason::SynchronizationConflict, $e);
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
