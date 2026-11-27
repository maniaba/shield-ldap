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

use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Resolves verified directory identities and preserves the original LDAP user API.
 */
final readonly class LDAPUserResolver
{
    public const ID_TYPE = LDAPIdentityPersistence::TYPE;

    private LDAPLinkService $links;
    private LDAPProfileSynchronizer $profiles;

    /**
     * Uses the standard identity model unless the caller supplies one.
     */
    public function __construct(UserModel $users, ?UserIdentityModel $identities = null)
    {
        $this->links    = new LDAPLinkService($users, $identities);
        $this->profiles = new LDAPProfileSynchronizer($users, $identities);
    }

    /**
     * Resolve an immutable directory ID after credential and access checks.
     *
     * Profile keys must be explicitly mapped to writable UserModel columns.
     * LDAP contact addresses cannot modify the local email/password identity.
     *
     * @param array<string, string|null>   $profile
     * @param array<array-key, int|string> $localAccounts
     */
    public function resolve(
        string $connectionId,
        string $externalId,
        array $profile = [],
        bool $provision = false,
        bool $updateProfile = true,
        array $localAccounts = [],
    ): User {
        return $this->profiles->resolve($connectionId, $externalId, $profile, $provision, $updateProfile, $localAccounts);
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
        $plan = $this->profiles->plan($connection, $externalId, $profile, $localAccounts);

        return ($apply ? $this->profiles->apply($plan) : $plan->status)->value;
    }

    /**
     * Explicitly associate a verified directory ID with a selected Shield user.
     *
     * The caller must authorize the link and verify the external ID. Supply the
     * expected local username when the selection comes from a username lookup.
     */
    public function link(string $connectionId, string $externalId, int|string $userId, ?string $expectedUsername = null): User
    {
        return $this->links->link($connectionId, $externalId, $userId, $expectedUsername);
    }

    /**
     * Check whether a proposed username-based link already exists.
     *
     * @throws LDAPException If either side already has a conflicting link.
     */
    public function isLinked(User $user, string $connectionId, string $externalId): bool
    {
        return $this->links->isLinked($user, $connectionId, $externalId);
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
        return $this->links->inspectLink($user, $connectionId, $externalId)->value;
    }

    /**
     * Replace one existing link after the caller verifies the new directory ID and authorizes the change.
     */
    public function replaceLink(
        string $connectionId,
        string $externalId,
        int|string $userId,
        string $expectedUsername,
    ): bool {
        return $this->links->replaceLink($connectionId, $externalId, $userId, $expectedUsername);
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
            throw new LDAPException(LDAPReason::InvalidIdentity);
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
                throw new LDAPException(LDAPReason::InvalidProfile);
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
            throw new LDAPException(LDAPReason::InvalidIdentity);
        }

        return bin2hex(strrev(substr($bytes, 0, 4)))
            . '-' . bin2hex(strrev(substr($bytes, 4, 2)))
            . '-' . bin2hex(strrev(substr($bytes, 6, 2)))
            . '-' . bin2hex(substr($bytes, 8, 2))
            . '-' . bin2hex(substr($bytes, 10));
    }
}
