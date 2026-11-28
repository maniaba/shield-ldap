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
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Models\UserModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Inspects, creates, and repairs authorized links for existing Shield users.
 */
final readonly class LDAPLinkService
{
    private LDAPIdentityPersistence $identities;

    /**
     * Use the configured user provider and identity model.
     */
    public function __construct(UserModel $users, ?UserIdentityModel $identities = null)
    {
        $this->identities = new LDAPIdentityPersistence($users, $identities);
    }

    /**
     * Read a contact scoped to this user's single link on the supplied connection.
     */
    public function getContactEmail(User $user, string $connectionId): ?string
    {
        if ($user->id === null) {
            return null;
        }

        $links = array_values(array_filter(
            $this->identities->identitiesForUser($user),
            static fn (UserIdentity $identity): bool => $identity->name === $connectionId,
        ));

        return count($links) === 1 ? LDAPContactEmail::read($links[0]->extra) : null;
    }

    /**
     * Link the selected Shield user after the caller authorizes and verifies the external identity.
     *
     * Supply an expected username when the selection comes from a username lookup.
     */
    public function link(string $connectionId, string $externalId, int|string $userId, ?string $expectedUsername = null): User
    {
        $key = LDAPIdentityPersistence::key($connectionId, $externalId);

        return $this->identities->transaction(function () use ($connectionId, $key, $userId, $expectedUsername): User {
            $user = $this->selectUser($userId, $expectedUsername);

            if (! $this->hasMatchingLink($user, $connectionId, $key, $expectedUsername !== null)) {
                $this->identities->create($connectionId, $key, $userId);
            }

            return $user;
        });
    }

    /**
     * Check whether the proposed username-based link exists, rejecting conflicting links.
     */
    public function isLinked(User $user, string $connectionId, string $externalId): bool
    {
        return $this->hasMatchingLink($user, $connectionId, LDAPIdentityPersistence::key($connectionId, $externalId), true);
    }

    /**
     * Report the state of an unambiguous proposed link on the selected connection.
     */
    public function inspectLink(User $user, string $connectionId, string $externalId): LinkStatus
    {
        $key      = LDAPIdentityPersistence::key($connectionId, $externalId);
        $identity = $this->identityForLink($user, $connectionId, $key);

        if ($identity === null) {
            return LinkStatus::Candidate;
        }

        return $identity->secret === $key ? LinkStatus::AlreadyLinked : LinkStatus::StaleLink;
    }

    /**
     * Replace an existing link after the caller authorizes the change and verifies the new directory ID.
     *
     * @return bool Whether the link was changed.
     */
    public function replaceLink(
        string $connectionId,
        string $externalId,
        int|string $userId,
        string $expectedUsername,
    ): bool {
        $key = LDAPIdentityPersistence::key($connectionId, $externalId);

        return $this->identities->transaction(function () use ($connectionId, $key, $userId, $expectedUsername): bool {
            $user     = $this->selectUser($userId, $expectedUsername);
            $identity = $this->identityForLink($user, $connectionId, $key);
            if ($identity?->id === null) {
                throw new LDAPException(LDAPReason::IdentityConflict);
            }

            if ($identity->secret === $key) {
                return false;
            }

            $this->identities->replace($identity, $connectionId, $key, $userId);

            return true;
        });
    }

    private function selectUser(int|string $userId, ?string $expectedUsername): User
    {
        $user = $this->identities->findUser($userId);
        if ($expectedUsername !== null
            && ($user->username === null || strcasecmp($user->username, $expectedUsername) !== 0)
        ) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        return $user;
    }

    private function hasMatchingLink(User $user, string $connectionId, string $key, bool $checkUserLinks): bool
    {
        $identity = $this->identities->findIdentity($key);
        if ($identity !== null && (string) $identity->user_id !== (string) $user->id) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        if ($checkUserLinks) {
            foreach ($this->identities->identitiesForUser($user) as $localIdentity) {
                if ($localIdentity->name === $connectionId && $localIdentity->secret !== $key) {
                    throw new LDAPException(LDAPReason::IdentityConflict);
                }
            }
        }

        return $identity !== null;
    }

    private function identityForLink(User $user, string $connectionId, string $key): ?UserIdentity
    {
        $selected = null;

        foreach ($this->identities->identitiesForUser($user) as $identity) {
            if ($identity->name !== $connectionId) {
                continue;
            }

            if ($selected !== null) {
                throw new LDAPException(LDAPReason::IdentityConflict);
            }

            $selected = $identity;
        }

        $owner = $this->identities->findIdentity($key);
        if ($owner !== null && ($selected === null
            || $selected->id !== $owner->id
            || (string) $owner->user_id !== (string) $user->id
            || $owner->secret !== $key)
        ) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        return $selected;
    }
}
