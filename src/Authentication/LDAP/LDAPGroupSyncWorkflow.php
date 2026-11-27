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

use CodeIgniter\Shield\Models\UserModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Reconciles mapped groups for existing Shield links after a complete directory scan.
 */
final readonly class LDAPGroupSyncWorkflow
{
    private LDAPIdentityPersistence $identities;

    public function __construct(private LDAPGroupEnumerationInterface $directory, private UserModel $users)
    {
        $this->identities = new LDAPIdentityPersistence($users);
    }

    /**
     * @param array<array-key, int|string> $localAccounts
     *
     * @return array{update: int, unchanged: int, skipped: int}
     */
    public function run(LDAPConnection $connection, array $localAccounts, bool $apply): array
    {
        if (! $connection->verifyCertificate) {
            throw new LDAPException(LDAPReason::TlsVerificationRequired);
        }

        $mappings = $connection->groupMappings;
        if ($mappings === null || array_diff(array_keys($mappings), array_keys(setting('AuthGroups.groups'))) !== []) {
            throw new LDAPException(LDAPReason::InvalidConfiguration);
        }

        [$entries, $skipped] = $this->stageMemberships($connection, array_keys($mappings));
        $totals              = ['update' => 0, 'unchanged' => 0, 'skipped' => $skipped];
        $groups              = new LDAPGroupSynchronizer();

        foreach ($entries as $key => $entry) {
            $status = $this->identities->transaction(function () use ($connection, $localAccounts, $apply, $key, $entry, $groups): SyncStatus {
                $identity = $this->identities->findIdentity($key);
                if ($identity === null || (string) $identity->user_id !== (string) $entry['userId']) {
                    throw new LDAPException(LDAPReason::IdentityConflict);
                }

                $user = $this->identities->findUser($identity->user_id);
                if ($user->isBanned() || ! $user->isActivated() || LDAPIdentityPersistence::isReservedAccount($user, null, $localAccounts)) {
                    return SyncStatus::Skipped;
                }

                return $groups->synchronize($this->users->builder()->db(), $user, $connection->id, $entry['groups'], $apply)
                    ? SyncStatus::Update
                    : SyncStatus::Unchanged;
            });

            $totals[$status->value]++;
        }

        return $totals;
    }

    /**
     * @param list<string> $configuredGroups
     *
     * @return array{array<string, array{userId: int|string, dn: string, groups: list<string>}>, int}
     */
    private function stageMemberships(LDAPConnection $connection, array $configuredGroups): array
    {
        $entries     = [];
        $skipped     = [];
        $linkedUsers = [];
        $scan        = $this->directory->scanGroupMemberships($connection);

        try {
            foreach ($scan as $entry) {
                $externalId = LDAPUserResolver::externalId($connection, $entry['attributes']);
                $key        = LDAPIdentityPersistence::key($connection->id, $externalId);
                $matched    = $entry['matchedGroups'] ?? throw new LDAPException(LDAPReason::InvalidDirectoryEntry);

                if (array_diff($matched, $configuredGroups) !== []) {
                    throw new LDAPException(LDAPReason::InvalidDirectoryEntry);
                }

                if (isset($skipped[$key])) {
                    continue;
                }

                $dn     = hash('sha256', $entry['dn']);
                $groups = array_values(array_unique($matched));
                sort($groups, SORT_STRING);
                $previous = $entries[$key] ?? null;
                if ($previous !== null) {
                    if ($previous['dn'] !== $dn || $previous['groups'] !== $groups) {
                        throw new LDAPException(LDAPReason::AmbiguousUser);
                    }

                    continue;
                }

                $identity = $this->identities->findIdentity($key);
                if ($identity === null) {
                    $skipped[$key] = true;

                    continue;
                }

                if (isset($linkedUsers[$identity->user_id])) {
                    throw new LDAPException(LDAPReason::IdentityConflict);
                }

                $linkedUsers[$identity->user_id] = true;
                $entries[$key]                   = ['userId' => $identity->user_id, 'dn' => $dn, 'groups' => $groups];
            }
        } finally {
            if ($scan instanceof LDAPUserScan) {
                $scan->close();
            }
        }

        return [$entries, count($skipped)];
    }
}
