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

use CodeIgniter\Database\BaseBuilder;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\GroupModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Reconciles LDAP-owned Shield group rows inside the sign-in transaction.
 *
 * @internal
 */
final class LDAPGroupSynchronizer
{
    /**
     * @param list<string> $groups Group keys verified by this connection
     */
    public function synchronize(BaseConnection $database, User $user, string $connectionId, array $groups): void
    {
        $model  = model(GroupModel::class);
        $userId = $user->id;

        if ($userId === null || $database !== $model->builder()->db()) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }

        $groupTable  = $model->builder()->getTable();
        $grantTable  = config('AuthLDAP')->tables['group_grants'];
        $memberships = $database->table($groupTable . ' memberships')
            ->select('memberships.id, memberships.group, grants.grant_key, grants.sources, grants.revision')
            ->join($grantTable . ' grants', 'grants.shield_group_id = memberships.id AND grants.user_id = memberships.user_id', 'left')
            ->where('memberships.user_id', $userId)
            ->get()
            ->getResultArray();
        $grants = $database->table($grantTable);
        $source = hash('sha256', $connectionId);
        $groups = array_unique($groups);

        foreach ($memberships as $membership) {
            $group = $membership['group'];

            if ($membership['grant_key'] !== self::grantKey($userId, $group)) {
                continue;
            }

            $sources = explode(',', $membership['sources']);
            $matches = in_array($group, $groups, true);

            if ($matches === in_array($source, $sources, true)) {
                continue;
            }

            $sources      = $matches ? [...$sources, $source] : array_diff($sources, [$source]);
            $membershipId = $membership['id'];
            $this->writeGrant($grants, $membershipId, (int) $membership['revision'], $sources);

            if ($sources === [] && $model->builder()->where(['id' => $membershipId, 'user_id' => $userId, 'group' => $group])->delete() !== true) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }
        }

        foreach (array_diff($groups, array_column($memberships, 'group')) as $group) {
            if ($group === '' || ! $model->isValidGroup($group)) {
                throw new LDAPException(LDAPReason::InvalidConfiguration);
            }

            $key = self::grantKey($userId, $group);
            // Clean up orphaned metadata on installations without foreign key enforcement.
            if ($grants->where('grant_key', $key)
                ->whereNotIn('shield_group_id', $database->table($groupTable)->select('id'))
                ->delete() !== true
            ) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }

            $membershipId = $model->insert(['user_id' => $userId, 'group' => $group, 'created_at' => Time::now()]);

            if ($membershipId === false || ! $grants->insert([
                'shield_group_id' => $membershipId,
                'user_id'         => $userId,
                'grant_key'       => $key,
                'sources'         => $source,
            ])) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }
        }

        $user->setGroupsCache($model->getForUser($user));
    }

    /**
     * @param array<int, string> $sources
     */
    private function writeGrant(BaseBuilder $grants, int|string $membershipId, int $revision, array $sources): void
    {
        // Conflict with another sign-in rather than overwriting its membership decision.
        $grants->where(['shield_group_id' => $membershipId, 'revision' => $revision]);
        $saved = $sources === []
            ? $grants->delete()
            : $grants->update(['sources' => implode(',', $sources), 'revision' => $revision + 1]);

        if ($saved !== true || $grants->db()->affectedRows() !== 1) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }
    }

    private static function grantKey(int|string $userId, string $group): string
    {
        return hash('sha256', $userId . "\0" . $group);
    }
}
