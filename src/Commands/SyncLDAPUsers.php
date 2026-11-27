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

namespace Maniaba\ShieldLDAP\Commands;

use CodeIgniter\Shield\Commands\BaseCommand;
use Maniaba\ShieldLDAP\Authentication\LDAP\SyncStatus;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Previews or applies provisioning and profile synchronization for a directory.
 */
final class SyncLDAPUsers extends BaseCommand
{
    protected $name        = 'shield:ldap-sync';
    protected $description = 'Preview or synchronize eligible LDAP users.';
    protected $usage       = 'shield:ldap-sync <connection> [--groups-only] [--apply]';
    protected $arguments   = [
        'connection' => 'LDAP connection ID from AuthLDAP.',
    ];
    protected $options = [
        '--groups-only' => 'Synchronize only mapped groups for existing linked users.',
        '--apply'       => 'Write the selected changes to Shield.',
    ];

    /**
     * Synchronize a named directory using the configured Shield user provider.
     *
     * @param array<array-key, mixed> $params
     */
    public function run(array $params): int
    {
        $connectionId = $params[0] ?? null;
        $apply        = array_key_exists('apply', $params);
        $groupsOnly   = array_key_exists('groups-only', $params);

        if (! is_string($connectionId) || $connectionId === ''
                                       || ($apply && $params['apply'] !== null)
                                       || ($groupsOnly && $params['groups-only'] !== null)
                                       || array_diff_key($params, [0 => true, 'apply' => true, 'groups-only' => true]) !== []
        ) {
            $this->error($this->usage);

            return EXIT_ERROR;
        }

        try {
            $config     = config('AuthLDAP');
            $connection = $config->getConnection($connectionId);

            if ($connection->id !== $connectionId) {
                throw new LDAPException(LDAPReason::InvalidConfiguration);
            }

            if ($groupsOnly) {
                $totals = service('ldapGroupSyncWorkflow')->run($connection, $config->localAccounts, $apply);
                $this->write(sprintf(
                    'Groups summary: %s=%d unchanged=%d skipped=%d',
                    $this->displayStatus(SyncStatus::Update, $apply),
                    $totals['update'],
                    $totals['unchanged'],
                    $totals['skipped'],
                ));

                return EXIT_SUCCESS;
            }

            $completed = service('ldapSyncWorkflow')->run(
                $connection,
                $config->localAccounts,
                $apply,
                fn (SyncStatus $status, string $identifier) => $this->write(sprintf(
                    '%s %s',
                    $this->displayStatus($status, $apply),
                    json_encode($identifier, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
                )),
                fn (LDAPException $exception) => $this->error($exception->getMessage()),
                fn (array $totals) => $this->writeSummary($totals, $apply),
            );

            return $completed ? EXIT_SUCCESS : EXIT_ERROR;
        } catch (LDAPException $exception) {
            $this->error($exception->getMessage());

            return EXIT_ERROR;
        }
    }

    /**
     * @param array{create: int, update: int, unchanged: int, skipped: int, conflicts: int} $totals
     */
    private function writeSummary(array $totals, bool $apply): void
    {
        $this->write(sprintf(
            'Summary: %s=%d %s=%d unchanged=%d skipped=%d conflicts=%d',
            $this->displayStatus(SyncStatus::Create, $apply),
            $totals['create'],
            $this->displayStatus(SyncStatus::Update, $apply),
            $totals['update'],
            $totals['unchanged'],
            $totals['skipped'],
            $totals['conflicts'],
        ));
    }

    private function displayStatus(SyncStatus $status, bool $apply): string
    {
        return match ($status) {
            SyncStatus::Create => $apply ? 'created' : 'would_create',
            SyncStatus::Update => $apply ? 'updated' : 'would_update',
            default            => $status->value,
        };
    }
}
