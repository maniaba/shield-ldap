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
use JsonException;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserEnumerationInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Previews or applies provisioning and profile synchronization for a directory.
 */
final class SyncLDAPUsers extends BaseCommand
{
    private const USER_CONFLICTS = ['identity_conflict', 'invalid_identity', 'invalid_profile'];

    protected $name        = 'shield:ldap-sync';
    protected $description = 'Preview or synchronize eligible LDAP users.';
    protected $usage       = 'shield:ldap-sync <connection> [--apply]';
    protected $arguments   = [
        'connection' => 'LDAP connection ID from AuthLDAP.',
    ];
    protected $options = [
        '--apply' => 'Apply the configured provisioning and profile updates.',
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

        if (! is_string($connectionId) || $connectionId === ''
                                       || ($apply && $params['apply'] !== null)
                                       || array_diff_key($params, [0 => true, 'apply' => true]) !== []
        ) {
            $this->error($this->usage);

            return EXIT_ERROR;
        }

        try {
            $config     = config('AuthLDAP');
            $connection = $config->getConnection($connectionId);
            $directory  = service('ldapDirectory');

            if ($connection->id !== $connectionId || ! $directory instanceof LDAPUserEnumerationInterface) {
                throw new LDAPException('invalid_configuration');
            }

            if (! $connection->verifyCertificate) {
                throw new LDAPException('tls_verification_required');
            }

            return $this->synchronize($connection, $directory, $config->localAccounts, $apply);
        } catch (LDAPException $exception) {
            $this->error($exception->getMessage());

            return EXIT_ERROR;
        }
    }

    /**
     * @param array<array-key, int|string> $localAccounts
     */
    private function synchronize(LDAPConnection $connection, LDAPUserEnumerationInterface $directory, array $localAccounts, bool $apply): int
    {
        $stage = @tmpfile();
        if ($stage === false) {
            throw new LDAPException('synchronization_conflict');
        }

        $totals = ['create' => 0, 'update' => 0, 'unchanged' => 0, 'skipped' => 0, 'conflicts' => 0];

        try {
            [$names, $totals['conflicts']] = $this->stageUsers($stage, $connection, $directory);
            if (! rewind($stage)) {
                throw new LDAPException('synchronization_conflict');
            }

            $resolver = new LDAPUserResolver(auth()->getProvider());

            while (($line = fgets($stage)) !== false) {
                [$externalId, $profile] = $this->decodeUser($line);
                $username               = $profile['username'] ?? null;

                try {
                    if ($username !== null && ($names[strtolower($username)] ?? 0) > 1) {
                        throw new LDAPException('identity_conflict');
                    }

                    $status = $resolver->synchronize($connection, $externalId, $profile, $localAccounts, $apply);
                } catch (LDAPException $exception) {
                    $this->reportUserConflict($exception);
                    $totals['conflicts']++;

                    continue;
                }

                $totals[$status]++;
                $this->write(sprintf(
                    '%s %s',
                    $this->displayStatus($status, $apply),
                    json_encode($username ?? $externalId, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
                ));
            }

            if (! feof($stage)) {
                throw new LDAPException('synchronization_conflict');
            }
        } finally {
            fclose($stage);
            $this->write(sprintf(
                'Summary: %s=%d %s=%d unchanged=%d skipped=%d conflicts=%d',
                $this->displayStatus('create', $apply),
                $totals['create'],
                $this->displayStatus('update', $apply),
                $totals['update'],
                $totals['unchanged'],
                $totals['skipped'],
                $totals['conflicts'],
            ));
        }

        return $totals['conflicts'] > 0 ? EXIT_ERROR : EXIT_SUCCESS;
    }

    /**
     * Collect and validate the directory results before making local changes.
     *
     * @param resource $stage
     *
     * @return array{array<array-key, int>, int} Username counts and entry conflicts.
     */
    private function stageUsers($stage, LDAPConnection $connection, LDAPUserEnumerationInterface $directory): array
    {
        $seen      = [];
        $names     = [];
        $conflicts = 0;

        foreach ($directory->scanUsers($connection) as $entry) {
            try {
                $externalId = LDAPUserResolver::externalId($connection, $entry['attributes']);
                $key        = hash('sha256', $externalId);
                $dn         = hash('sha256', $entry['dn']);

                if (isset($seen[$key])) {
                    if ($seen[$key] !== $dn) {
                        throw new LDAPException('ambiguous_user');
                    }

                    continue;
                }

                $seen[$key] = $dn;
                $profile    = LDAPUserResolver::profile($connection, $entry['attributes']);
            } catch (LDAPException $exception) {
                $this->reportUserConflict($exception);
                $conflicts++;

                continue;
            }

            if (isset($profile['username'])) {
                $name         = strtolower($profile['username']);
                $names[$name] = ($names[$name] ?? 0) + 1;
            }

            // Stage mapped values on disk to keep LDAP pages out of memory.
            $line = json_encode([base64_encode($externalId), array_map(base64_encode(...), $profile)], JSON_THROW_ON_ERROR) . "\n";
            if (fwrite($stage, $line) !== strlen($line)) {
                throw new LDAPException('synchronization_conflict');
            }
        }

        return [$names, $conflicts];
    }

    /**
     * @return array{string, array<string, string>}
     */
    private function decodeUser(string $line): array
    {
        try {
            $row = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new LDAPException('synchronization_conflict');
        }

        if (! is_array($row) || ! is_string($row[0] ?? null) || ! is_array($row[1] ?? null)) {
            throw new LDAPException('synchronization_conflict');
        }

        $externalId = base64_decode($row[0], true);
        if ($externalId === false) {
            throw new LDAPException('synchronization_conflict');
        }

        $profile = [];

        foreach ($row[1] as $field => $encoded) {
            if (! is_string($field) || ! is_string($encoded)) {
                throw new LDAPException('synchronization_conflict');
            }

            $value = base64_decode($encoded, true);
            if ($value === false) {
                throw new LDAPException('synchronization_conflict');
            }

            $profile[$field] = $value;
        }

        return [$externalId, $profile];
    }

    private function reportUserConflict(LDAPException $exception): void
    {
        if (! in_array($exception->reason, self::USER_CONFLICTS, true)) {
            throw $exception;
        }

        $this->error($exception->getMessage());
    }

    private function displayStatus(string $status, bool $apply): string
    {
        return match ($status) {
            'create' => $apply ? 'created' : 'would_create',
            'update' => $apply ? 'updated' : 'would_update',
            default  => $status,
        };
    }
}
