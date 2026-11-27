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
use Maniaba\ShieldLDAP\Authentication\LDAP\LinkStatus;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Previews, creates, and repairs LDAP links for existing Shield users.
 */
final class LinkLDAPUser extends BaseCommand
{
    protected $name        = 'shield:ldap-link';
    protected $description = 'Preview, create, or repair links between existing Shield accounts and LDAP.';
    protected $usage       = 'shield:ldap-link <connection> [<username>] [--all] [--apply] [--replace <new-ldap-id>]';
    protected $arguments   = [
        'connection' => 'LDAP connection ID from AuthLDAP.',
        'username'   => 'Existing Shield username to look up in the directory.',
    ];
    protected $options = [
        '--all'     => 'With --apply, add missing links for all users.',
        '--apply'   => 'Write links for the selected username or for --all.',
        '--replace' => 'Repair the selected username’s existing link using the specified new LDAP ID.',
    ];

    /**
     * Preview candidate identities or write the requested links.
     *
     * @param array<array-key, mixed> $params
     */
    public function run(array $params): int
    {
        $selection = $this->parseArguments($params);
        if ($selection === null) {
            $this->error($this->usage);

            return EXIT_ERROR;
        }

        [$connectionId, $username, $apply, $all, $replace] = $selection;

        try {
            $config     = config('AuthLDAP');
            $connection = $config->getConnection($connectionId);

            if ($connection->id !== $connectionId) {
                throw new LDAPException(LDAPReason::InvalidConfiguration);
            }

            return service('ldapLinkWorkflow')->run(
                $connection,
                $username,
                $config->localAccounts,
                $apply,
                $all,
                $replace,
                $this->writeResult(...),
                $this->writeSummary(...),
            ) ? EXIT_SUCCESS : EXIT_ERROR;
        } catch (LDAPException $exception) {
            $this->error($exception->getMessage());

            return EXIT_ERROR;
        }
    }

    /**
     * @param array<array-key, mixed> $params
     *
     * @return array{string, ?string, bool, bool, ?string}|null Connection, username, apply, all, and replacement ID.
     */
    private function parseArguments(array $params): ?array
    {
        if (array_diff_key($params, [0 => true, 1 => true, 'apply' => true, 'all' => true, 'replace' => true]) !== []) {
            return null;
        }

        $connectionId = $params[0] ?? null;
        $username     = $params[1] ?? null;
        $replace      = $params['replace'] ?? null;

        if (! is_string($connectionId) || $connectionId === '') {
            return null;
        }

        if ($username !== null && (! is_string($username) || trim($username) === '')) {
            return null;
        }

        if (array_key_exists('replace', $params) && (! is_string($replace) || $replace === '')) {
            return null;
        }

        if (isset($params['apply']) || isset($params['all'])) {
            return null;
        }

        $apply = array_key_exists('apply', $params);
        $all   = array_key_exists('all', $params);

        if ($all && (! $apply || $username !== null || $replace !== null)) {
            return null;
        }

        if (($apply && ! $all && $username === null) || ($replace !== null && ! $apply)) {
            return null;
        }

        return [$connectionId, $username, $apply, $all, $replace];
    }

    private function writeResult(int|string|null $userId, ?string $username, LDAPReason|LinkStatus $status, ?string $externalId): void
    {
        $label = $status->value;
        if ($externalId !== null) {
            $label .= ' LDAP ID ' . json_encode($externalId, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        }

        $this->write(sprintf(
            'Shield user %s %s %s',
            json_encode($userId, JSON_THROW_ON_ERROR),
            json_encode($username, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
            $label,
        ));
    }

    private function writeSummary(int $linked, int $skipped, int $conflicts): void
    {
        $this->write(sprintf('Summary: linked=%d skipped=%d conflicts=%d', $linked, $skipped, $conflicts));
    }
}
