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

namespace Maniaba\ShieldLDAP\Config;

use CodeIgniter\Config\BaseConfig;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;
use Throwable;

/**
 * Opt-in LDAP settings for choosing a directory or an explicitly reserved local account at login.
 */
class AuthLDAP extends BaseConfig
{
    /**
     * Gate LDAP login even when the authenticator alias is registered.
     */
    public bool $enabled = false;

    /**
     * Connection ID used when the login identifier has no mapped UPN suffix.
     */
    public string $defaultConnection = '';

    /**
     * Directory settings keyed by connection ID. Declare options in the array
     * to allow CodeIgniter overrides through authldap.connections.<id>.<option>.
     *
     * @var array<string, array<string, mixed>>
     */
    public array $connections = [
        // 'corporate' => [
        //     'hosts'               => ['dc01.example.com', 'dc02.example.com'],
        //     'baseDn'              => 'DC=example,DC=com',
        //     'bindDn'              => 'CN=shield-reader,OU=Service Accounts,DC=example,DC=com',
        //     'bindPassword'        => '',
        //     'encryption'          => 'ldaps',
        //     'verifyCertificate'   => true,
        //     'userBaseDn'          => 'OU=Users,DC=example,DC=com',
        //     'loginFilter'         => '(&(objectCategory=person)(objectClass=user))',
        //     'loginAttributes'     => ['sAMAccountName', 'userPrincipalName'],
        //     'externalIdAttribute' => 'objectGUID',
        //     'profileAttributes'   => ['username' => 'sAMAccountName'],
        //     'contactEmailAttribute' => 'mail',
        //     'groupMappings'       => ['user' => 'CN=Users Group,OU=Groups,DC=example,DC=com'],
        //     'syncGroupsOnLogin'   => true,
        //     'syncProfileOnLogin'  => true,
        // ],
    ];

    /**
     * @var array<string, string> Lowercase UPN suffix to connection ID.
     */
    public array $loginDomains = [];

    /**
     * @var array<string, int|string> Case-insensitive login identifier to expected local user ID.
     */
    public array $localAccounts = [];

    /**
     * Table names for Shield LDAP persistence.
     *
     * @var array{ldap_group_grants: string}
     */
    public array $tables = [
        'ldap_group_grants' => 'shield_ldap_group_grants',
    ];

    /**
     * Resolve the tracking table, preferring the application's Shield configuration.
     */
    public function getGroupGrantsTable(): string
    {
        return config('Auth')->tables['ldap_group_grants'] ?? $this->tables['ldap_group_grants'];
    }

    /**
     * Retrieve the settings for the specified connection ID.
     *
     * Override this method to load a named connection from an application-owned provider.
     *
     * @throws LDAPException If the connection settings or bind password are missing or invalid.
     */
    public function getConnection(string $id): LDAPConnection
    {
        $settings = $this->connections[$id] ?? null;

        if (! is_array($settings)
            || ! isset($settings['hosts'], $settings['baseDn'], $settings['bindDn'])
            || array_filter($settings, is_string(...), ARRAY_FILTER_USE_KEY) !== $settings
        ) {
            throw new LDAPException(LDAPReason::InvalidConfiguration);
        }

        try {
            return new LDAPConnection(
                $id,
                $settings['hosts'],
                $settings['baseDn'],
                $settings['bindDn'],
                $settings['bindPassword'] ?? '',
                ...array_diff_key($settings, ['hosts' => true, 'baseDn' => true, 'bindDn' => true, 'bindPassword' => true]),
            );
        } catch (Throwable $exception) {
            // The constructor received the raw bind password as an argument.
            throw new LDAPException($exception instanceof LDAPException ? $exception->reason : LDAPReason::InvalidConfiguration);
        }
    }

    /**
     * List the connection IDs declared in the configuration.
     *
     * @return list<string>
     */
    public function connectionIds(): array
    {
        return array_keys($this->connections);
    }

    /**
     * Omit bind passwords from the PHP debug representation of this config.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        $configuration = get_object_vars($this);

        foreach (array_filter($this->connections, is_array(...)) as $id => $settings) {
            $configuration['connections'][$id] = array_diff_key($settings, ['bindPassword' => true]);
        }

        return $configuration;
    }
}
