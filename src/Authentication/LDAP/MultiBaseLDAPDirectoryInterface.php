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

/**
 * Directory operations that support authentication across multiple search bases.
 */
interface MultiBaseLDAPDirectoryInterface extends LDAPDirectoryInterface
{
    /**
     * {@inheritDoc}
     *
     * Establish that exactly one directory entry matches across all search bases
     * before verifying the submitted password.
     *
     * @param list<string>|string $baseDn
     * @param list<string>        $attributes
     *
     * @return array{dn: string, attributes: array<string, list<string>>, matchedGroups?: list<string>}
     */
    public function authenticate(
        LDAPConnection $connection,
        array|string $baseDn,
        string $filter,
        array $attributes,
        string $password,
        string $eligibilityFilter = '(objectClass=*)',
    ): array;
}
