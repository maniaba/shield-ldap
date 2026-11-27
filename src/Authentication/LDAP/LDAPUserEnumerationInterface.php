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

use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Optional paged discovery of directory users for synchronization.
 */
interface LDAPUserEnumerationInterface extends LDAPDirectoryInterface
{
    /**
     * Enumerate eligible users in the configured search bases over verified TLS.
     *
     * Returned attribute names are lowercase. The configured ID and profile
     * attributes are included when present.
     *
     * @return iterable<int, array{dn: string, attributes: array<string, list<string>>}>
     *
     * @throws LDAPException If a search fails or its results are incomplete.
     */
    public function scanUsers(LDAPConnection $connection, int $pageSize = 100): iterable;
}
