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
 * Optional paged discovery of direct group membership for administrative synchronization.
 */
interface LDAPGroupEnumerationInterface extends LDAPDirectoryInterface
{
    /**
     * Enumerate eligible users with their immutable ID and verified mapped Shield group keys.
     * Include matchedGroups as an empty list for a user with no matches.
     *
     * @return iterable<int, array{dn: string, attributes: array<string, list<string>>, matchedGroups?: list<string>}>
     *
     * @throws LDAPException If user discovery or membership verification is incomplete.
     */
    public function scanGroupMemberships(LDAPConnection $connection, int $pageSize = 100): iterable;
}
