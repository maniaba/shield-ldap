<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
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
     * @return array{dn: string, attributes: array<string, list<string>>}
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
