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

use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Optional directory lookup for trusted administrative account linking.
 */
interface LDAPUserLookupInterface extends LDAPDirectoryInterface
{
    /**
     * Use the service account over verified TLS to locate exactly one entry
     * across the search bases, then confirm its eligibility and immutable ID.
     *
     * @param list<string>|string $baseDn
     *
     * @return array{dn: string, attributes: array<string, list<string>>} Contains the immutable ID under its lowercase attribute name.
     *
     * @throws LDAPException If the directory cannot confirm an eligible entry.
     */
    public function lookupUser(
        LDAPConnection $connection,
        array|string $baseDn,
        string $filter,
        string $eligibilityFilter = '(objectClass=*)',
    ): array;
}
