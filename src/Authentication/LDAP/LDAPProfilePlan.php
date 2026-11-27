<?php

declare(strict_types=1);

/**
 * This file is part of Shield LDAP.
 *
 * (c) 2026 maniaba
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Maniaba\ShieldLDAP\Authentication\LDAP;

/**
 * The inputs and expected outcome of a read-only profile synchronization preview.
 */
final readonly class LDAPProfilePlan
{
    /**
     * Retain the inputs for revalidation against local state at apply time.
     *
     * @param array<string, string|null>   $profile
     * @param array<array-key, int|string> $localAccounts
     */
    public function __construct(
        public LDAPConnection $connection,
        public string $externalId,
        public array $profile,
        public array $localAccounts,
        public SyncStatus $status,
    ) {
    }
}
