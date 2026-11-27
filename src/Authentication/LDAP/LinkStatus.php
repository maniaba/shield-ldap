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
 * Outcome of inspecting or writing one directory link.
 */
enum LinkStatus: string
{
    case Candidate     = 'candidate';
    case AlreadyLinked = 'already_linked';
    case StaleLink     = 'stale_link';
    case Linked        = 'linked';
    case Replaced      = 'replaced';
}
