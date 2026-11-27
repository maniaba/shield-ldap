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
