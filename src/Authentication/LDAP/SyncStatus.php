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
 * Action selected for an eligible directory entry.
 */
enum SyncStatus: string
{
    case Create    = 'create';
    case Update    = 'update';
    case Unchanged = 'unchanged';
    case Skipped   = 'skipped';
}
