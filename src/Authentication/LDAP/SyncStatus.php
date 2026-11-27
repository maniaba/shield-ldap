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
 * Action selected for an eligible directory entry.
 */
enum SyncStatus: string
{
    case Create    = 'create';
    case Update    = 'update';
    case Unchanged = 'unchanged';
    case Skipped   = 'skipped';
}
