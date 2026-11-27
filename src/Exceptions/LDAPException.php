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

namespace Maniaba\ShieldLDAP\Exceptions;

use CodeIgniter\Shield\Exceptions\RuntimeException;

/**
 * Reports LDAP failures using sanitized diagnostic reason codes.
 */
final class LDAPException extends RuntimeException
{
    /**
     * Localizes the message for the supplied diagnostic reason code.
     */
    public function __construct(public readonly string $reason)
    {
        parent::__construct(lang('ShieldLDAP.operationFailed', [$reason]));
    }
}
