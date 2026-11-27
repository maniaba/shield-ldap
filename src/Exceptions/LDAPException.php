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
use Throwable;

/**
 * Reports LDAP failures using sanitized diagnostic reason codes.
 */
final class LDAPException extends RuntimeException
{
    public readonly string $reason;
    public readonly ?LDAPReason $kind;

    /**
     * Localizes the failure and retains any underlying operational error.
     */
    public function __construct(LDAPReason|string $reason, ?Throwable $previous = null)
    {
        $this->kind   = $reason instanceof LDAPReason ? $reason : LDAPReason::tryFrom($reason);
        $this->reason = $reason instanceof LDAPReason ? $reason->value : $reason;

        parent::__construct(lang('ShieldLDAP.operationFailed', [$this->reason]), 0, $previous);
    }
}
