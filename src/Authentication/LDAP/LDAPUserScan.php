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

use Closure;
use Generator;
use IteratorAggregate;
use LDAP\Connection;

/**
 * A single-pass directory scan that owns its connection during iteration.
 *
 * @phpstan-type DirectoryEntry array{dn: string, attributes: array<string, list<string>>}
 *
 * @implements IteratorAggregate<int, DirectoryEntry>
 */
final class LDAPUserScan implements IteratorAggregate
{
    private bool $canStart          = true;
    private ?Connection $connection = null;

    /**
     * Start the connection and its entries only when iteration begins.
     *
     * @param Closure(): array{Connection, iterable<int, DirectoryEntry>} $start
     */
    public function __construct(private readonly Closure $start)
    {
    }

    /**
     * Yield entries while the scan is open and close it when iteration finishes.
     *
     * @return Generator<int, DirectoryEntry>
     */
    public function getIterator(): Generator
    {
        if (! $this->canStart) {
            return;
        }

        $this->canStart = false;

        try {
            [$this->connection, $entries] = ($this->start)();

            foreach ($entries as $entry) {
                yield $entry;

                if (! $this->isOpen()) {
                    return;
                }
            }
        } finally {
            $this->close();
        }
    }

    /**
     * End the scan immediately, even while its iterator is still referenced.
     */
    public function close(): void
    {
        $this->canStart   = false;
        $connection       = $this->connection;
        $this->connection = null;

        if ($connection !== null) {
            ldap_unbind($connection);
        }
    }

    private function isOpen(): bool
    {
        return $this->connection !== null;
    }
}
