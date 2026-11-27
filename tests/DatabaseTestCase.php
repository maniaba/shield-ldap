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

namespace Maniaba\ShieldLDAP\Tests;

use CodeIgniter\Shield\Config\Auth;
use CodeIgniter\Test\DatabaseTestTrait;

/**
 * @internal
 */
abstract class DatabaseTestCase extends TestCase
{
    use DatabaseTestTrait;

    protected $namespace = '\CodeIgniter\Shield';

    /**
     * Auth Table names
     */
    protected array $tables;

    protected function setUp(): void
    {
        parent::setUp();

        /** @var Auth $authConfig */
        $authConfig   = config('Auth');
        $this->tables = $authConfig->tables;
    }
}
