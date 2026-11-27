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

namespace Maniaba\ShieldLDAP\Tests\Unit;

use Maniaba\ShieldLDAP\Authentication\LDAP\NativeLDAPDirectory;
use Maniaba\ShieldLDAP\Config\Services;
use Maniaba\ShieldLDAP\Tests\TestCase;

/**
 * @internal
 */
final class LDAPServicesTest extends TestCase
{
    public function testSharesTheDirectoryByDefault(): void
    {
        $directory = Services::ldapDirectory();

        $this->assertInstanceOf(NativeLDAPDirectory::class, $directory);
        $this->assertSame($directory, Services::ldapDirectory(true));
        $this->assertSame($directory, service('ldapDirectory'));
    }

    public function testNonSharedDirectoryCallsCreateIndependentInstances(): void
    {
        $first  = Services::ldapDirectory(false);
        $second = Services::ldapDirectory(false);
        $shared = Services::ldapDirectory();

        $this->assertInstanceOf(NativeLDAPDirectory::class, $first);
        $this->assertNotSame($first, $second);
        $this->assertNotSame($first, $shared);
        $this->assertNotSame($second, $shared);
    }
}
