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

use CodeIgniter\Shield\Models\UserModel;
use Config\Services as ApplicationServices;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\NativeLDAPDirectory;
use Maniaba\ShieldLDAP\Config\Services;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;
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

    public function testUsesTheConfiguredTransportForAdministrativeServices(): void
    {
        $directory = Services::ldapDirectory();

        $this->assertSame($directory, service('ldapUserLookup'));
        $this->assertSame($directory, service('ldapUserEnumeration'));
    }

    public function testRejectsALookupTransportWithoutTheCapability(): void
    {
        ApplicationServices::injectMock('ldapDirectory', $this->createStub(LDAPDirectoryInterface::class));

        try {
            service('ldapUserLookup');
            $this->fail('The transport lacks the lookup capability.');
        } catch (LDAPException $exception) {
            $this->assertSame(LDAPReason::InvalidConfiguration, $exception->kind);
        }
    }

    public function testResolverWithExplicitProviderIsIndependentOfTheSharedResolver(): void
    {
        $provider = $this->createStub(UserModel::class);
        $shared   = service('ldapUserResolver');

        $this->assertSame($shared, service('ldapUserResolver'));
        $this->assertNotSame($shared, service('ldapUserResolver', $provider));
        $this->assertSame($shared, service('ldapUserResolver'));
    }
}
