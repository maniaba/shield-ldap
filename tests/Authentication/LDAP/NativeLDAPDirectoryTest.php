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

namespace Maniaba\ShieldLDAP\Tests\Authentication\LDAP;

use CodeIgniter\Shield\Exceptions\RuntimeException;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\NativeLDAPDirectory;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class NativeLDAPDirectoryTest extends TestCase
{
    public function testRedactsBindSecretInConfigurationInspection(): void
    {
        $connection = new LDAPConnection('test', ['ldap.example.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');

        $this->assertSame('readerPassword!', $connection->bindPassword());
        $this->assertStringNotContainsString('readerPassword!', print_r($connection, true));
        $this->assertStringNotContainsString('readerPassword!', var_export($connection, true));
        $this->assertStringNotContainsString('readerPassword!', json_encode($connection, JSON_THROW_ON_ERROR));
    }

    public function testInvalidEndpointThrowsLocalizedShieldException(): void
    {
        $language = service('language');
        $locale   = $language->getLocale();
        $language->setLocale('sr');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('LDAP operacija nije uspela (invalid_endpoint).');

        try {
            new LDAPConnection('test', ['ldap://example.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');
        } finally {
            $language->setLocale($locale);
        }
    }

    #[DataProvider('provideRejectsPasswordsBeforeContactingDirectory')]
    public function testRejectsPasswordsBeforeContactingDirectory(string $password): void
    {
        $connection = new LDAPConnection('test', ['invalid.test'], 'dc=example,dc=test', 'cn=reader,dc=example,dc=test', 'readerPassword!');

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_credentials');

        (new NativeLDAPDirectory())->authenticate($connection, $connection->baseDn, '(uid=alice)', [], $password);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRejectsPasswordsBeforeContactingDirectory(): iterable
    {
        yield 'empty password' => [''];

        yield 'NUL byte' => ["\0abc"];
    }
}
