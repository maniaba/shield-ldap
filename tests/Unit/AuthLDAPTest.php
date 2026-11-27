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

use Maniaba\ShieldLDAP\Config\AuthLDAP;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * @internal
 */
final class AuthLDAPTest extends TestCase
{
    private const CONNECTION_METADATA = [
        'hosts'               => ['ldap.example.test', 'ldap-backup.example.test'],
        'baseDn'              => 'dc=example,dc=test',
        'bindDn'              => 'cn=reader,dc=example,dc=test',
        'bindPassword'        => 'metadata-test-password',
        'encryption'          => 'starttls',
        'port'                => 1389,
        'connectTimeout'      => 4,
        'searchTimeout'       => 8,
        'userBaseDn'          => 'ou=users,dc=example,dc=test',
        'loginFilter'         => '(objectClass=inetOrgPerson)',
        'loginAttributes'     => ['cn', 'mail'],
        'externalIdAttribute' => 'objectGUID',
        'profileAttributes'   => ['email' => 'mail'],
        'provisionUsers'      => true,
        'eligibilityFilter'   => '(accountStatus=active)',
        'updateProfile'       => false,
        'verifyCertificate'   => true,
        'groupMappings'       => ['user' => 'cn=users,ou=groups,dc=example,dc=test'],
    ];

    public function testDefaultConfigurationHasNoConnections(): void
    {
        $this->assertSame([], (new AuthLDAP())->connectionIds());
    }

    public function testBuildsConnectionFromConfiguredMetadata(): void
    {
        $metadata = self::CONNECTION_METADATA;
        unset($metadata['bindPassword']);

        $config              = new AuthLDAP();
        $config->connections = [
            'missing-bind-secret-test' => $metadata,
            'corporate'                => self::CONNECTION_METADATA,
        ];

        $this->assertSame(['missing-bind-secret-test', 'corporate'], $config->connectionIds());

        $connection = $config->getConnection('corporate');

        $this->assertSame('corporate', $connection->id);
        $this->assertSame($metadata, array_intersect_key(get_object_vars($connection), $metadata));
        $this->assertSame('metadata-test-password', $connection->bindPassword());
    }

    public function testAcceptsExplicitCertificateVerificationOptOut(): void
    {
        $config              = new AuthLDAP();
        $config->connections = ['corporate' => ['verifyCertificate' => false] + self::CONNECTION_METADATA];

        $this->assertFalse($config->getConnection('corporate')->verifyCertificate);
    }

    /**
     * @param list<string> $userBaseDns
     */
    #[DataProvider('provideAcceptsOrderedUserBaseDnLists')]
    public function testAcceptsOrderedUserBaseDnLists(array $userBaseDns): void
    {
        $config              = new AuthLDAP();
        $config->connections = ['corporate' => ['userBaseDn' => $userBaseDns] + self::CONNECTION_METADATA];
        $connection          = $config->getConnection('corporate');

        $this->assertSame(self::CONNECTION_METADATA['baseDn'], $connection->baseDn);
        $this->assertSame($userBaseDns, $connection->userBaseDn);
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function provideAcceptsOrderedUserBaseDnLists(): iterable
    {
        yield 'single base DN' => [['ou=users,dc=example,dc=test']];

        yield 'ten base DNs' => [array_map(
            static fn (int $id): string => "ou=team{$id},dc=example,dc=test",
            range(10, 1),
        )];
    }

    #[DataProvider('provideLoadsNestedEnvironmentOverrides')]
    public function testLoadsNestedEnvironmentOverrides(string $separator): void
    {
        $overrides = [
            'authldap.connections.corporate.bindPassword'      => 'environment-test-password',
            'authldap.connections.corporate.hosts.0'           => 'ldap-env.example.test',
            'authldap.connections.corporate.port'              => '1636',
            'authldap.connections.corporate.provisionUsers'    => 'false',
            'authldap.connections.corporate.verifyCertificate' => 'false',
        ];

        $original = [];

        try {
            foreach ($overrides as $name => $value) {
                $key            = str_replace('.', $separator, $name);
                $original[$key] = getenv($key);
                putenv($key . '=' . $value);
            }

            // Seed defaults before BaseConfig loads the nested environment overrides.
            $reflection          = new ReflectionClass(AuthLDAP::class);
            $config              = $reflection->newInstanceWithoutConstructor();
            $config->connections = ['corporate' => self::CONNECTION_METADATA];
            $reflection->getConstructor()?->invoke($config);

            $connection = $config->getConnection('corporate');

            $this->assertSame('environment-test-password', $connection->bindPassword());
            $this->assertSame(['ldap-env.example.test', 'ldap-backup.example.test'], $connection->hosts);
            $this->assertSame(1636, $connection->port);
            $this->assertFalse($connection->provisionUsers);
            $this->assertFalse($connection->verifyCertificate);
        } finally {
            foreach ($original as $key => $value) {
                putenv($value === false ? $key : $key . '=' . $value);
            }
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLoadsNestedEnvironmentOverrides(): iterable
    {
        yield 'dotted' => ['.'];

        yield 'underscored' => ['_'];
    }

    public function testRedactsBindPasswordFromDiagnosticOutput(): void
    {
        $config              = new AuthLDAP();
        $config->connections = ['corporate' => self::CONNECTION_METADATA];
        $connection          = $config->getConnection('corporate');

        $this->assertStringNotContainsString('metadata-test-password', print_r($config, true));
        $this->assertStringNotContainsString('metadata-test-password', var_export($connection, true));
    }

    /**
     * @param array<string, mixed> $settings
     */
    #[DataProvider('provideRejectsMissingOrEmptyBindPassword')]
    public function testRejectsMissingOrEmptyBindPassword(array $settings): void
    {
        $config              = new AuthLDAP();
        $config->connections = ['missing-bind-secret-test' => $settings];

        $this->assertSame(['missing-bind-secret-test'], $config->connectionIds());

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_bind_secret');

        $config->getConnection('missing-bind-secret-test');
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideRejectsMissingOrEmptyBindPassword(): iterable
    {
        yield 'missing' => [array_diff_key(self::CONNECTION_METADATA, ['bindPassword' => true])];

        yield 'empty' => [['bindPassword' => ''] + self::CONNECTION_METADATA];
    }

    /**
     * @param array<array-key, mixed> $options
     */
    #[DataProvider('provideRejectsInvalidConnectionOptions')]
    public function testRejectsInvalidConnectionOptions(array $options): void
    {
        $config              = new AuthLDAP();
        $config->connections = ['corporate' => $options + self::CONNECTION_METADATA];

        try {
            $config->getConnection('corporate');
            $this->fail('Invalid connection options must be rejected.');
        } catch (LDAPException $exception) {
            $this->assertSame('invalid_configuration', $exception->reason);
            $this->assertStringNotContainsString('metadata-test-password', $exception->getMessage());
            $this->assertNull($exception->getPrevious());
        }
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideRejectsInvalidConnectionOptions(): iterable
    {
        yield 'nested connection ID' => [['id' => 'invalid-inline-id']];

        yield 'invalid port type' => [['port' => 'not-a-port']];

        yield 'invalid certificate verification type' => [['verifyCertificate' => 'not-a-bool']];

        yield 'group mappings as list' => [['groupMappings' => ['cn=users,dc=example,dc=test']]];

        yield 'empty Shield group key' => [['groupMappings' => ['' => 'cn=users,dc=example,dc=test']]];

        yield 'LDAP group DN as list' => [['groupMappings' => ['user' => ['cn=users,dc=example,dc=test']]]];

        yield 'blank LDAP group DN' => [['groupMappings' => ['user' => '  ']]];

        yield 'numeric host' => [['hosts' => [123]]];

        yield 'positional option' => [['starttls']];

        yield 'blank base DN' => [['baseDn' => '   ']];

        yield 'base DN with NUL byte' => [['baseDn' => "dc=example\0,dc=test"]];

        yield 'list used as base DN' => [['baseDn' => ['dc=example,dc=test']]];

        yield 'blank user base DN' => [['userBaseDn' => '   ']];

        yield 'user base DN with NUL byte' => [['userBaseDn' => "dc=example\0,dc=test"]];

        yield 'empty user base DN list' => [['userBaseDn' => []]];

        yield 'too many user base DNs' => [['userBaseDn' => array_fill(0, 11, 'dc=example,dc=test')]];

        yield 'associative user base DNs' => [['userBaseDn' => ['people' => 'dc=example,dc=test']]];

        yield 'non-contiguous user base DN indexes' => [['userBaseDn' => [0 => 'ou=people,dc=example,dc=test', 2 => 'ou=employees,dc=example,dc=test']]];

        yield 'numeric user base DN entry' => [['userBaseDn' => [123]]];

        yield 'blank user base DN entry' => [['userBaseDn' => ['dc=example,dc=test', '   ']]];

        yield 'user base DN entry with NUL byte' => [['userBaseDn' => ["dc=example\0,dc=test"]]];
    }

    public function testRejectsUnknownConnectionId(): void
    {
        $config              = new AuthLDAP();
        $config->connections = ['corporate' => self::CONNECTION_METADATA];

        $this->expectException(LDAPException::class);
        $this->expectExceptionMessage('invalid_configuration');

        $config->getConnection('unknown');
    }
}
