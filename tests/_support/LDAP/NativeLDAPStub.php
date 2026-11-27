<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Maniaba\ShieldLDAP\Tests\Support\LDAP;

/**
 * Scripted state for the LDAP functions loaded in isolated PHPUnit processes.
 */
final class NativeLDAPStub
{
    public static bool $available = true;

    /**
     * @var list<string>
     */
    public static array $connected = [];

    /**
     * @var list<array{string, string}> Ordered bind, search, and read operations with their DN.
     */
    public static array $operations = [];

    public static int $unbound = 0;

    /**
     * @var array<string, int> Endpoints whose service bind fails with the given LDAP code.
     */
    public static array $bindErrors = [];

    public static bool $warnOnBindFailure = false;
    public static int $lastError          = 0;
    public static string $diagnostic      = '';
    public static bool $searchFails       = false;
    public static int $searchCode         = 0;
    public static bool $hasReference      = false;

    /**
     * @var list<string> Distinguished names in the search result.
     */
    public static array $entries = [];

    /**
     * @var array<string, list<string>> Distinguished names returned for a given search base.
     */
    public static array $entriesByBase = [];

    /**
     * @var array<string, int> LDAP result code returned for a given search base.
     */
    public static array $searchCodesByBase = [];

    /**
     * @var array<string, array<string, list<string>>> Attribute values keyed by entry DN and lowercase attribute name.
     */
    public static array $attributesByDn = [];
}
