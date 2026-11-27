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

use CodeIgniter\CodingStandard\CodeIgniter4;
use Nexus\CsConfig\Factory;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->in(__DIR__)
    ->name('*.inc')
    ->ignoreDotFiles(false)
    ->exclude(['.idea', '.venv', 'build', 'site', 'tmp', 'vendor', 'writable']);

$overrides = [
    'declare_strict_types' => true,
    'void_return'          => true,
    'header_comment'       => [
        'comment_type' => 'PHPDoc',
        'header'       => <<<'HEADER'
            This file is part of Shield LDAP.

            Copyright (c) 2026 maniaba
            SPDX-License-Identifier: MIT

            See the LICENSE file for the full copyright and license information.
            HEADER,
    ],
];

$options = [
    'finder'    => $finder,
    'cacheFile' => 'build/.php-cs-fixer.cache',
];

return Factory::create(new CodeIgniter4(), $overrides, $options)->forProjects();
