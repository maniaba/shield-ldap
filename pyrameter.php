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

use Boundwize\Pyrameter\Config\PyrameterConfig;
use Boundwize\Pyrameter\TestKind;
use CodeIgniter\Test\DatabaseTestTrait;
use CodeIgniter\Test\FeatureTestTrait;
use Maniaba\ShieldLDAP\Tests\DatabaseTestCase;

return PyrameterConfig::create()
    ->usesClass(DatabaseTestTrait::class, TestKind::Integration, unless: [FeatureTestTrait::class])
    ->usesClass(DatabaseTestCase::class, TestKind::Integration, unless: [FeatureTestTrait::class])
    ->usesClass(FeatureTestTrait::class, TestKind::Functional)
    ->usesFunction('copy', TestKind::Integration)
    ->usesFunction('file_get_contents', TestKind::Integration)
    ->usesFunction('getcwd', TestKind::Integration)
    ->usesFunction('is_file', TestKind::Integration)
    ->usesFunction('unlink', TestKind::Integration)
    ->targetShape(
        unit: ['min' => 40],
        functional: ['max' => 20],
        integration: ['max' => 50],
        e2e: ['max' => 0],
    )
    ->failOnViolation();
