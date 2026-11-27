<?php

declare(strict_types=1);

use Boundwize\StructArmed\Architecture;
use Boundwize\StructArmed\Preset\Preset;
use Boundwize\StructArmed\Rule\Rules\Class_\MustBeFinalRule;

return Architecture::define()
    ->withPresets(Preset::PSR4(), Preset::CODEQUALITY())
    ->cacheDirectory(__DIR__ . '/build/structarmed')
    ->layer('tests', __DIR__ . '/tests')
    ->rule('tests.must_be_final', new MustBeFinalRule(layer: 'tests'));
