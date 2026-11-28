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

use stdClass;

/**
 * A contact read from LDAP. A null address clears the stored contact.
 *
 * @internal
 */
final readonly class LDAPContactEmail
{
    private const METADATA_KEY = 'shield_ldap_contact_email';

    public ?string $address;

    public function __construct(?string $address)
    {
        $this->address = $address === null ? null : self::validAddress($address);
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    public static function fromDirectory(LDAPConnection $connection, array $attributes): ?self
    {
        if ($connection->contactEmailAttribute === null) {
            return null;
        }

        $values = $attributes[strtolower($connection->contactEmailAttribute)] ?? [];

        return new self(count($values) === 1 ? $values[0] : null);
    }

    public static function read(?string $extra): ?string
    {
        $value = self::decode($extra)->{self::METADATA_KEY} ?? null;

        return is_string($value) ? self::validAddress($value) : null;
    }

    /**
     * Preserve unrelated properties and leave opaque metadata as it was.
     */
    public function updateExtra(?string $extra): ?string
    {
        $metadata = self::decode($extra);
        $key      = self::METADATA_KEY;

        if ($metadata === null || ($metadata->{$key} ?? null) === $this->address && ($this->address !== null || ! property_exists($metadata, $key))) {
            return $extra;
        }

        if ($this->address === null) {
            unset($metadata->{$key});
            if (get_object_vars($metadata) === []) {
                return null;
            }
        } else {
            $metadata->{$key} = $this->address;
        }

        $encoded = json_encode($metadata, JSON_PRESERVE_ZERO_FRACTION);

        return $encoded === false ? $extra : $encoded;
    }

    private static function decode(?string $extra): ?stdClass
    {
        if ($extra === null || $extra === '') {
            return new stdClass();
        }

        $metadata = json_decode($extra);

        return $metadata instanceof stdClass ? $metadata : null;
    }

    private static function validAddress(string $value): ?string
    {
        $address = trim($value, ' ');

        return strlen($address) <= 254
            && preg_match('/[\x00-\x1f\x7f,]/', $address) === 0
            && filter_var($address, FILTER_VALIDATE_EMAIL) !== false
            ? $address
            : null;
    }
}
