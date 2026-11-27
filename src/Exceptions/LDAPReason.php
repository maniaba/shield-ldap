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

namespace Maniaba\ShieldLDAP\Exceptions;

/**
 * Built-in sanitized LDAP failure codes.
 */
enum LDAPReason: string
{
    case AmbiguousLocalUser                 = 'ambiguous_local_user';
    case AmbiguousUser                      = 'ambiguous_user';
    case CertificateVerificationFailed      = 'certificate_verification_failed';
    case ConnectionConfigurationFailed      = 'connection_configuration_failed';
    case ConnectionTimeout                  = 'connection_timeout';
    case DirectoryIdentityChanged           = 'directory_identity_changed';
    case DirectoryUnavailable               = 'directory_unavailable';
    case DuplicateDirectoryIdentity         = 'duplicate_directory_identity';
    case ExtensionUnavailable               = 'extension_unavailable';
    case IdentityConflict                   = 'identity_conflict';
    case IncompleteSearch                   = 'incomplete_search';
    case IneligibleUser                     = 'ineligible_user';
    case InvalidAttribute                   = 'invalid_attribute';
    case InvalidBindSecret                  = 'invalid_bind_secret';
    case InvalidConfiguration               = 'invalid_configuration';
    case InvalidCredentials                 = 'invalid_credentials';
    case InvalidDirectoryEntry              = 'invalid_directory_entry';
    case InvalidDnComponent                 = 'invalid_dn_component';
    case InvalidEndpoint                    = 'invalid_endpoint';
    case InvalidExternalIdentity            = 'invalid_external_identity';
    case InvalidFilter                      = 'invalid_filter';
    case InvalidFilterValue                 = 'invalid_filter_value';
    case InvalidIdentity                    = 'invalid_identity';
    case InvalidProfile                     = 'invalid_profile';
    case InvalidSearch                      = 'invalid_search';
    case InvalidSearchLimit                 = 'invalid_search_limit';
    case LocalUserNotFound                  = 'local_user_not_found';
    case ReservedLocalAccount               = 'reserved_local_account';
    case ScanLimitExceeded                  = 'scan_limit_exceeded';
    case SearchFailed                       = 'search_failed';
    case SearchTimeout                      = 'search_timeout';
    case ServiceBindFailed                  = 'service_bind_failed';
    case SynchronizationConflict            = 'synchronization_conflict';
    case TlsContextFailed                   = 'tls_context_failed';
    case TlsFailed                          = 'tls_failed';
    case TlsVerificationOverrideUnsupported = 'tls_verification_override_unsupported';
    case TlsVerificationRequired            = 'tls_verification_required';
    case UnsupportedLdapClient              = 'unsupported_ldap_client';
    case UserBindFailed                     = 'user_bind_failed';
    case UserNotFound                       = 'user_not_found';
    case UserNotProvisioned                 = 'user_not_provisioned';

    /**
     * Return whether this failure marks an account that bulk linking can skip.
     */
    public function isLinkSkip(): bool
    {
        return match ($this) {
            self::IneligibleUser, self::InvalidProfile, self::ReservedLocalAccount, self::UserNotFound => true,
            default                                                                                    => false,
        };
    }

    /**
     * Return whether this failure marks a per-account linking conflict.
     */
    public function isLinkConflict(): bool
    {
        return match ($this) {
            self::AmbiguousLocalUser, self::AmbiguousUser, self::DirectoryIdentityChanged, self::DuplicateDirectoryIdentity,
            self::IdentityConflict, self::InvalidExternalIdentity, self::InvalidIdentity, self::LocalUserNotFound => true,
            default                                                                                               => false,
        };
    }

    /**
     * Return whether synchronization can continue with other accounts.
     */
    public function isSyncConflict(): bool
    {
        return match ($this) {
            self::IdentityConflict, self::InvalidIdentity, self::InvalidProfile => true,
            default                                                             => false,
        };
    }

    /**
     * Return whether opening the connection may try the next endpoint.
     */
    public function isRetryableEndpointFailure(): bool
    {
        return match ($this) {
            self::ConnectionTimeout, self::DirectoryUnavailable, self::SearchTimeout => true,
            default                                                                  => false,
        };
    }
}
