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

namespace Maniaba\ShieldLDAP\Config;

use CodeIgniter\Config\BaseService;
use CodeIgniter\Shield\Models\UserModel;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPDirectoryInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPLinkService;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPLinkWorkflow;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPProfileSynchronizer;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPSyncWorkflow;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserEnumerationInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserLookupInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Authentication\LDAP\NativeLDAPDirectory;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

class Services extends BaseService
{
    /**
     * Supplies the directory transport used for LDAP sign-in and diagnostics.
     */
    public static function ldapDirectory(bool $getShared = true): LDAPDirectoryInterface
    {
        if ($getShared) {
            return self::getSharedInstance('ldapDirectory');
        }

        return new NativeLDAPDirectory();
    }

    /**
     * Supplies the configured directory's administrative user lookup.
     */
    public static function ldapUserLookup(bool $getShared = true): LDAPUserLookupInterface
    {
        if ($getShared) {
            return self::getSharedInstance('ldapUserLookup');
        }

        $directory = service('ldapDirectory');

        if (! $directory instanceof LDAPUserLookupInterface) {
            throw new LDAPException(LDAPReason::InvalidConfiguration);
        }

        return $directory;
    }

    /**
     * Supplies the configured directory's paged enumeration capability.
     */
    public static function ldapUserEnumeration(bool $getShared = true): LDAPUserEnumerationInterface
    {
        if ($getShared) {
            return self::getSharedInstance('ldapUserEnumeration');
        }

        $directory = service('ldapDirectory');

        if (! $directory instanceof LDAPUserEnumerationInterface) {
            throw new LDAPException(LDAPReason::InvalidConfiguration);
        }

        return $directory;
    }

    /**
     * Supplies a resolver for sign-in. An explicit provider gets its own resolver.
     */
    public static function ldapUserResolver(?UserModel $provider = null, bool $getShared = true): LDAPUserResolver
    {
        if ($getShared && $provider === null) {
            return self::getSharedInstance('ldapUserResolver', null);
        }

        return new LDAPUserResolver($provider ?? auth()->getProvider());
    }

    /**
     * Supplies the operations for storing verified LDAP identity links.
     */
    public static function ldapLinkService(bool $getShared = true): LDAPLinkService
    {
        if ($getShared) {
            return self::getSharedInstance('ldapLinkService');
        }

        return new LDAPLinkService(auth()->getProvider());
    }

    /**
     * Supplies the planner and writer for LDAP profiles.
     */
    public static function ldapProfileSynchronizer(bool $getShared = true): LDAPProfileSynchronizer
    {
        if ($getShared) {
            return self::getSharedInstance('ldapProfileSynchronizer');
        }

        return new LDAPProfileSynchronizer(auth()->getProvider());
    }

    /**
     * Supplies the account linking workflow for the Spark command.
     */
    public static function ldapLinkWorkflow(bool $getShared = true): LDAPLinkWorkflow
    {
        if ($getShared) {
            return self::getSharedInstance('ldapLinkWorkflow');
        }

        return new LDAPLinkWorkflow(auth()->getProvider(), service('ldapLinkService'), service('ldapUserLookup'));
    }

    /**
     * Supplies the provisioning and profile synchronization workflow.
     */
    public static function ldapSyncWorkflow(bool $getShared = true): LDAPSyncWorkflow
    {
        if ($getShared) {
            return self::getSharedInstance('ldapSyncWorkflow');
        }

        return new LDAPSyncWorkflow(service('ldapUserEnumeration'), service('ldapProfileSynchronizer'));
    }
}
