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

namespace Maniaba\ShieldLDAP\Authentication\LDAP;

use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Models\UserIdentityModel;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Synchronizes a directory-owned address for Shield's email actions.
 *
 * @internal
 */
final readonly class LDAPEmailSynchronizer
{
    private const OWNER_TYPE = 'ldap_email';

    // Shield expects a string for password verification. This value is not a valid password hash.
    private const PASSWORD_DISABLED = 'ldap:password-disabled';

    public function __construct(private UserIdentityModel $identities)
    {
    }

    /**
     * Store or update the address within the resolver's transaction.
     *
     * @return bool Whether the user's email identity changed.
     */
    public function synchronize(User $user, string $key, string $email): bool
    {
        if (setting('Auth.allowMagicLinkLogins') !== false) {
            throw new LDAPException('invalid_configuration');
        }

        if (strlen($email) > 254 || preg_match('/[\x00-\x1F\x7F,]/', $email) === 1
                                 || filter_var($email, FILTER_VALIDATE_EMAIL) === false
        ) {
            throw new LDAPException('invalid_profile');
        }

        $email    = strtolower($email);
        $userId   = $user->id ?? throw new LDAPException('identity_conflict');
        $identity = $this->identities->getIdentityByType($user, Session::ID_TYPE_EMAIL_PASSWORD);
        $owner    = $this->identities->getIdentityBySecret(self::OWNER_TYPE, (string) $userId);

        if ($identity === null) {
            // A retained ownership record also protects an address removed by the application.
            if ($owner !== null) {
                return false;
            }

            $this->checkAddress($email, $userId);
            $this->createEmail($user, $userId, $key, $email);

            return true;
        }

        $address = $identity->secret;
        if ($address === null || $address === $email || $identity->secret2 !== self::PASSWORD_DISABLED
                              || $owner === null || $owner->name !== $key || $owner->extra !== hash('sha256', $address)
        ) {
            return false;
        }

        $this->checkAddress($email, $userId);
        $this->updateEmail($identity, $owner, $address, $email);

        return true;
    }

    private function checkAddress(string $email, int|string $userId): void
    {
        $secret = $this->identities->builder()->db()->protectIdentifiers('secret');
        $owner  = $this->identities->where('type', Session::ID_TYPE_EMAIL_PASSWORD)
            ->where('LOWER(' . $secret . ')', $email)
            ->where('user_id !=', $userId)
            ->first();

        if ($owner !== null) {
            throw new LDAPException('identity_conflict');
        }
    }

    private function createEmail(User $user, int|string $userId, string $key, string $email): void
    {
        // The existing unique (type, secret) key allows one LDAP address owner per user.
        $this->identities->create(new UserIdentity([
            'user_id' => $userId,
            'type'    => self::OWNER_TYPE,
            'name'    => $key,
            'secret'  => (string) $userId,
            'extra'   => hash('sha256', $email),
        ]));
        $this->identities->create(new UserIdentity([
            'user_id' => $userId,
            'type'    => Session::ID_TYPE_EMAIL_PASSWORD,
            'secret'  => $email,
            'secret2' => self::PASSWORD_DISABLED,
        ]));

        $created = $this->identities->getIdentityByType($user, Session::ID_TYPE_EMAIL_PASSWORD);
        if ($created?->secret !== $email || $created->secret2 !== self::PASSWORD_DISABLED) {
            throw new LDAPException('synchronization_conflict');
        }
    }

    private function updateEmail(UserIdentity $identity, UserIdentity $owner, string $address, string $email): void
    {
        // A local address or password change between the read and write supersedes LDAP ownership.
        $identity->secret = $email;
        $updated          = $this->identities->where('secret', $address)
            ->where('secret2', self::PASSWORD_DISABLED)
            ->save($identity);

        if (! $updated || $this->identities->builder()->db()->affectedRows() !== 1) {
            throw new LDAPException('synchronization_conflict');
        }

        $owner->extra = hash('sha256', $email);
        if (! $this->identities->save($owner)) {
            throw new LDAPException('synchronization_conflict');
        }
    }
}
