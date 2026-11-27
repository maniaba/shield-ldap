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

namespace Maniaba\ShieldLDAP\Commands;

use CodeIgniter\Shield\Commands\BaseCommand;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use Generator;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPConnection;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPFilter;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserLookupInterface;
use Maniaba\ShieldLDAP\Authentication\LDAP\LDAPUserResolver;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;

/**
 * Scans LDAP matches for existing Shield users and applies operator-selected links.
 */
final class LinkLDAPUser extends BaseCommand
{
    protected $name        = 'shield:ldap-link';
    protected $description = 'Preview LDAP links for existing Shield users or apply a link for a selected username.';
    protected $usage       = 'shield:ldap-link <connection> [<username>] [--apply]';
    protected $arguments   = [
        'connection' => 'LDAP connection ID from AuthLDAP.',
        'username'   => 'Existing Shield username to look up in the directory.',
    ];
    protected $options = [
        '--apply' => 'Write the link for the specified user.',
    ];

    /**
     * Preview candidate identities or write one explicitly selected link.
     *
     * @param array<array-key, mixed> $params
     */
    public function run(array $params): int
    {
        $connectionId = $params[0] ?? null;
        $username     = $params[1] ?? null;
        $apply        = array_key_exists('apply', $params);

        if (! is_string($connectionId) || $connectionId === ''
                                       || ($username !== null && (! is_string($username) || trim($username) === ''))
                                       || ($apply && ($username === null || $params['apply'] !== null))
                                       || array_diff_key($params, [0 => true, 1 => true, 'apply' => true]) !== []
        ) {
            $this->error($this->usage);

            return EXIT_ERROR;
        }

        try {
            $config     = config('AuthLDAP');
            $connection = $config->getConnection($connectionId);
            $directory  = service('ldapDirectory');

            if ($connection->id !== $connectionId || ! $directory instanceof LDAPUserLookupInterface) {
                throw new LDAPException('invalid_configuration');
            }

            if (! $connection->verifyCertificate) {
                throw new LDAPException('tls_verification_required');
            }

            $usernameAttribute = $connection->profileAttributes['username'] ?? null;
            if ($usernameAttribute === null && count($connection->loginAttributes) === 1) {
                $usernameAttribute = $connection->loginAttributes[0] ?? null;
            }

            if (! is_string($usernameAttribute)) {
                throw new LDAPException('invalid_configuration');
            }

            $users    = auth()->getProvider();
            $resolver = new LDAPUserResolver($users);

            if ($username !== null) {
                $matches = $users->where('LOWER(username)', strtolower($username))->findAll(2);
                if (count($matches) !== 1) {
                    throw new LDAPException($matches === [] ? 'local_user_not_found' : 'ambiguous_local_user');
                }
            } else {
                $matches = $this->scanUsers($users);
            }

            foreach ($matches as $user) {
                $status = $this->linkUser($user, $connection, $directory, $resolver, $usernameAttribute, $config->localAccounts, $apply);
                $this->write(sprintf(
                    'Shield user %s %s %s',
                    json_encode($user->id, JSON_THROW_ON_ERROR),
                    json_encode($user->username, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
                    $status,
                ));
            }
        } catch (LDAPException $exception) {
            $this->error($exception->getMessage());

            return EXIT_ERROR;
        }

        return EXIT_SUCCESS;
    }

    /**
     * @return Generator<int, User>
     */
    private function scanUsers(UserModel $users): Generator
    {
        $offset = 0;

        do {
            $batch = $users->orderBy('id', 'ASC')->findAll(100, $offset);

            foreach ($batch as $user) {
                yield $user;
            }
            $offset += count($batch);
        } while (count($batch) === 100);
    }

    /**
     * @param array<int|string, int|string> $localAccounts
     */
    private function linkUser(
        User $user,
        LDAPConnection $connection,
        LDAPUserLookupInterface $directory,
        LDAPUserResolver $resolver,
        string $usernameAttribute,
        array $localAccounts,
        bool $apply,
    ): string {
        $username = $user->username;
        $userId   = $user->id;

        try {
            if ($username === null || trim($username) === '' || preg_match('/^[^\p{Cc}]+$/uD', $username) !== 1 || $userId === null) {
                throw new LDAPException('invalid_profile');
            }

            foreach ($localAccounts as $localUsername => $localId) {
                if ((string) $localId === (string) $userId || strcasecmp((string) $localUsername, $username) === 0) {
                    throw new LDAPException('reserved_local_account');
                }
            }

            $entry = $directory->lookupUser(
                $connection,
                $connection->userBaseDn ?? $connection->baseDn,
                LDAPFilter::all($connection->loginFilter, LDAPFilter::equal($usernameAttribute, $username)),
                $connection->eligibilityFilter,
            );
            $externalId = LDAPUserResolver::externalId($connection, $entry['attributes']);
            $linked     = $resolver->isLinked($user, $connection->id, $externalId);

            if ($apply && ! $linked) {
                $resolver->link($connection->id, $externalId, $userId, $username);
            }

            $status = $linked ? 'already_linked' : ($apply ? 'linked' : 'candidate');

            return $status . ' LDAP ID ' . json_encode($externalId, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        } catch (LDAPException $exception) {
            if ($apply || ! in_array($exception->reason, [
                'ambiguous_user', 'identity_conflict', 'ineligible_user', 'invalid_external_identity',
                'invalid_identity', 'invalid_profile', 'reserved_local_account', 'user_not_found',
            ], true)) {
                throw $exception;
            }

            return $exception->reason;
        }
    }
}
