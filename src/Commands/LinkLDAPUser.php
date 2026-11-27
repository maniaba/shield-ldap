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

use Closure;
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
 * Previews, creates, and repairs LDAP links for existing Shield users.
 */
final class LinkLDAPUser extends BaseCommand
{
    private const SKIPPED = [
        'already_linked', 'ineligible_user', 'invalid_profile', 'reserved_local_account', 'user_not_found',
    ];
    private const CONFLICTS = [
        'ambiguous_local_user', 'ambiguous_user', 'directory_identity_changed', 'duplicate_directory_identity',
        'identity_conflict', 'invalid_external_identity', 'invalid_identity', 'local_user_not_found', 'stale_link',
    ];

    protected $name        = 'shield:ldap-link';
    protected $description = 'Preview, create, or repair links between existing Shield accounts and LDAP.';
    protected $usage       = 'shield:ldap-link <connection> [<username>] [--all] [--apply] [--replace <new-ldap-id>]';
    protected $arguments   = [
        'connection' => 'LDAP connection ID from AuthLDAP.',
        'username'   => 'Existing Shield username to look up in the directory.',
    ];
    protected $options = [
        '--all'     => 'With --apply, add missing links for all users.',
        '--apply'   => 'Write links for the selected username or for --all.',
        '--replace' => 'Repair the selected username’s existing link using the specified new LDAP ID.',
    ];

    /**
     * Preview candidate identities or write the requested links.
     *
     * @param array<array-key, mixed> $params
     */
    public function run(array $params): int
    {
        $connectionId = $params[0] ?? null;
        $username     = $params[1] ?? null;
        $replace      = $params['replace'] ?? null;
        $apply        = array_key_exists('apply', $params);
        $all          = array_key_exists('all', $params);

        if (! is_string($connectionId) || $connectionId === ''
                                       || ($username !== null && (! is_string($username) || trim($username) === ''))
                                       || ($apply && ($params['apply'] !== null || (! $all && $username === null)))
                                       || ($all && ($params['all'] !== null || ! $apply || $username !== null))
                                       || (array_key_exists('replace', $params) && (! $apply || $all || ! is_string($replace) || $replace === ''))
                                       || array_diff_key($params, [0 => true, 1 => true, 'apply' => true, 'all' => true, 'replace' => true]) !== []
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
            $lookup   = fn (User $user): string => $this->lookupExternalId(
                $user,
                $connection,
                $directory,
                $usernameAttribute,
                $config->localAccounts,
            );

            if ($all) {
                return $this->linkAll($users, $resolver, $connectionId, $lookup);
            }

            $matches = $username === null ? $this->scanUsers($users) : [$this->findLocalUser($users, $username)];

            foreach ($matches as $user) {
                $result = $this->inspectUser($user, $resolver, $connectionId, $lookup);
                $status = $result['status'];

                if ($apply) {
                    $status = $this->applyUser($user, $resolver, $connectionId, $status, $result['externalId'], $replace);
                }

                $this->writeResult($user->id, $user->username, $status, $result['externalId']);
            }
        } catch (LDAPException $exception) {
            $this->error($exception->getMessage());

            return EXIT_ERROR;
        }

        return EXIT_SUCCESS;
    }

    private function findLocalUser(UserModel $users, string $username): User
    {
        $matches = $users->where('LOWER(username)', strtolower($username))->findAll(2);

        if (count($matches) !== 1) {
            throw new LDAPException($matches === [] ? 'local_user_not_found' : 'ambiguous_local_user');
        }

        return $matches[0];
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
    private function lookupExternalId(
        User $user,
        LDAPConnection $connection,
        LDAPUserLookupInterface $directory,
        string $usernameAttribute,
        array $localAccounts,
    ): string {
        $username = $user->username;
        $userId   = $user->id;

        if ($username === null || trim($username) === '' || preg_match('/^[^\\p{Cc}]+$/uD', $username) !== 1 || $userId === null) {
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

        return LDAPUserResolver::externalId($connection, $entry['attributes']);
    }

    /**
     * @param Closure(User): string $lookup
     *
     * @return array{status: string, externalId: ?string}
     */
    private function inspectUser(User $user, LDAPUserResolver $resolver, string $connectionId, Closure $lookup): array
    {
        $externalId = null;

        try {
            $externalId = $lookup($user);
            $status     = $resolver->inspectLink($user, $connectionId, $externalId);
        } catch (LDAPException $exception) {
            $status = $this->userFailure($exception);
        }

        return ['status' => $status, 'externalId' => $externalId];
    }

    private function applyUser(
        User $user,
        LDAPUserResolver $resolver,
        string $connectionId,
        string $status,
        ?string $externalId,
        ?string $replace,
    ): string {
        $userId   = $user->id;
        $username = $user->username;

        if ($externalId === null || $userId === null || $username === null || ! in_array($status, ['candidate', 'already_linked', 'stale_link'], true)) {
            throw new LDAPException($status);
        }

        if ($replace !== null) {
            if ($replace !== $externalId) {
                throw new LDAPException('directory_identity_changed');
            }

            return $resolver->replaceLink($connectionId, $externalId, $userId, $username) ? 'replaced' : 'already_linked';
        }

        if ($status === 'stale_link') {
            throw new LDAPException('identity_conflict');
        }

        if ($status === 'already_linked') {
            return $status;
        }

        $resolver->link($connectionId, $externalId, $userId, $username);

        return 'linked';
    }

    /**
     * @param Closure(User): string $lookup
     */
    private function linkAll(UserModel $users, LDAPUserResolver $resolver, string $connectionId, Closure $lookup): int
    {
        $rows      = [];
        $names     = [];
        $ids       = [];
        $linked    = 0;
        $skipped   = 0;
        $conflicts = 0;

        try {
            // Inspect the whole selection before writing, so two matches for
            // the same identity are rejected even when neither is linked yet.
            foreach ($this->scanUsers($users) as $user) {
                $result = $this->inspectUser($user, $resolver, $connectionId, $lookup);
                $name   = strtolower($user->username ?? '');
                $id     = $result['externalId'];

                if ($name !== '') {
                    $names[$name] = ($names[$name] ?? 0) + 1;
                }

                if ($id !== null) {
                    $ids[$id] = ($ids[$id] ?? 0) + 1;
                }

                $rows[] = $result + ['userId' => $user->id, 'username' => $user->username];
            }

            foreach ($rows as $row) {
                $name       = strtolower($row['username'] ?? '');
                $externalId = $row['externalId'];
                $status     = $row['status'];

                if (($names[$name] ?? 0) > 1) {
                    $status = 'ambiguous_local_user';
                } elseif ($externalId !== null && $ids[$externalId] > 1) {
                    $status = 'duplicate_directory_identity';
                } elseif ($status === 'candidate' && $row['username'] !== null && $externalId !== null) {
                    try {
                        $user = $this->findLocalUser($users, $row['username']);
                        if ($user->id !== $row['userId'] || $user->username !== $row['username'] || $lookup($user) !== $externalId) {
                            throw new LDAPException('directory_identity_changed');
                        }

                        $status = $resolver->inspectLink($user, $connectionId, $externalId);
                        if ($status === 'candidate') {
                            $status = $this->applyUser($user, $resolver, $connectionId, $status, $externalId, null);
                        }
                    } catch (LDAPException $exception) {
                        $status = $this->userFailure($exception);
                    }
                }

                $this->writeResult($row['userId'], $row['username'], $status, $externalId);

                if ($status === 'linked') {
                    $linked++;
                } elseif (in_array($status, self::SKIPPED, true)) {
                    $skipped++;
                } else {
                    $conflicts++;
                }
            }
        } finally {
            $this->write(sprintf('Summary: linked=%d skipped=%d conflicts=%d', $linked, $skipped, $conflicts));
        }

        return $conflicts === 0 ? EXIT_SUCCESS : EXIT_ERROR;
    }

    private function userFailure(LDAPException $exception): string
    {
        if (! in_array($exception->reason, self::SKIPPED, true) && ! in_array($exception->reason, self::CONFLICTS, true)) {
            throw $exception;
        }

        return $exception->reason;
    }

    private function writeResult(int|string|null $userId, ?string $username, string $status, ?string $externalId): void
    {
        if ($externalId !== null) {
            $status .= ' LDAP ID ' . json_encode($externalId, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
        }

        $this->write(sprintf(
            'Shield user %s %s %s',
            json_encode($userId, JSON_THROW_ON_ERROR),
            json_encode($username, JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR),
            $status,
        ));
    }
}
