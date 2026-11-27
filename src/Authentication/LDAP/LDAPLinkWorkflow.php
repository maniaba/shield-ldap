<?php

declare(strict_types=1);

/**
 * This file is part of Shield LDAP.
 *
 * (c) 2026 maniaba
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Maniaba\ShieldLDAP\Authentication\LDAP;

use Closure;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Models\UserModel;
use Generator;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Looks up directory accounts and applies explicitly authorized identity links.
 */
final readonly class LDAPLinkWorkflow
{
    /**
     * Uses the configured Shield user provider and directory lookup service.
     */
    public function __construct(
        private UserModel $users,
        private LDAPLinkService $links,
        private LDAPUserLookupInterface $directory,
    ) {
    }

    /**
     * Preview or apply links for the selected Shield account or full user list.
     *
     * @param array<int|string, int|string>                                           $localAccounts
     * @param Closure(int|string|null, ?string, LDAPReason|LinkStatus, ?string): void $writeResult
     * @param Closure(int, int, int): void                                            $writeSummary
     *
     * @return bool Whether the workflow completed without bulk conflicts.
     */
    public function run(
        LDAPConnection $connection,
        ?string $username,
        array $localAccounts,
        bool $apply,
        bool $all,
        ?string $replace,
        Closure $writeResult,
        Closure $writeSummary,
    ): bool {
        if (! $connection->verifyCertificate) {
            throw new LDAPException(LDAPReason::TlsVerificationRequired);
        }

        $usernameAttribute = $connection->profileAttributes['username'] ?? null;
        if ($usernameAttribute === null && count($connection->loginAttributes) === 1) {
            $usernameAttribute = $connection->loginAttributes[0];
        }

        if ($usernameAttribute === null) {
            throw new LDAPException(LDAPReason::InvalidConfiguration);
        }

        $lookup = fn (User $user): string => $this->lookupExternalId($user, $connection, $usernameAttribute, $localAccounts);

        if ($apply && $username === null) {
            if (! $all || $replace !== null) {
                throw new LDAPException(LDAPReason::InvalidConfiguration);
            }

            return $this->linkAll($connection->id, $lookup, $writeResult, $writeSummary);
        }

        $matches = $username === null ? $this->iterateLocalUsers() : [$this->findLocalUser($username)];

        foreach ($matches as $user) {
            $result = $this->inspectUser($user, $connection->id, $lookup);
            $status = $result['status'];

            if ($apply) {
                $status = $this->applyUser($user, $connection->id, $status, $result['externalId'], $replace);
            }

            $writeResult($user->id, $user->username, $status, $result['externalId']);
        }

        return true;
    }

    private function findLocalUser(string $username): User
    {
        $matches = $this->users->where('LOWER(username)', strtolower($username))->findAll(2);

        if (count($matches) !== 1) {
            throw new LDAPException($matches === [] ? LDAPReason::LocalUserNotFound : LDAPReason::AmbiguousLocalUser);
        }

        return $matches[0];
    }

    /**
     * @return Generator<int, User>
     */
    private function iterateLocalUsers(): Generator
    {
        $offset = 0;

        do {
            $batch = $this->users->orderBy('id', 'ASC')->findAll(100, $offset);

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
        string $usernameAttribute,
        array $localAccounts,
    ): string {
        $username = $user->username;
        $userId   = $user->id;

        if ($username === null || trim($username) === '' || preg_match('/^[^\\p{Cc}]+$/uD', $username) !== 1 || $userId === null) {
            throw new LDAPException(LDAPReason::InvalidProfile);
        }

        foreach ($localAccounts as $localUsername => $localId) {
            if ((string) $localId === (string) $userId || strcasecmp((string) $localUsername, $username) === 0) {
                throw new LDAPException(LDAPReason::ReservedLocalAccount);
            }
        }

        $entry = $this->directory->lookupUser(
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
     * @return array{status: LDAPReason|LinkStatus, externalId: ?string}
     */
    private function inspectUser(User $user, string $connectionId, Closure $lookup): array
    {
        $externalId = null;

        try {
            $externalId = $lookup($user);
            $status     = $this->links->inspectLink($user, $connectionId, $externalId);
        } catch (LDAPException $exception) {
            $status = $this->userFailure($exception);
        }

        return ['status' => $status, 'externalId' => $externalId];
    }

    private function applyUser(
        User $user,
        string $connectionId,
        LDAPReason|LinkStatus $status,
        ?string $externalId,
        ?string $replace,
    ): LinkStatus {
        if ($status instanceof LDAPReason) {
            throw new LDAPException($status);
        }

        $userId   = $user->id;
        $username = $user->username;

        if ($externalId === null || $userId === null || $username === null) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        if ($replace !== null) {
            if ($replace !== $externalId) {
                throw new LDAPException(LDAPReason::DirectoryIdentityChanged);
            }

            return $this->links->replaceLink($connectionId, $externalId, $userId, $username)
                ? LinkStatus::Replaced
                : LinkStatus::AlreadyLinked;
        }

        if ($status === LinkStatus::StaleLink) {
            throw new LDAPException(LDAPReason::IdentityConflict);
        }

        if ($status === LinkStatus::AlreadyLinked) {
            return $status;
        }

        $this->links->link($connectionId, $externalId, $userId, $username);

        return LinkStatus::Linked;
    }

    /**
     * @param Closure(User): string                                                   $lookup
     * @param Closure(int|string|null, ?string, LDAPReason|LinkStatus, ?string): void $writeResult
     * @param Closure(int, int, int): void                                            $writeSummary
     */
    private function linkAll(string $connectionId, Closure $lookup, Closure $writeResult, Closure $writeSummary): bool
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
            foreach ($this->iterateLocalUsers() as $user) {
                $result = $this->inspectUser($user, $connectionId, $lookup);
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
                    $status = LDAPReason::AmbiguousLocalUser;
                } elseif ($externalId !== null && $ids[$externalId] > 1) {
                    $status = LDAPReason::DuplicateDirectoryIdentity;
                } elseif ($status === LinkStatus::Candidate && $row['username'] !== null && $externalId !== null) {
                    try {
                        $user = $this->findLocalUser($row['username']);

                        // Recheck the directory match after preflight, before writing.
                        if ($user->id !== $row['userId'] || strcasecmp($user->username ?? '', $row['username']) !== 0 || $lookup($user) !== $externalId) {
                            throw new LDAPException(LDAPReason::DirectoryIdentityChanged);
                        }

                        $status = $this->links->inspectLink($user, $connectionId, $externalId);
                        if ($status === LinkStatus::Candidate) {
                            $status = $this->applyUser($user, $connectionId, $status, $externalId, null);
                        }
                    } catch (LDAPException $exception) {
                        $status = $this->userFailure($exception);
                    }
                }

                $writeResult($row['userId'], $row['username'], $status, $externalId);

                if ($status === LinkStatus::Linked) {
                    $linked++;
                } elseif ($status === LinkStatus::AlreadyLinked || ($status instanceof LDAPReason && $status->isLinkSkip())) {
                    $skipped++;
                } else {
                    $conflicts++;
                }
            }
        } finally {
            $writeSummary($linked, $skipped, $conflicts);
        }

        return $conflicts === 0;
    }

    private function userFailure(LDAPException $exception): LDAPReason
    {
        $reason = $exception->kind;

        if ($reason === null || (! $reason->isLinkSkip() && ! $reason->isLinkConflict())) {
            throw $exception;
        }

        return $reason;
    }
}
