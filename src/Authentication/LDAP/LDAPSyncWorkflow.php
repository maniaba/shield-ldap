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
use JsonException;
use Maniaba\ShieldLDAP\Exceptions\LDAPException;
use Maniaba\ShieldLDAP\Exceptions\LDAPReason;

/**
 * Stages an eligible directory scan and coordinates per-user synchronization.
 */
final readonly class LDAPSyncWorkflow
{
    /**
     * Uses the supplied directory reader and profile synchronizer.
     */
    public function __construct(private LDAPUserEnumerationInterface $directory, private LDAPProfileSynchronizer $profiles)
    {
    }

    /**
     * Complete the scan before planning or applying local account changes.
     *
     * @param array<array-key, int|string>                                                                 $localAccounts
     * @param Closure(SyncStatus, string): void                                                            $reportResult
     * @param Closure(LDAPException): void                                                                 $reportConflict
     * @param Closure(array{create: int, update: int, unchanged: int, skipped: int, conflicts: int}): void $reportSummary
     */
    public function run(
        LDAPConnection $connection,
        array $localAccounts,
        bool $apply,
        Closure $reportResult,
        Closure $reportConflict,
        Closure $reportSummary,
    ): bool {
        if (! $connection->verifyCertificate) {
            throw new LDAPException(LDAPReason::TlsVerificationRequired);
        }

        $stage = @fopen('php://temp', 'w+b');
        if ($stage === false) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }

        $totals = ['create' => 0, 'update' => 0, 'unchanged' => 0, 'skipped' => 0, 'conflicts' => 0];

        try {
            [$names, $totals['conflicts']] = $this->stageUsers($stage, $connection, $reportConflict);
            if (! rewind($stage)) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }

            while (($line = fgets($stage)) !== false) {
                [$externalId, $profile] = $this->decodeUser($line);
                $username               = $profile['username'] ?? null;

                try {
                    if ($username !== null && ($names[strtolower($username)] ?? 0) > 1) {
                        throw new LDAPException(LDAPReason::IdentityConflict);
                    }

                    $plan   = $this->profiles->plan($connection, $externalId, $profile, $localAccounts);
                    $status = $apply ? $this->profiles->apply($plan) : $plan->status;
                } catch (LDAPException $exception) {
                    $this->reportUserConflict($exception, $reportConflict);
                    $totals['conflicts']++;

                    continue;
                }

                $totals[$status->value]++;
                $reportResult($status, $username ?? $externalId);
            }

            if (! feof($stage)) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }
        } finally {
            fclose($stage);
            $reportSummary($totals);
        }

        return $totals['conflicts'] === 0;
    }

    /**
     * Collect and validate the directory results before making local changes.
     *
     * @param resource                     $stage
     * @param Closure(LDAPException): void $reportConflict
     *
     * @return array{array<array-key, int>, int} Username counts and entry conflicts.
     */
    private function stageUsers($stage, LDAPConnection $connection, Closure $reportConflict): array
    {
        $seen      = [];
        $names     = [];
        $conflicts = 0;

        $scan = $this->directory->scanUsers($connection);

        try {
            foreach ($scan as $entry) {
                try {
                    $externalId = LDAPUserResolver::externalId($connection, $entry['attributes']);
                    $key        = hash('sha256', $externalId);
                    $dn         = hash('sha256', $entry['dn']);

                    if (isset($seen[$key])) {
                        if ($seen[$key] !== $dn) {
                            throw new LDAPException(LDAPReason::AmbiguousUser);
                        }

                        continue;
                    }

                    $seen[$key] = $dn;
                    $profile    = LDAPUserResolver::profile($connection, $entry['attributes']);
                } catch (LDAPException $exception) {
                    $this->reportUserConflict($exception, $reportConflict);
                    $conflicts++;

                    continue;
                }

                if (isset($profile['username'])) {
                    $name         = strtolower($profile['username']);
                    $names[$name] = ($names[$name] ?? 0) + 1;
                }

                // Use a stream so large scans can spill into temporary storage.
                $line = json_encode([base64_encode($externalId), array_map(base64_encode(...), $profile)], JSON_THROW_ON_ERROR) . "\n";
                if (fwrite($stage, $line) !== strlen($line)) {
                    throw new LDAPException(LDAPReason::SynchronizationConflict);
                }
            }
        } finally {
            if ($scan instanceof LDAPUserScan) {
                $scan->close();
            }
        }

        return [$names, $conflicts];
    }

    /**
     * @return array{string, array<string, string>}
     */
    private function decodeUser(string $line): array
    {
        try {
            $row = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new LDAPException(LDAPReason::SynchronizationConflict, $exception);
        }

        if (! is_array($row) || ! is_string($row[0] ?? null) || ! is_array($row[1] ?? null)) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }

        $externalId = base64_decode($row[0], true);
        if ($externalId === false) {
            throw new LDAPException(LDAPReason::SynchronizationConflict);
        }

        $profile = [];

        foreach ($row[1] as $field => $encoded) {
            if (! is_string($field) || ! is_string($encoded)) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }

            $value = base64_decode($encoded, true);
            if ($value === false) {
                throw new LDAPException(LDAPReason::SynchronizationConflict);
            }

            $profile[$field] = $value;
        }

        return [$externalId, $profile];
    }

    /**
     * @param Closure(LDAPException): void $reportConflict
     */
    private function reportUserConflict(LDAPException $exception, Closure $reportConflict): void
    {
        if ($exception->kind?->isSyncConflict() !== true) {
            throw $exception;
        }

        $reportConflict($exception);
    }
}
