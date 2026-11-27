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

namespace Maniaba\ShieldLDAP\Database\Migrations;

use CodeIgniter\Database\Forge;
use CodeIgniter\Database\Migration;

final class AddLdapGroupGrants extends Migration
{
    private readonly string $groupTable;
    private readonly string $grantTable;

    public function __construct(?Forge $forge = null)
    {
        $authConfig       = config('Auth');
        $this->DBGroup    = $authConfig->DBGroup ?? $this->DBGroup;
        $this->groupTable = $authConfig->tables['groups_users'];
        $this->grantTable = config('AuthLDAP')->tables['group_grants'];

        parent::__construct($forge);
    }

    public function up(): void
    {
        $this->forge->addField([
            'shield_group_id' => ['type' => 'int', 'constraint' => 11, 'unsigned' => true],
            'user_id'         => ['type' => 'int', 'constraint' => 11, 'unsigned' => true],
            'grant_key'       => ['type' => 'char', 'constraint' => 64],
            'sources'         => ['type' => 'text'],
            'revision'        => ['type' => 'int', 'unsigned' => true, 'default' => 0],
        ]);
        $this->forge->addPrimaryKey('shield_group_id');
        $this->forge->addUniqueKey('grant_key');
        $this->forge->addForeignKey('shield_group_id', $this->groupTable, 'id', '', 'CASCADE');
        $attributes = $this->db->getPlatform() === 'MySQLi' ? ['ENGINE' => 'InnoDB'] : [];
        $this->forge->createTable($this->grantTable, false, $attributes);
    }

    public function down(): void
    {
        $this->forge->dropTable($this->grantTable, true);
    }
}
