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

namespace Maniaba\ShieldLDAP\Config;

use CodeIgniter\Events\Events;
use Maniaba\ShieldLDAP\Authentication\Authenticators\LDAP;

Events::on('login', LDAP::rememberAfterAction(...), Events::PRIORITY_HIGH);
