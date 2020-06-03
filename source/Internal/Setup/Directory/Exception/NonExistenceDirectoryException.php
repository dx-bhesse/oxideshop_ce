<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\EshopCommunity\Internal\Setup\Directory\Exception;

use Exception;
use Throwable;

/**
 * Class NonExistenceDirectoryException
 *
 * @package OxidEsales\EshopCommunity\Internal\Setup\Directory
 */
class NonExistenceDirectoryException extends Exception
{
    public const NON_EXISTENCE_DIRECTORY = 'Following folder is not exist';
}
