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
 * Class NotAbsolutePathException
 *
 * @package OxidEsales\EshopCommunity\Internal\Setup\Directory
 */
class NotAbsolutePathException extends Exception
{
    public const NOT_ABSOLUTE_PATHS = 'shop-directory and compile-directory must be absolute paths';
}
