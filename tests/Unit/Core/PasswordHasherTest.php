<?php
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Tests\Unit\Core;

use OxidEsales\Eshop\Core\Hasher;
use OxidEsales\Eshop\Core\PasswordHasher;
use OxidEsales\EshopCommunity\Internal\Password\Exception\PasswordHashException;
use OxidEsales\EshopCommunity\Internal\Password\Service\PasswordHashBcryptService;

class PasswordHasherTest extends \OxidTestCase
{
    public function testHashWithHasherImplementation()
    {
        $password = 'password';
        $salt = 'salt';

        $passwordHashService = $this->getMock(Hasher::class);
        $passwordHashService->expects($this->once())->method('hash')->with()->willReturn('somePasswordHash');

        $passwordHasher = new PasswordHasher($passwordHashService);

        $passwordHasher->hash($password, $salt);
    }

    public function testHashWithPasswordHashServiceInterfaceImplementation()
    {
        $password = 'password';
        $salt = 'salt';

        $passwordHashService = $this->getMock(PasswordHashBcryptService::class);
        $passwordHashService->expects($this->once())->method('hash')->with()->willReturn('somePasswordHash');

        $passwordHasher = new PasswordHasher($passwordHashService);

        $passwordHasher->hash($password, $salt);
    }

    public function testConstructorThrowsExceptionOnUnsupportedPasswordHashService()
    {
        $this->expectException(PasswordHashException::class);

        $passwordHashService = $this->getMock(\stdClass::class);

        new PasswordHasher($passwordHashService);
    }
}
