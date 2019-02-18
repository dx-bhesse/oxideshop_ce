<?php
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Tests\Unit\Core;

use OxidEsales\Eshop\Core\Exception\StandardException;
use OxidEsales\Eshop\Core\PasswordSaltGenerator;
use OxidEsales\TestingLibrary\UnitTestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Class PasswordSaltGeneratorTest
 */
class PasswordSaltGeneratorTest extends UnitTestCase
{
    /**
     */
    public function testSaltLength()
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);
        $this->assertSame(32, strlen($generator->generate()));
    }

    /**
     */
    public function testGeneratedSaltShouldBeUnique()
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);
        $salts = array();

        for ($i = 1; $i <= 100; $i++) {
            $salts[] = $generator->generate();
        }

        $this->assertCount(100, array_unique($salts));
    }

    /**
     */
    public function testGeneratePseudoRandomBytesReturnsEmptyStringIfNoRandomBytesGeneratorIsAvailable()
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $openSSLFunctionalityChecker->method('isOpenSslRandomBytesGeneratorAvailable')->willReturn(false);
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);

        $randomBytes = $generator->generatePseudoRandomBytes();

        $this->assertSame('', $randomBytes);
    }

    /**
     */
    public function testGenerateFallsBackToCustomSaltGeneratorIfGeneratePseudoRandomBytesFails()
    {
        $generatorMock = $this->getMockBuilder(PasswordSaltGenerator::class)
            ->setMethods(['generatePseudoRandomBytes', '_customSaltGenerator'])
            ->disableOriginalConstructor()
            ->getMock();
        $generatorMock->method('generatePseudoRandomBytes')->willReturn('');

        $generatorMock
            ->expects($this->once())
            ->method('_customSaltGenerator')
            ->willReturn('salt');

        $generatorMock->generate();
    }

    /**
     */
    public function testGenerateStrongSaltProduces32CharsLongStringByDefault()
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);

        $strongSalt = $generator->generateStrongSalt();

        $this->assertSame(
            32,
            strlen($strongSalt)
        );
    }

    /**
     */
    public function testGenerateStrongSaltProducesUniqueSalts()
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);

        $salt_1 = $generator->generateStrongSalt();
        $salt_2 = $generator->generateStrongSalt();

        $this->assertNotSame($salt_1, $salt_2);
    }

    /**
     */
    public function testGenerateStrongSaltStringLengthIsCompatibleWithGenerate()
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);

        $strongSalt = $generator->generateStrongSalt();
        $salt = $generator->generate();

        $this->assertSame(
            strlen($strongSalt),
            strlen($salt)
        );
    }

    /**
     * @dataProvider validSaltLengthDataProvider
     *
     * @param int $validSaltLength
     */
    public function testGenerateStrongSaltReturnsStringOfRequestedLength(int $validSaltLength)
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);

        $salt = $generator->generateStrongSalt($validSaltLength);

        $this->assertSame($validSaltLength, strlen($salt));
    }

    /**
     * @return array
     */
    public function validSaltLengthDataProvider(): array
    {
        return [
            ['saltLength' => 32],
            ['saltLength' => 64],
            ['saltLength' => 128],
        ];
    }

    /**
     * @dataProvider invalidSaltLengthDataProvider
     *
     * @param int $invalidSaltLength
     */
    public function testGenerateStrongSaltThrowsExceptionForInvalidSaltLength(int $invalidSaltLength)
    {
        $openSSLFunctionalityChecker = $this->getOpenSSLFunctionalityChecker();
        $generator = new PasswordSaltGenerator($openSSLFunctionalityChecker);

        $this->expectException(StandardException::class);

        $generator->generateStrongSalt($invalidSaltLength);
    }

    /**
     * @return array
     */
    public function invalidSaltLengthDataProvider(): array
    {
        return [
            ['saltLength' => -1],
            ['saltLength' => 0],
            ['saltLength' => 31],
            ['saltLength' => 129],
        ];
    }


    /**
     * @return \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker|MockObject
     */
    private function getOpenSSLFunctionalityChecker(): \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
    {
        $openSSLFunctionalityChecker = $this->getMockBuilder(\OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker::class)->getMock();

        return $openSSLFunctionalityChecker;
    }
}
