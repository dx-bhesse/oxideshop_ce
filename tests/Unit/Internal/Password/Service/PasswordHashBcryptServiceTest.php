<?php declare(strict_types=1);
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Tests\Unit\Internal\Password;

use OxidEsales\EshopCommunity\Internal\Password\Exception\PasswordHashException;
use OxidEsales\EshopCommunity\Internal\Password\Service\PasswordHashBcryptService;
use PHPUnit\Framework\TestCase;

/**
 *
 */
class PasswordHashBcryptServiceTest extends TestCase
{
    /**
     *
     */
    public function testHashForGivenPasswordIsEncryptedWithBcrypt()
    {
        $password = 'secret';

        $passwordHashService = new PasswordHashBcryptService();
        $hash = $passwordHashService->hash($password);
        $info = password_get_info($hash);

        $this->assertSame(PASSWORD_BCRYPT, $info['algo']);
    }

    /**
     *
     */
    public function testHashWithOptions()
    {
        $password = 'secret';

        $passwordHashService = new PasswordHashBcryptService();
        $hash = $passwordHashService->hash($password, ['cost' => 4]);
        $info = password_get_info($hash);

        $this->assertSame(4, $info['options']['cost']);
    }

    /**
     * @dataProvider invalidCostOptionValueDataProvider
     *
     * @param mixed $invalidCostOption
     */
    public function testHashWithInvalidCostOptionValueTriggersWarning($invalidCostOption)
    {
        $this->expectException(\OxidEsales\EshopCommunity\Internal\Password\Exception\PasswordHashException::class);

        $password = 'secret';

        $passwordHashService = new PasswordHashBcryptService();
        $passwordHashService->hash($password, ['cost' => $invalidCostOption]);
    }


    /**
     * @return array
     */
    public function invalidCostOptionValueDataProvider(): array
    {
        return [
            [-5],
            [0],
            [3], // Cost must be at least 4
            [[10]],
            ['string'],
        ];
    }

    /**
     * @dataProvider notRecommendedSaltOptionValueDataProvider
     *
     * @param mixed $notRecommendedSaltOption
     */
    public function testHashWithNotRecommendedSaltOptionValueTriggersWarning($notRecommendedSaltOption)
    {
        $this->expectException(\PHPUnit\Framework\Error\Warning::class);

        $password = 'secret';

        $passwordHashService = new PasswordHashBcryptService();
        $passwordHashService->hash($password, ['salt' => $notRecommendedSaltOption]);
    }

    /**
     * @return array
     */
    public function notRecommendedSaltOptionValueDataProvider(): array
    {
        return [
            ['salt must be at least 22 chars long scalar' => PHP_INT_MAX],
            ['salt must be at least 22 chars long scalar' => ''],
            ['salt must be at least 22 chars long scalar' => 1],
            ['salt must be at least 22 chars long scalar' => false],
            ['salt must be at least 22 chars long scalar' => substr(md5('salt'), 0, 21)],

        ];
    }

    /**
     * @dataProvider invalidSaltOptionValueDataProvider
     *
     * @param mixed $invalidSaltOption
     */
    public function testHashWithInvalidSaltOptionValueTriggersException($invalidSaltOption)
    {
        $this->expectException(PasswordHashException::class);

        $password = 'secret';

        $passwordHashService = new PasswordHashBcryptService();
        $passwordHashService->hash($password, ['salt' => $invalidSaltOption]);
    }

    /**
     * @return array
     */
    public function invalidSaltOptionValueDataProvider(): array
    {
        return [
            ['salt must be at least 22 chars long string' => []],
            ['salt must be at least 22 chars long string' => null],
            ['salt must be at least 22 chars long string' => new \stdClass()],
        ];
    }

    /**
     *
     */
    public function testHashForEmptyPasswordIsEncryptedWithBcrypt()
    {
        $password = '';

        $passwordHashService = new PasswordHashBcryptService();
        $hash = $passwordHashService->hash($password);
        $info = password_get_info($hash);

        $this->assertSame(PASSWORD_BCRYPT, $info['algo']);
    }

    /**
     *
     */
    public function testConsecutiveHashingTheSamePasswordProducesDifferentHashes()
    {
        $password = 'secret';

        $passwordHashService = new PasswordHashBcryptService();
        $hash_1 = $passwordHashService->hash($password);
        $hash_2 = $passwordHashService->hash($password);

        $this->assertNotSame($hash_1, $hash_2);
    }

    /**
     * @param int $multiplier
     *
     * @dataProvider stringMultiplierDataProvider
     */
    public function testHashDoesNotTruncatePasswordSmallerThan73Characters(int $multiplier)
    {
        $passwordHashService = new PasswordHashBcryptService();
        $options = [
            'cost' => 4,
            'salt' => md5('salt')
        ];
        $basePassword = str_repeat('*', $multiplier);
        $passwordA = $basePassword . '_A';
        $passwordB = $basePassword . '_B';

        $passwordLength = strlen($passwordA);

        $hashA = $passwordHashService->hash($passwordA, $options);
        $hashB = $passwordHashService->hash($passwordB, $options);

        $this->assertNotEquals($hashA, $hashB, 'Expectation failed as passwords did get truncated for a password length of ' . $passwordLength);
    }

    public function stringMultiplierDataProvider(): array
    {
        $range = range(0, 70);
        $multipiliers = [];

        foreach ($range as $multipilier) {
            $multipiliers[] = [$multipilier];
        }

        return $multipiliers;
    }

    public function testHashTruncatesPasswordLongerThan72Characters()
    {
        $passwordHashService = new PasswordHashBcryptService();
        $options = [
            'cost' => 4,
            'salt' => md5('salt')
        ];
        $basePassword = str_repeat('*', 71);
        $passwordA = $basePassword . '_A';
        $passwordB = $basePassword . '_B';

        $passwordLength = strlen($passwordA);

        $hashA = $passwordHashService->hash($passwordA, $options);
        $hashB = $passwordHashService->hash($passwordB, $options);

        $this->assertEquals($hashA, $hashB, 'Expectation failed as passwords did not get truncated for a password length of ' . $passwordLength);
    }
}
