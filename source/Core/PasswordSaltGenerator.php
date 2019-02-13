<?php declare(strict_types=1);
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Core;

use OxidEsales\Eshop\Core\Exception\StandardException;

/**
 * Generates Salt for the user password
 */
class PasswordSaltGenerator
{
    /**
     * @var \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
     *
     * @deprecated since v6.4.0 (2019-01-30); This property will be removed completely
     */
    private $_openSSLFunctionalityChecker;

    /**
     * Sets dependencies.
     *
     * @param \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker $openSSLFunctionalityChecker
     *
     * @deprecated since v6.4.0 (2019-01-30); The constructor will be removed completely
     */
    public function __construct(\OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker $openSSLFunctionalityChecker)
    {
        $this->_openSSLFunctionalityChecker = $openSSLFunctionalityChecker;
    }


    /**
     * Generates a string, which is suitable for cryptographic use
     *
     * @param int $saltLength
     *
     * @throws \Exception
     * @throws StandardException
     *
     * @return string
     */
    public function generateStrongSalt(int $saltLength = 32): string
    {
        $minimumSaltLenght = 32;
        $maximumSaltLenght = 128;
        if ($saltLength < $minimumSaltLenght || $saltLength > $maximumSaltLenght) {
            throw new StandardException(
                'Error: Invalid salt lenght: "' . $saltLength . '". It should be a value between ' . $minimumSaltLenght . ' and ' . $maximumSaltLenght
            );
        }

        $numberOfRandomBytesToGenerate = $saltLength / 2;

        return bin2hex(random_bytes($numberOfRandomBytesToGenerate));
    }

    /**
     * Caution this method may return a string, that is not suitable for cryptographic use.
     *
     * @deprecated since v6.4.0 (2019-01-30); This method will be removed completely, use \OxidEsales\EshopCommunity\Core\PasswordSaltGenerator::generateStrongSalt instead.
     *
     * @return string
     */
    public function generate(): string
    {
        $bytes = $this->generatePseudoRandomBytes();
        $salt = bin2hex($bytes);

        if ('' === $salt) {
            $sSalt = $this->_customSaltGenerator();
        }

        return $sSalt;
    }

    /**
     * @deprecated since v6.4.0 (2019-01-30); This method will be removed completely.
     *
     * @return string
     */
    public function generatePseudoRandomBytes(): string
    {
        $pseudoRandomBytes = '';
        if ($this->_getOpenSSLFunctionalityChecker()->isOpenSslRandomBytesGeneratorAvailable()) {
            $generatedBytes = openssl_random_pseudo_bytes(16, $cryptographicallyStrong);
            if (false === $generatedBytes || false === $cryptographicallyStrong) {
                $pseudoRandomBytes = '';
            }
        }

        return $pseudoRandomBytes;
    }

    /**
     * Gets open SSL functionality checker.
     *
     * @deprecated since v6.4.0 (2019-01-30); This method will be removed completely
     *
     * @return \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
     */
    protected function _getOpenSSLFunctionalityChecker(): \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
    {
        return $this->_openSSLFunctionalityChecker;
    }

    /**
     * Generates custom salt.
     *
     * @deprecated since v6.4.0 (2019-01-30); This method will be removed completely.
     *
     * @return string
     */
    protected function _customSaltGenerator()
    {
        $sHash = '';
        $sSalt = '';
        for ($i = 0; $i < 32; $i++) {
            $sHash = hash('sha256', $sHash . mt_rand());
            $iPosition = mt_rand(0, 62);
            $sSalt .= $sHash[$iPosition];
        }

        return $sSalt;
    }
}
