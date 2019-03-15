<?php declare(strict_types=1);
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Core;

use OxidEsales\Eshop\Core\Exception\StandardException;

/**
 * Generates Salt for the user password
 *
 * @deprecated since v6.4.0 (2019-03-15); This class will be removed completely.
 */
class PasswordSaltGenerator
{
    /**
     * @var \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
     */
    private $_openSSLFunctionalityChecker;

    /**
     * Sets dependencies.
     *
     * @param \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker $openSSLFunctionalityChecker
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
        $minimumSaltLength = 32;
        $maximumSaltLength = 128;
        if ($saltLength < $minimumSaltLength || $saltLength > $maximumSaltLength) {
            throw new StandardException(
                'Error: Invalid salt length: "' . $saltLength . '". It should be a value between ' . $minimumSaltLength . ' and ' . $maximumSaltLength
            );
        }

        $numberOfRandomBytesToGenerate = $saltLength / 2;

        return bin2hex(random_bytes($numberOfRandomBytesToGenerate));
    }

    /**
     * Caution this method may return a string, that is not suitable for cryptographic use.
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
     * @return \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
     */
    protected function _getOpenSSLFunctionalityChecker(): \OxidEsales\Eshop\Core\OpenSSLFunctionalityChecker
    {
        return $this->_openSSLFunctionalityChecker;
    }

    /**
     * Generates custom salt.
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
