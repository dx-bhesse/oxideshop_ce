<?php
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Core;

use OxidEsales\EshopCommunity\Internal\Application\ContainerFactory;
use OxidEsales\EshopCommunity\Internal\Password\Bridge\PasswordServiceBridgeInterface;
use OxidEsales\EshopCommunity\Internal\Password\Exception\PasswordHashException;
use OxidEsales\EshopCommunity\Internal\Password\Service\PasswordHashBcryptService;
use OxidEsales\EshopCommunity\Internal\Password\Service\PasswordHashServiceInterface;

/**
 * Hash password together with salt, using set hash algorithm
 */
class PasswordHasher
{
    /**
     * @var \OxidEsales\Eshop\Core\Hasher|PasswordHashServiceInterface
     */
    private $passwordHashService;

    /**
     * Sets dependencies.
     *
     * @param \OxidEsales\Eshop\Core\Hasher|PasswordHashServiceInterface $passwordHashService
     */
    public function __construct($passwordHashService)
    {
        if (!$passwordHashService instanceof Hasher &&
            !$passwordHashService instanceof PasswordHashServiceInterface
        ) {
            throw new PasswordHashException('Unsupported password hashing service: ' . get_class($passwordHashService));
        }

        $this->passwordHashService = $passwordHashService;
    }

    /**
     * Hash password with a salt.
     *
     * @param string $password not hashed password.
     * @param string $salt     salt string.
     *
     * @return string
     */
    public function hash($password, $salt): string
    {
        $passwordHashService = $this->_getHasher();

        if ($passwordHashService instanceof Hasher) {
            $hash = $passwordHashService->hash($password . $salt);
        } elseif ($passwordHashService instanceof PasswordHashServiceInterface) {
            $options = $this->getOptionsForHashService($passwordHashService, $salt);

            $hash = $passwordHashService->hash($password, $options);
        }

        return $hash;
    }

    /**
     * Returns password hash service
     *
     * @return \OxidEsales\Eshop\Core\Hasher|PasswordHashServiceInterface
     */
    protected function _getHasher()
    {
        return $this->passwordHashService;
    }

    /**
     * @param PasswordHashServiceInterface $passwordHashService
     * @param string                       $salt
     *
     * @return array
     */
    private function getOptionsForHashService(PasswordHashServiceInterface $passwordHashService, string $salt): array
    {
        if ($passwordHashService instanceof PasswordHashBcryptService) {
            $cost = ContainerFactory::getInstance()
                ->getContainer()
                ->get(PasswordServiceBridgeInterface::class)
                ->getBcryptCostOption();
            $options = [
                'salt' => $salt,
                'cost' => $cost
            ];
        }

        return $options;
    }
}
