<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Core;

/**
 * Themes handler class.
 *
 * @internal Do not make a module extension for this class.
 * @see      https://oxidforge.org/en/core-oxid-eshop-classes-must-not-be-extended.html
 */
class Theme extends \OxidEsales\Eshop\Core\Base
{
    /**
     * Theme info array
     *
     * @var array
     */
    protected $_aTheme = [];

    /**
     * Theme info list
     *
     * @var array
     */
    protected $_aThemeList = [];

    /**
     * Load theme info
     *
     * @param string $sOXID theme id
     *
     * @return bool
     */
    public function load($sOXID)
    {
        $sFilePath = \OxidEsales\Eshop\Core\Registry::getConfig()->getViewsDir() . $sOXID . "/theme.php";
        if (file_exists($sFilePath) && is_readable($sFilePath)) {
            $aTheme = [];
            include $sFilePath;
            $this->_aTheme = $aTheme;
            $this->_aTheme['id'] = $sOXID;
            $this->_aTheme['active'] = ($this->getActiveThemeId() == $sOXID);

            return true;
        }

        return false;
    }

    /**
     * Set theme as active
     */
    public function activate()
    {
        $sError = $this->checkForActivationErrors();
        if ($sError) {
            /** @var \OxidEsales\Eshop\Core\Exception\StandardException $oException */
            $oException = oxNew(\OxidEsales\Eshop\Core\Exception\StandardException::class, $sError);
            throw $oException;
        }
        $sParent = $this->getInfo('parentTheme');
        if ($sParent) {
            \OxidEsales\Eshop\Core\Registry::getConfig()->saveShopConfVar("str", 'sTheme', $sParent);
            \OxidEsales\Eshop\Core\Registry::getConfig()->saveShopConfVar("str", 'sCustomTheme', $this->getId());
        } else {
            \OxidEsales\Eshop\Core\Registry::getConfig()->saveShopConfVar("str", 'sTheme', $this->getId());
            \OxidEsales\Eshop\Core\Registry::getConfig()->saveShopConfVar("str", 'sCustomTheme', '');
        }
        $settingsHandler = oxNew(\OxidEsales\Eshop\Core\SettingsHandler::class);
        $settingsHandler->setModuleType('theme')->run($this);
    }

    /**
     * Load theme info list
     *
     * @return array
     */
    public function getList()
    {
        $this->_aThemeList = [];
        $sOutDir = \OxidEsales\Eshop\Core\Registry::getConfig()->getViewsDir();
        foreach (glob($sOutDir . "*", GLOB_ONLYDIR) as $sDir) {
            $oTheme = oxNew(\OxidEsales\Eshop\Core\Theme::class);
            if ($oTheme->load(basename($sDir))) {
                $this->_aThemeList[$sDir] = $oTheme;
            }
        }

        return $this->_aThemeList;
    }

    /**
     * Return theme information
     *
     * @param string $sName name of info item to retrieve
     *
     * @return mixed
     */
    public function getInfo($sName)
    {
        if (!isset($this->_aTheme[$sName])) {
            return null;
        }

        return $this->_aTheme[$sName];
    }

    /**
     * Returns the currently active frontend theme id
     *
     * @return string
     */
    public function getActiveThemeId()
    {
        $sCustTheme = \OxidEsales\Eshop\Core\Registry::getConfig()->getConfigParam('sCustomTheme');
        if ($sCustTheme) {
            return $sCustTheme;
        }

        return \OxidEsales\Eshop\Core\Registry::getConfig()->getConfigParam('sTheme');
    }

    /**
     * Returns the ids of the active theme and its parent themes
     * (e.g. ['childchildtheme','childtheme','wave'])
     * @param $theme
     * @return string[]
     */
    public function getThemeIdChain($theme)
    {
        $themeIds=[];
        $checkThemeId=$theme;
        while($checkThemeId)
        {
            $themeIds[]=$checkThemeId;
            $oTheme=oxNew(\OxidEsales\Eshop\Core\Theme::class);
            if ($oTheme->load($checkThemeId))
            {
                $checkThemeId=$oTheme->getParentId();
            }
            else{
                $checkThemeId='';
            }
        }

        return $themeIds;
    }

    /**
     * Gets ids of active theme and their parents.
     * Examples:
     *      if flow theme is active we will get ['flow']
     *      if azure is extended by some other we will get ['azure', 'extending_theme']
     *
     * @return array
     */
    public function getActiveThemesList()
    {
        $activeThemeList = [];
        if (!$this->isAdmin()) {

            $themeId=$this->getActiveThemeId();
            while($themeId)
            {
                $oTheme=oxNew(Theme::class);
                if ($oTheme->load($themeId))
                {
                    $activeThemeList[]=$themeId;
                    $themeId=$oTheme->getParentId();
                }
            }

            $activeThemeList=array_reverse($activeThemeList);
        }

        return $activeThemeList;
    }

    public function getParentId()
    {
        return $this->getInfo('parentTheme');
    }

    /**
     * Return loaded parent
     *
     * @return \OxidEsales\Eshop\Core\Theme
     */
    public function getParent()
    {
        $sParent = $this->getParentId();
        if (!$sParent) {
            return null;
        }
        $oTheme = oxNew(\OxidEsales\Eshop\Core\Theme::class);
        if ($oTheme->load($sParent)) {
            return $oTheme;
        }

        return null;
    }

    /**
     * run pre-activation checks and return EXCEPTION_* translation string if error
     * found or false on success
     *
     * @return string
     */
    public function checkForActivationErrors()
    {
        if (!$this->getId()) {
            return 'EXCEPTION_THEME_NOT_LOADED';
        }
        $oParent = $this->getParent();
        if ($oParent) {
            $sParentVersion = $oParent->getInfo('version');
            if (!$sParentVersion) {
                return 'EXCEPTION_PARENT_VERSION_UNSPECIFIED';
            }
            $aMyParentVersions = $this->getInfo('parentVersions');
            if (!$aMyParentVersions || !is_array($aMyParentVersions)) {
                return 'EXCEPTION_UNSPECIFIED_PARENT_VERSIONS';
            }
            if (!in_array($sParentVersion, $aMyParentVersions)) {
                return 'EXCEPTION_PARENT_VERSION_MISMATCH';
            }
        } elseif ($this->getInfo('parentTheme')) {
            return 'EXCEPTION_PARENT_THEME_NOT_FOUND';
        }

        return false;
    }

    /**
     * Get theme ID
     *
     * @return string
     */
    public function getId()
    {
        return $this->getInfo("id");
    }
}
