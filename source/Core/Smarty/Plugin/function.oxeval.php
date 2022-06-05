<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

use OxidEsales\Eshop\Core\Registry;

/**
 * Smarty function
 * -------------------------------------------------------------
 * Purpose: eval given string
 * add [{oxeval var="..."}] where you want to display content
 * -------------------------------------------------------------
 *
 * @param array  $aParams  parameters to process
 * @param smarty &$oSmarty smarty object
 *
 * @return string
 *
 * @psalm-suppress UndefinedFunction
 */
function smarty_function_oxeval($aParams, &$oSmarty)
{
    if ($aParams['var'] && ($aParams['var'] instanceof \OxidEsales\Eshop\Core\Field)) {
        $aParams['var'] = trim($aParams['var']->getRawValue());
    }
    $deactivateSmarty = Registry::getConfig()->getConfigParam('deactivateSmartyForCmsContent');
    $processLongDescriptions = Registry::getConfig()->getConfigParam('bl_perfParseLongDescinSmarty') || isset($aParams['force']);
    if (!$deactivateSmarty && $processLongDescriptions) {

        // Params that can be passed to Smartys eval():
        $aValidSmartyParams = ['var', 'assign'];

        // Smartys built-in eval() cannot be called directly:
        $smartyContent = 'string:';

        // Store params in oxeval_{random}_paramName variables:
        // ({random} included in case oxeval is nested)
        $variablePrefix='oxeval_'.Registry::getUtilsObject()->generateUId().'_';
        foreach ($aValidSmartyParams as $paramName) {
            if (isset($aParams[$paramName])) {
                $oSmarty->assign($variablePrefix. $paramName, $aParams[$paramName]);
            }
        }

        // Call eval() with stored oxevalXXX-variables as params:
        $smartyContent .= '[{eval ';
        $k = 0;
        foreach ($aValidSmartyParams as $paramName) {
            if (isset($aParams[$paramName])) {
                if ($k > 0) {
                    $smartyContent .= ' ';
                }
                $smartyContent .= $paramName;
                $smartyContent .= '=$'.$variablePrefix . $paramName;
                $k++;
            }
        }
        $smartyContent .= '}]';

        return $oSmarty->fetch($smartyContent);
    }

    return $aParams['var'];
}
