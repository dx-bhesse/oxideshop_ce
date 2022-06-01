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
        $oSmarty->loadPlugin('smarty_function_eval');

        $y='string:';
        $k=0;
        foreach($aParams as $pName => $pVal) {
            $y .= '[{capture assign="oxeval' . $k . '"}]';
            $y .= $pVal;
            $y .= '[{/capture}]';
            $k++;
        }
        $y.='[{eval ';
        $k=0;
        foreach($aParams as $pName => $pVal)
        {
            if ($k>0)
            {
                $y.=' ';
            }
            $y.=$pName;
            $y.='=$oxeval'.$k;
            $k++;
        }
        $y.='}]';

        return $oSmarty->fetch($y);
    }

    return $aParams['var'];
}
