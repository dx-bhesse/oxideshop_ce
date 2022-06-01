<?php

namespace OxidEsales\EshopCommunity\Core\Smarty;

class OxidSmartySecurityPolicy extends \Smarty_Security
{
    public function __construct($smarty)
    {
        parent::__construct($smarty);

        $this->allow_constants=true;
        $this->php_functions = [
            'empty',
            'isset',
            'is_array',
            'in_array',
            'is_int',
            'count'
        ];
        $this->php_modifiers = [
            'count',
            'round',
            'floor',
            'trim',
            'explode',
            'implode',
            'is_array',
            'getimagesize',
            'var_dump',
            'strtotime',
            'nl2br',
            'parse_url', // dynscript.tpl
            'oxNew'      // dynscript.tpl
        ];
    }
}