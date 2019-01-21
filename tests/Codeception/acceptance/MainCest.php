<?php
/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\EshopCommunity\Tests\Codeception;

use OxidEsales\Codeception\Page\Home;
use OxidEsales\Codeception\Page\Account\UserOrderHistory;
use OxidEsales\Codeception\Module\Translation\Translator;

class MainCest
{
    public function frontPageWorks(AcceptanceTester $I)
    {
        $I->amOnPage(Home::$URL);
        $I->see(Translator::translate("HOME"));
    }

    /**
     * TODO: Should it be without translations?
     *
     * @param AcceptanceTester $I
     */
    public function shopBrowsing(AcceptanceTester $I)
    {
        // open start page
        $I->amOnPage(Home::$URL);

        $I->see(Translator::translate("HOME"));
        $I->see(Translator::translate('START_BARGAIN_HEADER'));

        // open category
        $I->click('Test category 0 [EN] šÄßüл', '#navigation');
        $I->see('Test category 0 [EN] šÄßüл', 'h1');

        // check if subcategory exists
        $I->see('Test category 1 [EN] šÄßüл', '#moreSubCat_1');

        //open Details page
        $I->click('#productList_1');

        // login to shop
        $I->amOnPage(UserOrderHistory::$URL);
        $I->waitForElement('h1', 10);
        $I->see(Translator::translate('LOGIN'), 'h1');

        $I->fillField(UserOrderHistory::$loginUserNameField,'example_test@oxid-esales.dev');
        $I->fillField(UserOrderHistory::$loginUserPasswordField,'useruser');
        $I->click(UserOrderHistory::$loginButton);

        $I->see(Translator::translate('ORDER_HISTORY'), 'h1');
    }

}
