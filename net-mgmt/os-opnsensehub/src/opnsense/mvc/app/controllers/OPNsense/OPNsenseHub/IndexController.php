<?php

namespace OPNsense\OPNsenseHub;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/OPNsenseHub/index');
        $this->view->formGeneral = $this->getForm('general');
    }
}
