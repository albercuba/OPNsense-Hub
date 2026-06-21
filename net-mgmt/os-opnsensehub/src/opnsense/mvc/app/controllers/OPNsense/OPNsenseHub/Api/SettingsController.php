<?php

namespace OPNsense\OPNsenseHub\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\OPNsenseHub\OPNsenseHub;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'opnsensehub';
    protected static $internalModelClass = OPNsenseHub::class;

}
