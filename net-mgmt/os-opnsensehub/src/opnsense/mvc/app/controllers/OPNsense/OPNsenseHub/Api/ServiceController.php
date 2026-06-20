<?php

namespace OPNsense\OPNsenseHub\Api;

use OPNsense\Base\ApiControllerBase;

class ServiceController extends ApiControllerBase
{
    public function connectAction()
    {
        if ($this->request->isPost()) {
            return json_decode(trim((string)$this->configdRun('opnsensehub connect')), true);
        }
        return array('status' => 'failed', 'message' => 'POST required');
    }

    public function disconnectAction()
    {
        if ($this->request->isPost()) {
            return json_decode(trim((string)$this->configdRun('opnsensehub disconnect')), true);
        }
        return array('status' => 'failed', 'message' => 'POST required');
    }

    public function statusAction()
    {
        return json_decode(trim((string)$this->configdRun('opnsensehub status')), true);
    }
}
