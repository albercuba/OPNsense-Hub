<?php

namespace OPNsense\OPNsenseHub\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    private function runJsonCommand($command)
    {
        try {
            $output = trim((string)(new Backend())->configdRun($command));
        } catch (\Throwable $e) {
            return array('status' => 'error', 'message' => $e->getMessage());
        }

        if ($output === '') {
            return array('status' => 'error', 'message' => 'OPNsense Hub command returned no output');
        }

        $decoded = json_decode($output, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
            return array(
                'status' => 'error',
                'message' => 'OPNsense Hub command returned invalid JSON',
                'detail' => json_last_error_msg()
            );
        }

        return $decoded;
    }

    public function connectAction()
    {
        if ($this->request->isPost()) {
            return $this->runJsonCommand('opnsensehub connect');
        }
        return array('status' => 'failed', 'message' => 'POST required');
    }

    public function disconnectAction()
    {
        if ($this->request->isPost()) {
            return $this->runJsonCommand('opnsensehub disconnect');
        }
        return array('status' => 'failed', 'message' => 'POST required');
    }

    public function removeAction()
    {
        if ($this->request->isPost()) {
            return $this->runJsonCommand('opnsensehub remove');
        }
        return array('status' => 'failed', 'message' => 'POST required');
    }

    public function statusAction()
    {
        return $this->runJsonCommand('opnsensehub status');
    }
}
