<style>
.opnsensehub-actions {
    margin-top: 10px;
    margin-bottom: 10px;
}
</style>

<script>
$( document ).ready(function() {
    var data_get_map = {'frm_GeneralSettings': '/api/opnsensehub/settings/get'};

    function escapeHtml(value) {
        return $('<div/>').text(value === null || value === undefined ? '' : value).html();
    }

    function setRuntimeField(name, value) {
        $('[name="' + name + '"]').val(value || '');
    }

    function refreshRuntimeStatus() {
        ajaxCall('/api/opnsensehub/service/status', {}, function(data) {
            setRuntimeField('opnsensehub.last_heartbeat', data && data.last_heartbeat ? data.last_heartbeat : '');
            setRuntimeField('opnsensehub.last_error', data && data.last_error ? data.last_error : '');
        });
    }

    mapDataToFormUI(data_get_map).done(function(){
        formatTokenizersUI();
        $('.selectpicker').selectpicker('refresh');
        refreshRuntimeStatus();
    });

    function formatHubMessage(data) {
        var status = data && data.status ? String(data.status) : 'unknown';
        var isError = status === 'error' || status === 'failed';
        var heading = isError ? 'Connection failed' : status === 'connected' ? 'Connected successfully' : status === 'removed' ? 'Removed successfully' : 'OPNsense Hub response';
        var alertClass = isError ? 'alert-danger' : status === 'connected' || status === 'removed' ? 'alert-success' : 'alert-info';
        var html = '<div class="alert ' + alertClass + '" style="margin-bottom: 12px;"><strong>' + escapeHtml(heading) + '</strong></div>';

        if (data && data.message) {
            html += '<p style="margin-bottom: 12px;">' + escapeHtml(data.message) + '</p>';
        }

        html += '<table class="table table-condensed table-striped" style="margin-bottom: 0;">';
        html += '<tbody>';
        html += '<tr><th style="width: 130px;">Status</th><td>' + escapeHtml(status) + '</td></tr>';
        if (data && data.interface) {
            html += '<tr><th>Interface</th><td><code>' + escapeHtml(data.interface) + '</code></td></tr>';
        }
        if (data && data.webgui_port) {
            html += '<tr><th>WebGUI Port</th><td><code>' + escapeHtml(data.webgui_port) + '</code></td></tr>';
        }
        if (data && data.last_heartbeat) {
            html += '<tr><th>Last heartbeat</th><td>' + escapeHtml(data.last_heartbeat) + '</td></tr>';
        }
        if (data && data.last_error) {
            html += '<tr><th>Last error</th><td>' + escapeHtml(data.last_error) + '</td></tr>';
        }
        if (data && data.detail) {
            html += '<tr><th>Detail</th><td>' + escapeHtml(data.detail) + '</td></tr>';
        }
        html += '</tbody></table>';
        return $(html);
    }

    function showHubDialog(data, defaultType) {
        var status = data && data.status ? String(data.status) : 'unknown';
        var dialogType = status === 'error' || status === 'failed' ? BootstrapDialog.TYPE_DANGER : defaultType;
        BootstrapDialog.show({type: dialogType, title: 'OPNsense Hub', message: formatHubMessage(data)});
    }

    $('#saveAct').click(function(){
        saveFormToEndpoint('/api/opnsensehub/settings/set', 'frm_GeneralSettings', function(){
            refreshRuntimeStatus();
            location.reload();
        });
    });
    $('#connectAct').click(function(){
        saveFormToEndpoint('/api/opnsensehub/settings/set', 'frm_GeneralSettings', function(){
            ajaxCall('/api/opnsensehub/service/connect', {}, function(data){
                showHubDialog(data, BootstrapDialog.TYPE_INFO);
                refreshRuntimeStatus();
            });
        });
    });
    $('#disconnectAct').click(function(){
        ajaxCall('/api/opnsensehub/service/disconnect', {}, function(data){
            showHubDialog(data, BootstrapDialog.TYPE_WARNING);
            refreshRuntimeStatus();
        });
    });
    $('#removeAct').click(function(){
        BootstrapDialog.confirm({
            type: BootstrapDialog.TYPE_DANGER,
            title: 'Remove OPNsense Hub',
            message: 'Remove the local OPNsense Hub WireGuard peer, interface assignment, and saved state?',
            callback: function(result) {
                if (!result) {
                    return;
                }
                ajaxCall('/api/opnsensehub/service/remove', {}, function(data){
                    showHubDialog(data, BootstrapDialog.TYPE_SUCCESS);
                    refreshRuntimeStatus();
                    location.reload();
                });
            }
        });
    });
});
</script>

<div class="content-box">
  {{ partial('layout_partials/base_form', ['fields': formGeneral, 'id': 'frm_GeneralSettings']) }}
  <div class="col-md-12 opnsensehub-actions">
    <button class="btn btn-primary" id="saveAct" type="button"><b>Save</b></button>
    <button class="btn btn-success" id="connectAct" type="button"><b>Connect</b></button>
    <button class="btn btn-warning" id="disconnectAct" type="button"><b>Disconnect</b></button>
    <button class="btn btn-danger" id="removeAct" type="button"><b>Remove</b></button>
  </div>
</div>
