<script>
$( document ).ready(function() {
    var data_get_map = {'frm_GeneralSettings': '/api/opnsensehub/settings/get'};
    mapDataToFormUI(data_get_map).done(function(){ formatTokenizersUI(); $('.selectpicker').selectpicker('refresh'); });

    function escapeHtml(value) {
        return $('<div/>').text(value === null || value === undefined ? '' : value).html();
    }

    function formatHubMessage(data) {
        var status = data && data.status ? String(data.status) : 'unknown';
        var isError = status === 'error' || status === 'failed';
        var heading = isError ? 'Connection failed' : status === 'connected' ? 'Connected successfully' : 'OPNsense Hub response';
        var alertClass = isError ? 'alert-danger' : status === 'connected' ? 'alert-success' : 'alert-info';
        var html = '<div class="alert ' + alertClass + '" style="margin-bottom: 12px;"><strong>' + escapeHtml(heading) + '</strong></div>';

        if (data && data.message) {
            html += '<p style="margin-bottom: 12px;">' + escapeHtml(data.message) + '</p>';
        }

        html += '<table class="table table-condensed table-striped" style="margin-bottom: 0;">';
        html += '<tbody>';
        html += '<tr><th style="width: 130px;">Status</th><td>' + escapeHtml(status) + '</td></tr>';
        if (data && data.device_id) {
            html += '<tr><th>Device ID</th><td><code>' + escapeHtml(data.device_id) + '</code></td></tr>';
        }
        if (data && data.tunnel_ip) {
            html += '<tr><th>Tunnel IP</th><td><code>' + escapeHtml(data.tunnel_ip) + '</code></td></tr>';
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
        saveFormToEndpoint('/api/opnsensehub/settings/set', 'frm_GeneralSettings', function(){ ajaxCall('/api/opnsensehub/service/status', {}, function(){ location.reload(); }); });
    });
    $('#connectAct').click(function(){
        saveFormToEndpoint('/api/opnsensehub/settings/set', 'frm_GeneralSettings', function(){
            ajaxCall('/api/opnsensehub/service/connect', {}, function(data){
                showHubDialog(data, BootstrapDialog.TYPE_INFO);
            });
        });
    });
    $('#disconnectAct').click(function(){ ajaxCall('/api/opnsensehub/service/disconnect', {}, function(data){ showHubDialog(data, BootstrapDialog.TYPE_WARNING); }); });
});
</script>

<div class="content-box">
  {{ partial('layout_partials/base_form', ['fields': formGeneral, 'id': 'frm_GeneralSettings']) }}
  <div class="col-md-12">
    <button class="btn btn-primary" id="saveAct" type="button"><b>Save</b></button>
    <button class="btn btn-success" id="connectAct" type="button"><b>Connect</b></button>
    <button class="btn btn-danger" id="disconnectAct" type="button"><b>Disconnect</b></button>
  </div>
</div>
