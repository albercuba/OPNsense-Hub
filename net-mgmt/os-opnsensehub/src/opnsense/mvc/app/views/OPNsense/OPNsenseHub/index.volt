<script>
$( document ).ready(function() {
    var data_get_map = {'frm_GeneralSettings': '/api/opnsensehub/settings/get'};
    mapDataToFormUI(data_get_map).done(function(){ formatTokenizersUI(); $('.selectpicker').selectpicker('refresh'); });

    $('#saveAct').click(function(){
        saveFormToEndpoint('/api/opnsensehub/settings/set', 'frm_GeneralSettings', function(){ ajaxCall('/api/opnsensehub/service/status', {}, function(){ location.reload(); }); });
    });
    $('#connectAct').click(function(){ ajaxCall('/api/opnsensehub/service/connect', {}, function(data){ BootstrapDialog.show({type: BootstrapDialog.TYPE_INFO, title: 'OPNsense Hub', message: JSON.stringify(data)}); }); });
    $('#disconnectAct').click(function(){ ajaxCall('/api/opnsensehub/service/disconnect', {}, function(data){ BootstrapDialog.show({type: BootstrapDialog.TYPE_WARNING, title: 'OPNsense Hub', message: JSON.stringify(data)}); }); });
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
