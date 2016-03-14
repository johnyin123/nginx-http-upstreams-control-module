/*! uc javascript
Copyright (C) dss_liuhl
QQ:1610153337
email:15817409379@163.com
 */

$(".update_btn").click(function ()
{
    var $backend = $(this).parents("form");
    var $dlg = $("#suredlg");

    var $iphash = $backend.find(".uc_iphash");
    var iphash = 0;
    if ($iphash.get(0).checked)
    {
        iphash = 1;
    }
    var keepalive = $backend.find("select").val();

    $dlg.attr("m", "update");
    $dlg.attr("b", $backend.attr('v'));
    $dlg.attr('i', iphash);
    $dlg.attr('k', keepalive);

    $("#suredlg").modal("show");

}
);

$('#editdlg').on('show.bs.modal', function (event)
{

    var $button = $(event.relatedTarget);
    var $server_row = $button.parents("tr").first();

    var server = $server_row.attr("v");
    var backend = $button.parents("form").first().attr("v");

    var server_name = $server_row.find(".uc_server").text();

    var modal = $(this);

    modal.find('.modal-title').text('Edit Server: ' + server_name);
    modal.find('#m_server').text('Edit Server: ' + server_name);

    $("#m_server").val($server_row.find(".uc_server").text());
    $("#m_weight").val($server_row.find(".uc_weight").text());
    $("#m_backup").val($server_row.find(".uc_backup").attr('v'));
    $("#m_max_fails").val($server_row.find(".uc_max_fails").text());
    $("#m_fail_timeout").val($server_row.find(".uc_fail_timeout").text());

    var $suredlg = $("#suredlg");
    $suredlg.attr('b', backend);
    $suredlg.attr('s', server);
    $suredlg.attr('m', "edit");
}
);

$("#edit_btn").click(function ()
{
    $("#editdlg").modal("hide");
    $("#suredlg").modal("show");
}
);

$(".enable_btn").click(function ()
{
    var $backend = $(this).parents("form");
    var $server_row = $(this).parents("tr");

    var $dlg = $("#suredlg");

    var $btn = $(this);

    $dlg.attr("m", "enable");
    $dlg.attr("b", $backend.attr('v'));
    $dlg.attr("s", $server_row.attr('v'));

    if ($btn.text() == "disable")
    {
        $dlg.attr('d', 1);
    }
    else if ($btn.text() == "enable")
    {
        $dlg.attr('d', 0);
    }
    $dlg.modal("show");

}
);

$("#sure_btn").click(function ()
{
    var $dlg = $("#suredlg");
    var method = $dlg.attr("m");

    $dlg.modal("hide");

    var data = {};

    switch (method)
    {
    case "update":
        data.method = "update";
        data.backend = $dlg.attr("b");
        data.ip_hash = $dlg.attr("i");
        data.keepalive = $dlg.attr("k");
        $.post("upstreams_update", data, function (result)
        {
            var response = $.parseJSON(result);
            if (response.code == 0)
            {
                alert(response.message);
                window.location.href = "/upstreams";
            }
            else
            {
                alert(response.message);
            }

        }
        );
        break;

    case "edit":
        data.method = "edit";
        data.backend = $dlg.attr("b");
        data.server = $dlg.attr("s");
        data.weight = $("#m_weight").val();
        data.backup = $("#m_backup").val();
        data.max_fails = $("#m_max_fails").val();
        data.fail_timeout = $("#m_fail_timeout").val();

        $.post("/upstreams_edit", data, function (result)
        {
            var response = $.parseJSON(result);
            if (response.code == 0)
            {
                alert(response.message);
                window.location.href = "/upstreams";
            }
            else
            {
                alert(response.message);
            }

        }
        );
        break;
    case "enable":
        data.method = "enable";
        data.backend = $dlg.attr("b");
        data.server = $dlg.attr("s");
        data.down = $dlg.attr("d");
        $.post("/upstreams_enable", data, function (result)
        {
            var response = $.parseJSON(result);
            if (response.code == 0)
            {
                alert(response.message);
                window.location.href = "/upstreams";
            }
            else
            {
                alert(response.message);
            }

        }
        );
        break;
    default:
        alert("Unknown method.");
        break;
    }

    return false;

}
);
