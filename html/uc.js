/*! uc javascript
Copyright (C) dss_liuhl
QQ:1610153337
email:15817409379@163.com
 */

function readitem(server, item)
{
    var server_item_obj = $("#" + server + "\\[" + item + "\\]"); //commit obj
    var server_item = $("#m_" + item).val(server_item_obj.val());
}

function updateitem(server, item)
{
    var server_item_obj = $("#" + server + "\\[" + item + "\\]"); //commit obj
    var server_item_display = server_item_obj.parents("td").first().find("span"); //display obj
    var server_item = $("#m_" + item).val();
    
    if (server_item != server_item_display.attr('run'))
    {
        server_item_display.attr('style', 'color:red');
    }
    else
    {
        server_item_display.attr('style', 'color:green');
    }
    server_item_display.text(server_item);
    server_item_obj.val(server_item);
}

$('#editdlg').on('show.bs.modal', function (event)
{
    
    var button = $(event.relatedTarget);
    var server = button.data('whatever');
    server = server.replace(/[\[]/g, "\\[");
    server = server.replace(/[\]]/g, "\\]");
    
    var server_name = $("#" + server + "\\[name\\]").val();
    var modal = $(this);
    modal.attr('datakey', server);
    modal.find('.modal-title').text('Edit Server: ' + server_name);
    modal.find('#m_server').text('Edit Server: ' + server_name);
    
    readitem(server, 'weight');
    readitem(server, 'backup');
    readitem(server, 'max_fails');
    readitem(server, 'fail_timeout');
    
}
);

$(".modal-footer>button").click(function ()
{
    
    var server = $("#editdlg").attr('datakey');
    
    updateitem(server, "weight");
    updateitem(server, "backup");
    updateitem(server, "max_fails");
    updateitem(server, "fail_timeout");
    
    $("#editdlg").modal("hide");
    
}
);
