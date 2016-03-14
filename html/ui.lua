--[[  

  Copyright (C) dss_liuhl
     QQ:1610153337
     email:15817409379@163.com
 
--]]--[[

	This is the default script written for user interface of upstream control module. The server generate response html page by performing this script code. You can customize this script to meet your ui demand as long as you comply the following constraints:

	1. Script Language: lua
	2. Interface Callback Function: write_html(data)
	   This function will be called by the nginx server on the server-side when you query upstream configuration through the browser.
	   1) The return value should be a html string.
	   2) The input parameter 'data' is table type, will be supplied by the server when calling.
	    An example for the input parameter 'data':
		data={
		  uptime=5,
		  backend_count=2,
		  backend_set={
		  	{
		    	backend='team-backend',
		    	ip_hash=0,
		    	keepalive=5,
		    	server_count=3,
		    	server_set={
		    		{
		       		server='192.168.1.99:8082',
		       		weight=1,
		       		backup=0,
		       		max_fails=10,
		       		fail_timeout=30,
		       		down=0,
		       		requests=12343,
		    		},
		    		{
		       		server='192.168.1.99',
		       		weight=2,
		       		backup=0,
		       		max_fails=10,
		       		fail_timeout=30,
		       		down=0,
		       		requests=456,
		    		},
		    		{
		       		server='192.168.1.99:8080',
		       		weight=2,
		       		backup=1,
		       		max_fails=10,
		       		fail_timeout=30,
		       		down=0,
		       		requests=900,
		    		},
		    	},
		  	},
		  	{
		    	backend='blog-backend',
		    	ip_hash=1,
		    	keepalive=0,
		    	server_count=3,
		    	server_set={
		    		{
		       		server='192.168.1.99:9082',
		       		weight=1,
		       		backup=0,
		       		max_fails=10,
		       		fail_timeout=30,
		       		down=0,
		       		requests=666,
		    		},
		    		{
		       		server='192.168.1.99:9093',
		       		weight=0,
		       		backup=0,
		       		max_fails=10,
		       		fail_timeout=30,
		       		down=0,
		       		requests=456,
		    		},
		    		{
		       		server='192.168.1.99:9080',
		       		weight=2,
		       		backup=0,
		       		max_fails=10,
		       		fail_timeout=30,
		       		down=1,
		       		requests=900,
		    		},
		    	},
		  	},  	
		  },
		}

--]]

status={
[0]="Normal",
[1]="Down",
}
enable={
[0]="disable",
[1]="enable",
}
backup={
[0]="No",
[1]="Yes",
}

function write_iphash(backend)
   if backend.ip_hash == 1 then
       return "<label><input type='checkbox' class='uc_iphash' value='1' checked='checked' />ip_hash</label>\n"
   else 
       return "<label><input type='checkbox' class='uc_iphash' value='1' />ip_hash</label>\n"
   end
end

function write_keepalive_options(backend)
   kp={}
   table.insert(kp,"<label for='"..backend.backend.."_keepalive'>keepalive:</label>\n")
   table.insert(kp,"<select id='"..backend.backend.."_keepalive' name='"..backend.backend.."_keepalive'>\n")
   
   for i=0,32,1 do
        table.insert(kp,"<option value='"..i.."'")
        if backend.keepalive==i then
             table.insert(kp," selected='selected' ")
        end
       	table.insert(kp," >"..i.."</option>\n")    
   end
   table.insert(kp,"</select>\n")
   return table.concat(kp)
end

function write_backends(data)
    local backend_set={}
    for i=1,data.backend_count,1 do
       local backend = {
        "<form class='form-inline' action='' v='"..(i-1).."'>\n",
             "<fieldset>\n",
                  "<legend><h2>"..data.backend_set[i].backend.."</h2></legend>\n",
                  "<div class='checkbox-inline'>\n",
                       write_iphash(data.backend_set[i]),
                  "</div>\n",
                  "<div class='form-group' style='margin-left:20px;'>\n",
			write_keepalive_options(data.backend_set[i]),
		  "</div>\n",
                  "<div class='form-group' style='margin-left:20px;'><label><input name='"..data.backend_set[i].backend.."_submit]' type='button' value='update' class='update_btn'></input></label></div><br>\n",
                    "<table  style='margin-top:10px;' class='table table-striped table-bordered'>\n",
           				"<tr>\n",
           					"<th>Server</th>\n",
           					"<th align='center' style='text-align:center'>Weight</th>\n",
           					"<th align='center' style='text-align:center'>Backup</th>\n",
           					"<th align='center' style='text-align:center'>max_fails</th>\n",
           					"<th align='center' style='text-align:center'>fail_timeout</th>\n",
           					"<th align='center' style='text-align:center'>Status</th>\n",
           					"<th align='right' style='text-align:right'>Requests</th>\n",
           					"<th>Operations</th>\n",
           				"</tr>\n",
					write_servers(data.backend_set[i]),
					"</table>\n",
				"</fieldset>\n",
			"</form>\n",
          }
       table.insert(backend_set,table.concat(backend))
    end
    return table.concat(backend_set)
end

function write_servers(backend)
    local server_set={}
	for i=1,backend.server_count,1 do
        local server={
           "<tr class='uc_server_row' v='"..(i-1).."'>\n",
                "<td>\n",
                	"<span class='uc_server'>"..backend.server_set[i].server.."</span>\n",
                "</td>\n",
                "<td align='center'>\n",
                	"<span class='uc_weight'>"..math.floor(backend.server_set[i].weight).."</span>\n",
                "</td>\n",
                "<td align='center'>\n",
                	"<span class='uc_backup' v='"..backend.server_set[i].backup.."'>"..backup[backend.server_set[i].backup].."</span>\n",
                "</td>\n",
                "<td align='center'>\n",
                	"<span class='uc_max_fails'>"..math.floor(backend.server_set[i].max_fails).."</span>\n",
                "</td>\n",
                "<td align='center'>\n",
                	"<span class='uc_fail_timeout'>"..math.floor(backend.server_set[i].fail_timeout).."</span>\n",
                "</td>\n",
                "<td align='center'>\n",
                	"<span class='uc_down' v='"..backend.server_set[i].down.."'>"..status[backend.server_set[i].down].."</span>\n",
                "</td>\n",
                "<td align='right'>\n",
                	math.floor(backend.server_set[i].requests),
                "</td>\n",
                "<td><a data-toggle='modal' data-target='#editdlg' style='cursor:pointer;'>edit</a> <a style='cursor:pointer;' class='enable_btn'>"..enable[backend.server_set[i].down].."</a></td>\n",
           "</tr>\n",
        }
        table.insert(server_set,table.concat(server))
	end
	return table.concat(server_set)
end

function write_dialog()
    local dlg={
    "<div class='modal fade' id='editdlg' tabindex='-1' role='dialog' aria-labelledby='editdlglabel'>\n",
        "<div class='modal-dialog' role='document'>\n",
           "<div class='modal-content'>\n",
               "<div class='modal-header'>\n",
                    "<button type='button' class='close' data-dismiss='modal' aria-label='Close'><span aria-hidden='true'>&times;</   span></button>\n",
                    "<h4 class='modal-title' id='editdlglabel'>Edit</h4>\n",
               "</div>\n",
               "<div class='modal-body'>\n",
                    "<form class='form-horizontal'>\n",
                         "<div class='form-group'>\n",
                              "<label for='m_server' class='col-sm-3 control-label'>Server:</label>\n",
                              "<p class='col-sm-9 form-control-static' id='m_server'>192.168.1.105:8525</p>\n",
                         "</div>\n",
                         "<div class='form-group'>\n",
                              "<label for='m_weight' class='col-sm-3 control-label'>Weight:</label>\n",
                              "<div class='col-sm-9'><input type='text' class='form-control' id='m_weight' value=''/></div>\n",
                         "</div>\n",
                         "<div class='form-group'>\n",
                              "<label for='m_backup' class='col-sm-3 control-label'>Backup:</label>\n",
                              "<div class='col-sm-9'><select class='form-control' id='m_backup'>\n",
                                  "<option value='1'>Yes</option>\n",
                                  "<option value='0'>No</option>\n",
                              "</select></div>\n",
                        "</div>\n",
                        "<div class='form-group'>\n",
                              "<label for='m_max_fails' class='col-sm-3 control-label'>max_fails:</label>\n",
                              "<div class='col-sm-9'><input type='text' class='form-control' id='m_max_fails' value=''/></div>\n",
                        "</div>\n",
                        "<div class='form-group'>\n",
                              "<label for='m_fail_timeout' class='col-sm-3 control-label'>fail_timeout:</label>\n",
                              "<div class='col-sm-9'><input type='text' class='form-control' id='m_fail_timeout' value=''/></div>\n",
                        "</div>\n",
                    "</form>\n",
                "</div>\n",
                "<div class='modal-footer'>\n",
                    "<button type='button' class='btn btn-primary' id='edit_btn'>OK</button>\n",
                "</div>\n",
           "</div>\n",
       "</div>\n",
    "</div>\n",
    "<div class='modal fade' id='suredlg' tabindex='-1' role='dialog' aria-labelledby='suredlglabel' m='' b='' s='' i='' k='' d=''>\n",
        "<div class='modal-dialog' role='document'>\n",
           "<div class='modal-content'>\n",
               "<div class='modal-header'>\n",
                    "<button type='button' class='close' data-dismiss='modal' aria-label='Close'><span aria-hidden='true'>&times;</   span></button>\n",
                    "<h4 class='modal-title' id='suredlglabel'>Warnning</h4>\n",
               "</div>\n",
               "<div class='modal-body'>\n",
                    "<p  class='text-warning'>Your commit will change the server's configuration. Are you sure to do this?</p>",
                "</div>\n",
                "<div class='modal-footer'>\n",
                    "<button type='button' class='btn btn-primary' id='sure_btn'>Yes</button>\n",
                    "<button type='button' class='btn btn-default' data-dismiss='modal'>No</button>\n",
                "</div>\n",
           "</div>\n",
       "</div>\n",
    "</div>\n",
    "<script src='/uc.js'></script>\n",
    }
    return table.concat(dlg)
end

function write_html(data) 
    local html={
        "<!DOCTYPE html>\n",
        "<html lang='zh-CN'>\n",
            "<head>\n",
                 "<meta charset='utf-8'>\n",
                 "<meta http-equiv='X-UA-Compatible' content='IE=edge'>\n",
                 "<meta name='viewport' content='width=device-width, initial-scale=1'>\n",
                 "<meta http-equiv='content-type' content='text/html; charset=UTF-8'>\n",
                 "<meta name='keywords' content='Nginx, Upstreams, Control, Nginx module' />\n",
                 "<meta name='description' content='Nginx Upstreams Control' />\n",
                 "<meta name='author' content='dss_liuhl(QQ:1610153337 email:15817409379@163.com)' />\n",
                 "<title>Nginx Upstreams</title>\n",
                 "<script>\n",
                      "window.jQuery || document.write(\'<script src=\"/jquery.min.js\"><\\/script>\')\n",
                 "</script>\n",
                 "<script src='/bootstrap/js/bootstrap.min.js'></script>\n",
                 "<link type='text/css' href='/bootstrap/css/bootstrap.min.css' rel='stylesheet'>\n",
             "</head>\n",
             "<body>\n",
                 "<div style='padding:20px;'>\n",
                      "<h1>Nginx Upstreams("..math.floor(data.backend_count)..")</h1>\n",
                      "<label>Uptime: "..math.floor(data.uptime).." days</label>\n",
                      write_backends(data),
		 "</div>\n",
                 write_dialog(),
	     "</body>\n",
         "</html>\n",
         }
     return table.concat(html)
end



