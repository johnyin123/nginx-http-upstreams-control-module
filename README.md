 
#基于web的 nginx upstream 监控和管理模块
#nginx http upstreams control module  
本模块是为监视和控制nginx的upstream配置而写的nginx模块。  
本模块实现的功能可以让你随时查看nginx的upstream配置还能够对upstream服务器上的请求进行实时计数，同时还能在不退出nginx服务，不编辑nginx配置文件的情况下在线更改upstream配置。  

This is a nginx module for monitoring and control upstream.  
You can view http upstream configuration and statistical upstream service request count of nginx.You also can modify upstream configuration online by the browser without editting nginx configuration file and stopping nginx service. 
  
 
#安装
#Install
* 安装模块依赖项：lua5.2 和 lua-cjson
* Install dependencies for this module  
  
         lua5.2  
         lua-cjson  
  
  
* 用下面的./configure配置项编译nginx（版本：nginx-1.9.8）：  
* Compile nginx (version:nginx-1.9.8) with this ./configure option:     

        --add-module=path/to/src/directory   
        --with-cc-opt="-I /usr/include/lua5.2"   
        --with-ld-opt="-l lua5.2 -L /usr/lib/i386-linux-gnu"    

* 将html目录下的所有东西拷贝到nginx的html目录。  
* Copy the "html" directory's all things to nginx "html" directory.

#配置
#Config 
   将类似下面的内容添加到nginx.conf：  
   Add like following content to nginx.conf:

    location ~^/upstreams {    

        upstreams_admin         on;    

        auth_basic              "valid user";    

        auth_basic_user_file     /usr/local/nginx/conf/oschina_pw;
        
        ui_lua_file              /usr/local/nginx/html/ui.lua;
        
        timeout                  3;
         
    }  

#用法
#Use
   通过浏览器访问http://您的WEB服务器/upstreams  
   Access http://domain/upstreams through the browser


#配置指令
#configuration directive for nginx
   * upstreams_admin

        开启或关闭upstream的监控功能,开启设置此值为on,关闭设置此值为off
        举例：upstreams_admin on
  
        On or off this module function.
        example：upstreams_admin on
  
   * auth_basic  

        请参考nginx对应指令说明  
        Please reference to auth_basic directive of nginx
  
   * auth_basic_user_file

        请参考nginx对应指令说明
        Please reference to auth_basic_user_file directive of nginx
  
   * ui_lua_file

        UI脚本文件路径（lua脚本文件）
        如果未设置，默认为path/to/nginx/html/ui.lua
        举例：ui_lua_file /usr/local/nginx/html/myui.lua
  
        The UI lua script file path, default value is path/to/nginx/html/ui.lua
        example: ui_lua_file /usr/local/nginx/html/myui.lua

   * timeout

        更新upstream配置的超时时间（单位：秒）。如果未设置，默认为3秒
        举例：timeout 5

        The response timeout for post upstream modification request, default value is 3 second. 
        example:timeout 5
    
#API
   * 配置查询接口 
   * query upstream configuration  
 
        GET /upstreams   
        通过web客户访问   
      
   * UI回调接口  
   * UI callback interface  

        (lua) write_html(data)    
        在nginx服务端回调   

   * Keepalive，Ip hash更新接口  
   * update Keepalive，Ip hash for the backend

        (AJAX) POST /upstreams_update   
        请求参数： 
        parameter:   
         {  
            method:'update',  
            backend:?,  
            ip_hash:?,  
            keepalive:?     
         }    
        响应格式： 
        response:  
         {  
            code:?,  
            message:'?'   
         }  

        说明：  
        explaining:

        请求和响应均为json格式  

        method:指明请求的类型，值固定为字符串“update”，表示更新upstream 后端的ip_hash配置和keepalive配置   

        backend:upstream后端索引（从0开始），该索引与nginx配置文件中的后端从上到下顺序对应  

        ip_hash:新的ip_hash值，只能取0或1  

        keepalive:新的keepalive值，0或正整数，0表示关闭keepalive，大于0表示keepalive cache数量（请参考aginx对应指令）  

        code:返回码  
        0 更新upstream配置成功     
        1 服务器处理超时    
        2 更新出错    
        3 服务器忙    
        4 请求参数错误    
        5 未知错误  
 
        message:与返回码对应的消息文本
   
   * upstream 服务器参数编辑接口  
  
        (AJAX) POST /upstreams_edit   
        请求参数:      
         {   
            method:'edit',  
            backend:?,  
            server:?,  
            weight:?,  
            backup:?,  
            max_fails:?,  
            fail_timeout:?  
         }    
        响应格式:  
         {   
            code:?,   
            message:'?'  
         }   

        说明：  

        请求和响应均为json格式  

        method:指明请求的类型，值固定为字符串“edit”，表示更新upstream 后端某个server的配置   

        backend:upstream后端索引（从0开始），该索引与nginx配置文件中的后端从上到下顺序对应  

        server:server索引（从0开始），该索引与nginx配置文件中的某一后端的服务器从上到下顺序对应  

        weight:请参考aginx对应指令说明  

        backup:表示是否将服务器设为备份，只能取0或1。0为不备份，1为备份  

        max_fails:请参考aginx对应指令说明  

        fail_timeout:请参考aginx对应指令说明  

        code:返回码  
        0 更新upstream配置成功     
        1 服务器处理超时    
        2 更新出错    
        3 服务器忙    
        4 请求参数错误    
        5 未知错误   

        message:与返回码对应的消息文本
    
   * upstream 服务器启停接口  
 
        (AJAX) POST /upstreams_enable   
        请求参数:    
         {   
           method:'enable',   
           backend:?,   
           server:?,   
           down:?,   
         }    
        响应格式:   
         {   
           code:?,   
           message:'?'   
         }   
   
        说明：  

        请求和响应均为json格式  

        method:指明请求的类型，值固定为字符串“enable”，表示启动或停止upstream某个server   

        backend:upstream后端索引（从0开始），该索引与nginx配置文件中的后端从上到下顺序对应  

        server:server索引（从0开始），该索引与nginx配置文件中的某一后端的服务器从上到下顺序对应  

        down:表示是否停止服务器，只能取0或1。0为启动，1为停止  

        code:返回码  
        0 更新upstream配置成功     
        1 服务器处理超时    
        2 更新出错    
        3 服务器忙    
        4 请求参数错误    
        5 未知错误   

        message:与返回码对应的消息文本

#自定制UI
#Customize UI by yourself  

你可以利用API定制属于自己的响应界面，方法如下：  
You can customize your UI by the API following these steps:

1. 使用lua脚本编写html响应页面，由服务端在执行WEB查询接口响应时进行回调  
1. Edit the html response page script using lua script language. That will be called by the nginx server on the server-side when you query upstream configuration through the browser.  

2. 使用诸如javascript的客户脚本调用AJAX接口来更新upstream配置  
2. Edit the client script such as javascript to modify upstream configuration. The client script can be embbed into the html page Whick you just has written in previous step.   
   
--- 

#关于作者
#Author
* dss_liuhl 
* QQ:1610153337 
* email:15817409379@163.com
