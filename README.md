 
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
   将下面的内容添加到nginx.conf：  
   Add following content to nginx.conf:

    location ~^/upstreams {    

       upstreams_admin         on;    

       auth_basic              "valid user";    

       auth_basic_user_file     /usr/local/nginx/conf/oschina_pw;
        
       ui_lua_file              "/usr/local/nginx/html/ui.lua";
        
       timeout                  3000;
         
    }

#用法
#Use
   通过浏览器访问http://主机/upstreams  
   Access http://host/upstreams through the browser


#自定制UI
#Customize UI by yourself  

目前服务端提供如下API  
  
   * 配置查询接口    
   (HTTP) GET /upstreams

   * UI回调接口    
   (lua) write_html(data)  

   * Keepalive，Ip hash更新接口(waiting...)  
   (AJAX) POST /upstreams_update  
     post parameter:    
     {  
       method:'update',  
       backend:?(backend index that begin with 0),  
       ip_hash:?(0/1),  
       keepalive:?(unsigned integer)    
     }    
     response:  
     {  
        code:?(0,1,2,3,4,5),  
        message:'?'   
     }  
    

   * upstream 服务器参数编辑接口(waiting...)    
   (AJAX) POST /upstreams_edit   
     post parameter:      
     {   
        method:'edit',  
        backend:?(backend index that begin with 0),  
        server:?(server index that begin with 0),  
        weight:?(unsigned integer),  
        backup:?(0/1),  
        max_fails:?(unsigned integer),  
        fail_timeout:?(unsigned integer)  
     }    
     response:  
     {   
        code:?(0,1,2,3,4,5),   
        message:?  
     }   
    
   * upstream 服务器启停接口(waiting...)   
   (AJAX) POST /upstreams_enable   
     post parameter:    
     {   
        method:'enable',   
        backend:?(backend index that begin with 0),   
        server:?(server index that begin with 0),   
        down:? (0/1),   
     }    
     response:   
     {   
        code:?(0,1,2,3,4,5),   
        message:?   
     }   
   
--- 

#关于作者
#Author
* dss_liuhl 
* QQ:1610153337 
* email:15817409379@163.com