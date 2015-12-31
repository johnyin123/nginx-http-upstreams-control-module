#nginx http upstreams control module  
The guide of ngx_http_upstream_ctl_module module installation

#Install
1. Compile nginx with this ./configure option:

       --add-module=path/to/src/directory  

2. Copy the "html" directory's "bootstrap" folder and "jquery.min.js" to nginx "html" directory.

#Config 
   Add following content to nginx.conf:

    location ~^/upstreams {    

       upstreams_admin         on;    

       //auth_basic            "valid-user";    

       //auth_basic_user_file  oschina/oschina_pw;    

    }

#Use
   Enter http://host/upstreams

--- 
#Author
* by dss_liuhl 
* QQ:1610153337 
* email:15817409379@163.com

