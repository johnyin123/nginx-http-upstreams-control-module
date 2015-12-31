#nginx http upstreams control module  
The guide of ngx_http_upstream_ctl_module module installation


##1.Install
To install, compile nginx with this ./configure option:

    --add-module=path/to/this/directory


##2.Config   
  

    location ~^/upstreams {  

        upstreams_admin         on;  

        //auth_basic            "valid-user";  

        //auth_basic_user_file  oschina/oschina_pw;  
    
    }   
 

##3.Use
Enter http://host/upstreams

--- 
##Author
* by dss_liuhl 
* QQ:1610153337 
* email:15817409379@163.com

