#nginx http upstreams control module  

This is a nginx module for monitoring and control upstream.  
You can view http upstream configuration and statistical upstream service request count of nginx.You also can modify upstream configuration online by browser without editting nginx configuration file and stopping nginx service. 
  
 

#Install
1. Compile nginx (version:nginx-1.9.8) with this ./configure option:     

       --add-module=path/to/src/directory     

2. Copy the "html" directory's all things to nginx "html" directory.

#Config 
   Add following content to nginx.conf:

    location ~^/upstreams {    

       upstreams_admin         on;    

       auth_basic              "valid user";    

       auth_basic_user_file     /usr/local/nginx/conf/oschina_pw;    

    }

#Use
   Access http://host/upstreams by browser

--- 
#Author
* by dss_liuhl 
* QQ:1610153337 
* email:15817409379@163.com

