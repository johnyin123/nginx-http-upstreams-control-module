#这是一个新分支
##使用新的用例场景开发
1. 点击ip_hash 和 keepalive 旁的update按钮更新对应后端的的upstream转发方式，即时生效
2. 点击server行的edit按钮更新server的运行参数，即时生效
3. 点击server行的enable/disable按钮更新启动或停止对应服务，即时生效

##更进一步
* 将ui界面元素配置化，使用户可自定义界面
  
  
---
*** 
  
#基于web的 nginx upstream 监控和管理模块
#nginx http upstreams control module  
本模块是为监视和控制nginx的upstream配置而写的nginx模块。  
本模块实现的功能可以让你随时查看nginx的upstream配置还能够对upstream服务器上的请求进行实时计数，同时还能在不退出nginx服务，不编辑nginx配置文件的情况下在线更改upstream配置。  

This is a nginx module for monitoring and control upstream.  
You can view http upstream configuration and statistical upstream service request count of nginx.You also can modify upstream configuration online by the browser without editting nginx configuration file and stopping nginx service. 
  
 
#安装
#Install
1. 用下面的./configure配置项编译nginx（版本：nginx-1.9.8）：  
1. Compile nginx (version:nginx-1.9.8) with this ./configure option:     

       --add-module=path/to/src/directory     

2. 将html目录下的所有东西拷贝到nginx的html目录。  
2. Copy the "html" directory's all things to nginx "html" directory.

#配置
#Config 
   将下面的内容添加到nginx.conf：  
   Add following content to nginx.conf:

    location ~^/upstreams {    

       upstreams_admin         on;    

       auth_basic              "valid user";    

       auth_basic_user_file     /usr/local/nginx/conf/oschina_pw;    

    }

#用法
#Use
   通过浏览器访问http://主机/upstreams  
   Access http://host/upstreams through the browser

--- 

#关于作者
#Author
* dss_liuhl 
* QQ:1610153337 
* email:15817409379@163.com
