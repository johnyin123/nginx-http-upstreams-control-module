/*
* Copyright (C) dss_liuhl
*     QQ:1610153337
*     email:15817409379@163.com
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_channel.h>


#define SIG_UPSTREAM_SYN                 36
#define CHANNEL_CMD_UPSTREAM_SYN         1024

#define UPSTREAM_CTL_ADM_OFF             0
#define UPSTREAM_CTL_ADM_ON              1
#define TEMPLATE_BUFFER_SIZE             20
#define UC_MAX_RESPONSE_SIZE             20000


extern ngx_module_t ngx_http_upstream_module;
extern ngx_module_t ngx_http_upstream_ip_hash_module;
extern ngx_module_t ngx_http_upstream_keepalive_module;
extern ngx_uint_t   ngx_process;

typedef char *(*cmd_set_pt)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
typedef ngx_int_t(*add_event_pt)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
typedef void(*channel_pt)(ngx_event_t *ev);


typedef struct  /* copy from ngx_http_upstream_keepalive_module */
{
    ngx_uint_t                         max_cached;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_upstream_keepalive_srv_conf_t;

typedef struct
{
    ngx_flag_t   upstreams_admin;
    //ngx_str_t  auth_basic;
    //ngx_str_t  auth_basic_user_file;

    ngx_array_t  upstreams;

    cmd_set_pt   original_iphash_cmd_set_handler;
    cmd_set_pt   original_keepalive_cmd_set_handler;
    cmd_set_pt   original_upstream_block_cmd_set_handler;
    add_event_pt original_add_event_handler;
    channel_pt   original_channel_handler;
} uc_main_conf_t;

typedef struct
{
    ngx_str_t                      host;
    ngx_uint_t                     ip_hash;
    ngx_uint_t                     keepalive;
    ngx_http_upstream_srv_conf_t   *upstream;

    ngx_array_t                    *uc_servers;  /* array member type is uc_server_t* */
} uc_srv_conf_t;

typedef struct
{
    ngx_http_upstream_server_t  *server;
    ngx_http_upstream_rr_peer_t *running_server;

    ngx_uint_t                  disable;
    ngx_uint_t                  rcount; /* request count */
} uc_server_t;


static char *uc_cmd_set_upstreams_admin_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t uc_module_preconf(ngx_conf_t *cf);
static uc_srv_conf_t *uc_get_srv_conf(uc_main_conf_t *ucmcf, ngx_str_t *host);
static ngx_int_t uc_module_init(ngx_cycle_t *cycle);
static char *uc_upstream_block_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *uc_iphash_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *uc_keepalive_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t uc_channel_add_event_hook_handler(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
static void uc_channel_handler(ngx_event_t *ev);
static void *uc_module_create_main_conf(ngx_conf_t *cf);
static void uc_sig_syn_handler(int signo);


static uc_main_conf_t *sucmcf = 0;

static ngx_command_t  ngx_http_upstream_ctl_commands[] =
{
    {
        ngx_string("upstreams_admin"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        uc_cmd_set_upstreams_admin_handler,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    /*
    { ngx_string("auth_basic"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_upstream_ctl_loc_conf_t, auth),
    NULL },

    { ngx_string("auth_basic_user_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_upstream_ctl_loc_conf_t, auth_file),
    NULL },
    */
    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ctl_module_ctx =
{
    uc_module_preconf,          /* preconfiguration */
    NULL,                       /* postconfiguration */

    uc_module_create_main_conf, /* create main configuration */
    NULL,                       /* init main configuration */

    NULL,                       /* create server configuration */
    NULL,                       /* merge server configuration */

    NULL,                       /* create location configuration */
    NULL                        /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_ctl_module =
{
    NGX_MODULE_V1,
    &ngx_http_upstream_ctl_module_ctx, /* module context */
    ngx_http_upstream_ctl_commands,    /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    uc_module_init,                    /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
uc_request_handler(ngx_http_request_t *r)
{
    ngx_chain_t                     out;
    ngx_int_t                       rc;
    ngx_buf_t                       *b;
    ngx_uint_t                      i, m;
    ngx_uint_t                      uilen;

    ngx_http_upstream_srv_conf_t    *uscf;
    uc_main_conf_t                  *ucmcf;
    uc_srv_conf_t                   *ucscf, **ucscfp;
    ngx_http_upstream_server_t      *usrv;


    char testui[UC_MAX_RESPONSE_SIZE] = "This is a test with data.<br>\r\n";
    char tmpbuf[TEMPLATE_BUFFER_SIZE];
    m = 0;
    memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);

    if (r->method & NGX_HTTP_POST)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "uc_request_handler() == process user upstream control request. this is a post request.");
        r->discard_body = 1;
    }
    else
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "uc_request_handler() == process user upstream control request. this is a get request.");

    }

    ucmcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_ctl_module);
    ucscfp = ucmcf->upstreams.elts;

    for (i = 0; i < ucmcf->upstreams.nelts; i++)
    {

        ucscf = ucscfp[i];
        uscf = ucscf->upstream;
        strcat(testui, (const char *)"<form method='post' name='");
        strncat(testui, (const char *)uscf->host.data, uscf->host.len);
        strcat(testui, (const char *)"' action='/upstreams' >");
        strcat(testui, (const char *)"<fieldset><legend>");
        strncat(testui, (const char *)uscf->host.data, uscf->host.len);
        strcat(testui, (const char *)"</legend>");
        strcat(testui, (const char *)"<input type='checkbox' name='iphash' value='1' ");
        if (ucscf->ip_hash)
        {
            strcat(testui, (const char *)"checked='checked'");
        }
        strcat(testui, (const char *)" /> ip_hash");


        strcat(testui, (const char *)"keepalive:<select name='keepalive'>");
        for (m = 0; m < 10; m++)
        {
            strcat(testui, (const char *)"<option value='");
            memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);
            sprintf(tmpbuf, "%d", m);
            strncat(testui, (const char *)tmpbuf, strlen(tmpbuf));
            if (ucscf->keepalive == m)
            {
                strcat(testui, (const char *)"' selected='selected'>");
            }
            else
            {
                strcat(testui, (const char *)"'>");
            }
            strncat(testui, (const char *)tmpbuf, strlen(tmpbuf));
            strcat(testui, (const char *)"</option>");

        }
        strcat(testui, (const char *)"</select>");
        strcat(testui, (const char *)"<input name='submit_");
        strncat(testui, (const char *)uscf->host.data, uscf->host.len);
        strcat(testui, (const char *)"' type='submit' value='update'></input><br><table border='1'><tr><th>Server</th><th>Weight</th><th>Backup</th><th>max_fails</th><th>fail_timeout</th><th>Status</th><th>Requests</th><th>Operations</th></tr>");
        usrv = uscf->servers->elts;
        for (m = 0; m < uscf->servers->nelts; m++, usrv++)
        {
            strcat(testui, (const char *)"<tr>");
            strcat(testui, (const char *)"<td>");
            strncat(testui, (const char *)usrv->name.data, usrv->name.len);
            strcat(testui, (const char *)"</td><td>");
            memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);
            sprintf(tmpbuf, "%d ", usrv->weight);
            strncat(testui, (const char *)tmpbuf, strlen(tmpbuf));
            strcat(testui, (const char *)"</td><td>");
            //backup
            if (usrv->backup)
            {
                strncat(testui, (const char *)"Yes", 3);
            }
            else
            {
                strncat(testui, (const char *)"No", 2);
            }
            strcat(testui, (const char *)"</td><td>");
            memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);
            sprintf(tmpbuf, "%d ", usrv->max_fails);
            strncat(testui, (const char *)tmpbuf, strlen(tmpbuf));
            strcat(testui, (const char *)"</td><td>");
            memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);
            sprintf(tmpbuf, "%d ", (int)usrv->fail_timeout);
            strncat(testui, (const char *)tmpbuf, strlen(tmpbuf));
            strcat(testui, (const char *)"</td><td>");
            //down
            if (usrv->down)
            {
                strncat(testui, (const char *)"Down", 4);
            }
            else
            {
                strncat(testui, (const char *)"Normal", 6);
            }
            strcat(testui, (const char *)"</td><td>");

            strcat(testui, (const char *)"</td><td>");
            strcat(testui, (const char *)"<a>edit</a><a>disable</a>");
            strcat(testui, (const char *)"</td>");
            strcat(testui, (const char *)"</tr>");
        }
        strcat(testui, (const char *)"</table></fieldset></form>");
    }


    uilen = strlen(testui);
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = uilen;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";

    rc = ngx_http_send_header(r);

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u_char *ui = ngx_palloc(r->pool, uilen);
    if (ui == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for ui.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ui, testui, uilen);

    b->pos = ui;
    b->last = ui + uilen;
    b->memory = 1;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    if (r->method & NGX_HTTP_POST)
    {

        //TEST
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "uc_request_handler() == send sig SIG_UPSTREAM_SYN to master process.");
        if (kill(getppid(), SIG_UPSTREAM_SYN))
        {

            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "Failed to send upstream conf update sig %s", strerror(errno));
        }
    }

    return ngx_http_output_filter(r, &out);
}


static char *
uc_cmd_set_upstreams_admin_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    uc_main_conf_t *ucmcf;
    ngx_str_t  *value;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_cmd_set_upstreams_admin_handler() == parse upstream_admin cmd and decide if install upstream control request handler.");

    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = uc_request_handler;

    value = cf->args->elts;    //ex:upstreams_admin on

    if (ngx_strcmp(value[1].data, "off") == 0)
    {
        ucmcf->upstreams_admin = UPSTREAM_CTL_ADM_OFF;
        return NGX_CONF_OK;
    }
    else if (ngx_strcmp(value[1].data, "on") == 0)
    {
        ucmcf->upstreams_admin = UPSTREAM_CTL_ADM_ON;
        return NGX_CONF_OK;
    }
    else
    {
        ucmcf->upstreams_admin = UPSTREAM_CTL_ADM_OFF;
        return NGX_CONF_OK;
    }

    return "can not be here.";
}



static ngx_int_t
uc_module_preconf(ngx_conf_t *cf)
{
    ngx_command_t *cmd;
    uc_main_conf_t  *ucmcf;

    if(ngx_process == NGX_PROCESS_SIGNALLER)
    {
        return 0;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_module_preconf() == install hook to iphash cmd set handler and keepalive cmd set handler.");
    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);

    cmd = ngx_http_upstream_module.commands;
    if ((cmd) && (ngx_strncmp("upstream", cmd->name.data, cmd->name.len) == 0))
    {
        if(uc_upstream_block_hook_handler != cmd->set)
        {
            ucmcf->original_upstream_block_cmd_set_handler = cmd->set;
            cmd->set = uc_upstream_block_hook_handler;
        }
    }

    cmd = ngx_http_upstream_ip_hash_module.commands;
    if ((cmd) && (ngx_strncmp("ip_hash", cmd->name.data, cmd->name.len) == 0))
    {
        if(uc_iphash_hook_handler != cmd->set)
        {
            ucmcf->original_iphash_cmd_set_handler = cmd->set;
            cmd->set = uc_iphash_hook_handler;
        }
    }

    cmd = ngx_http_upstream_keepalive_module.commands;
    if ((cmd) && (ngx_strncmp("keepalive", cmd->name.data, cmd->name.len) == 0))
    {
        if(uc_keepalive_hook_handler != cmd->set)
        {
            ucmcf->original_keepalive_cmd_set_handler = cmd->set;
            cmd->set = uc_keepalive_hook_handler;
        }
    }

    return 0;
}


static char *
uc_upstream_block_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    uc_main_conf_t  *ucmcf;
    uc_srv_conf_t *ucscf, **ucscfp;
    ngx_http_upstream_main_conf_t    *umcf;
    ngx_http_upstream_srv_conf_t *uscf, **uscfp;
    ngx_str_t                     *value;
    ngx_uint_t i;
    char *rc;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_upstream_block_hook_handler() == create ctl module server conf and make one to one correspondence with upstream server conf.");
    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);
    ucscf = ngx_pcalloc(cf->pool, sizeof(uc_srv_conf_t));
    value = cf->args->elts;
    ucscf->host = value[1];
    ucscfp = ngx_array_push(&ucmcf->upstreams);
    *ucscfp = ucscf;
    if (ucmcf->original_upstream_block_cmd_set_handler)
    {
        rc = ucmcf->original_upstream_block_cmd_set_handler(cf, cmd, conf);
        if (rc == NGX_CONF_OK)
        {
            umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
            uscfp = umcf->upstreams.elts;
            for (i = 0; i < umcf->upstreams.nelts; i++)
            {
                uscf = uscfp[i];
                if ((uscf->host.len == ucscf->host.len)
                        && (ngx_strncasecmp(uscf->host.data, ucscf->host.data, ucscf->host.len) == 0))
                {
                    ucscf->upstream = uscf;
                    break;
                }
            }
        }
        return rc;

    }
    else
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_ERROR;

}

static uc_srv_conf_t *
uc_get_srv_conf(uc_main_conf_t *ucmcf, ngx_str_t *host)
{
    uc_srv_conf_t *ucscf, **ucscfp;
    ngx_uint_t i;

    ucscfp = ucmcf->upstreams.elts;
    for (i = 0; i < ucmcf->upstreams.nelts; i++)
    {
        ucscf = ucscfp[i];
        if ((ucscf->host.len == host->len)
                && (ngx_strncasecmp(ucscf->host.data, host->data, host->len) == 0))
        {
            return ucscf;
        }
    }
    return NULL;
}

static char *
uc_iphash_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    uc_main_conf_t  *ucmcf;
    uc_srv_conf_t *ucscf;
    ngx_http_upstream_srv_conf_t *uscf;
    char *rc;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_iphash_hook_handler() == get ip_hash conf value and save it to ctl module server conf.");
    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ucscf = uc_get_srv_conf(ucmcf, &uscf->host);

    if (ucscf == NULL)
    {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Not found upstream control service configuration.");
        return NGX_CONF_ERROR;
    }

    if (ucmcf->original_iphash_cmd_set_handler)
    {
        rc = ucmcf->original_iphash_cmd_set_handler(cf, cmd, conf);
        if (rc == NGX_CONF_OK)
        {
            ucscf->ip_hash = 1;
        }
        else
        {
            ucscf->ip_hash = 0;
        }
    }
    else
    {
        ucscf->ip_hash = 0;
    }
    return NGX_CONF_OK;

}

static char *
uc_keepalive_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    uc_main_conf_t *ucmcf;
    uc_srv_conf_t *ucscf;
    ngx_http_upstream_srv_conf_t *uscf;
    ngx_http_upstream_keepalive_srv_conf_t *ukscf;
    char *rc;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_keepalive_hook_handler() == get keepalive conf value and save it to ctl module server conf.");

    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ucscf = uc_get_srv_conf(ucmcf, &uscf->host);
    if (ucscf == NULL)
    {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Not found upstream control service configuration.");
        return NGX_CONF_ERROR;
    }

    if (ucmcf->original_keepalive_cmd_set_handler)
    {
        rc = ucmcf->original_keepalive_cmd_set_handler(cf, cmd, conf);
        if (rc == NGX_CONF_OK)
        {
            ukscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_keepalive_module);
            ucscf->keepalive = ukscf->max_cached;
        }
        else
        {
            ucscf->keepalive = 0;
        }
    }
    else
    {
        ucscf->keepalive = 0;
    }

    return NGX_CONF_OK;
}

static void *
uc_module_create_main_conf(ngx_conf_t *cf)
{
    uc_main_conf_t  *ucmcf;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_module_create_main_conf() == create upstream control moudle main conf.");
    ucmcf = ngx_pcalloc(cf->pool, sizeof(uc_main_conf_t));
    if (ucmcf == NULL)
    {
        return NULL;
    }

    if (ngx_array_init(&ucmcf->upstreams, cf->pool, 4,
                       sizeof(uc_srv_conf_t *))
            != NGX_OK)
    {
        return NULL;
    }

    if(sucmcf)
    {
        ucmcf->original_iphash_cmd_set_handler = sucmcf->original_iphash_cmd_set_handler;
        ucmcf->original_keepalive_cmd_set_handler = sucmcf->original_keepalive_cmd_set_handler;
        ucmcf->original_upstream_block_cmd_set_handler = sucmcf->original_upstream_block_cmd_set_handler;
        ucmcf->original_add_event_handler = sucmcf->original_add_event_handler;
        ucmcf->original_channel_handler = sucmcf->original_channel_handler;
    }
    sucmcf = ucmcf;
    return ucmcf;
}

static ngx_int_t
uc_module_init(ngx_cycle_t *cycle)
{
    void              ***cf;
    ngx_event_conf_t    *ecf;
    ngx_core_conf_t   *ccf;
    ngx_uint_t i;
    ngx_event_module_t   *m;
    uc_main_conf_t    *ucmcf;

    if(ngx_process == NGX_PROCESS_SIGNALLER)
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "uc_module_init() == 1.install channel add event hook to event module for adding myself channel handler. 2.install sig handler.");
    cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);
    ecf = (*cf)[ngx_event_core_module.ctx_index];

    ucmcf = sucmcf;

    for (i = 0; ngx_modules[i]; i++)
    {
        if (ngx_modules[i]->type != NGX_EVENT_MODULE)
        {
            continue;
        }
        if (ngx_modules[i]->ctx_index == ecf->use)
        {
            m = ngx_modules[i]->ctx;

            if(uc_channel_add_event_hook_handler != m->actions.add)
            {
                ucmcf->original_add_event_handler = m->actions.add;
                m->actions.add = uc_channel_add_event_hook_handler;
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                              "uc_module_init() == success to set uc_channel_add_event_hook_handler:%d", (int)m->actions.add);
            }
            break;

        }
    }

    struct sigaction sa;

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_handler = uc_sig_syn_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIG_UPSTREAM_SYN, &sa, NULL) == -1)
    {
#if (NGX_VALGRIND)
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigaction(SIG_UPSTREAM_SYN) failed, ignored");
#else
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigaction(SIG_UPSTREAM_SYN) failed");
        return NGX_ERROR;
#endif
    }


    ccf = (ngx_core_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (geteuid() == 0)
    {

        ccf->group = getgid();
        ccf->user = getuid();
        struct passwd *passwd;
        passwd = getpwuid(ccf->user);
        ccf->username = passwd->pw_name;
    }

    return NGX_OK;
}
static ngx_int_t
uc_channel_add_event_hook_handler(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    uc_main_conf_t  *ucmcf;

    ucmcf = sucmcf;

    if ((ev->channel == 1)
            && (event == NGX_READ_EVENT)
            && (ev->handler))
    {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "uc_channel_add_event_hook_handler() == install myself channel handler:uc_channel_handler.");
        if(uc_channel_handler != ev->handler)
        {
            ucmcf->original_channel_handler = ev->handler;
            ev->handler = uc_channel_handler;
        }
        if (ucmcf->original_add_event_handler)
        {
            return ucmcf->original_add_event_handler(ev, event, flags);
        }
    }

    if (ucmcf->original_add_event_handler)
    {
        return ucmcf->original_add_event_handler(ev, event, flags);
    }

    return 0;

}
static void
uc_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout)
    {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "channel handler");

    for (;; )
    {

        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NGX_ERROR)
        {

            if (ngx_event_flags & NGX_USE_EPOLL_EVENT)
            {
                ngx_del_conn(c, 0);
            }

            ngx_close_connection(c);
            return;
        }

        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT)
        {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR)
            {
                return;
            }
        }

        if (n == NGX_AGAIN)
        {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %d", ch.command);

        switch (ch.command)
        {

        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;

        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;

        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        case NGX_CMD_OPEN_CHANNEL:

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;

        case NGX_CMD_CLOSE_CHANNEL:

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                           ngx_processes[ch.slot].channel[0]);

            if (close(ngx_processes[ch.slot].channel[0]) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "close() channel failed");
            }

            ngx_processes[ch.slot].channel[0] = -1;
            break;
        case CHANNEL_CMD_UPSTREAM_SYN:    //
            ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "uc_channel_handler() == receive CHANNEL_CMD_UPSTREAM_SYN and download new conf from share memory zone and apply it.");

            break;
        }
    }

    //ucmcf->original_channel_handler(ev);
}

static void
uc_sig_syn_handler(int signo)
{
    ngx_int_t      i;
    ngx_channel_t  ch;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "uc_channel_handler() == receive SIG_UPSTREAM_SYN sig and write channel cmd CHANNEL_CMD_UPSTREAM_SYN to all child worker(exept of current worker)");

    ngx_memzero(&ch, sizeof(ngx_channel_t));
    ch.command = CHANNEL_CMD_UPSTREAM_SYN;
    ch.fd = -1;

    for (i = 0; i < ngx_last_process; i++)
    {



        if (ngx_processes[i].detached || ngx_processes[i].pid == -1)
        {
            continue;
        }

        if (ngx_processes[i].just_spawn)
        {
            ngx_processes[i].just_spawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting)
        {
            continue;
        }

        if (ngx_write_channel(ngx_processes[i].channel[0], &ch, sizeof(ngx_channel_t), ngx_cycle->log)
                != NGX_OK)
        {

            ngx_log_debug8(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                           "Failed to write channel for update upstream. child: %d %P e:%d t:%d d:%d r:%d j:%d   err:%s",
                           i,
                           ngx_processes[i].pid,
                           ngx_processes[i].exiting,
                           ngx_processes[i].exited,
                           ngx_processes[i].detached,
                           ngx_processes[i].respawn,
                           ngx_processes[i].just_spawn,
                           strerror(errno));
        }
    }
    return;
}

