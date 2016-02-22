/*
* Copyright (C) dss_liuhl
*     QQ:1610153337
*     email:15817409379@163.com
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_channel.h>

/////////////// macro defines ////////////////////////////////

//signal define
#define SIG_UPSTREAM_SYN                  36
#define SIG_UPSTREAM_SYN_ACK              39
#define SIG_UPSTREAM_REQUEST_COUNT_REPORT 40

//channel command define
#define CHANNEL_CMD_UPSTREAM_SYN          1024
#define CHANNEL_CMD_UPSTREAM_FINALIZE_REQ 1025

//module command value define
#define UPSTREAM_CTL_ADM_OFF              0
#define UPSTREAM_CTL_ADM_ON               1
//temporay buffer size
#define TEMPLATE_BUFFER_SIZE              8192
//html response content maxium length
#define UC_MAX_RESPONSE_SIZE              40000
//allocated share memory size
#define UC_SHZONE_PAGE_COUNT              9
//nginx upstream configuration specifacation
#define UC_MAX_GROUPSRV_NUMBER            10000
#define UC_MAX_GROUP_NUMBER               1000
//request count
#define UC_RCOUNT_KEY_ARRAY_INIT_SIZE     5
//synchronous wait outtime
#define UC_WAIT_OUTTIME                   3000
//apply configuration time span
#define UC_APPCONF_TIMESPAN               50

//user interface response flag
#define UI_STATUS_GET                     0
#define UI_STATUS_POST_OK                 1
#define UI_STATUS_POST_TIMEOUT            2
#define UI_STATUS_POST_SRV_ERR            3
#define UI_STATUS_POST_SRV_BUSY           4
#define UI_STATUS_POST_SRV_ZERO           5

#ifndef NGX_RWLOCK_WLOCK
#define NGX_RWLOCK_WLOCK  ((ngx_atomic_uint_t) -1)
#endif

#ifndef NGX_RWLOCK_SPIN
#define NGX_RWLOCK_SPIN   2048
#endif

#define uc_trylock(lock)  (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK))
#define uc_unlock(lock)   *(lock) = 0

#define uc_get_display_color(item) ((last_post && (last_post->server.item != usrv->item)) ? "red" : "green")
#define uc_get_display_value(item) ((last_post) ? last_post->server.item : usrv->item)
#define uc_get_display_string(item) ((last_post) ? &uc_##item[last_post->server.item] : &uc_##item[usrv->item])

///////////////// type defines ////////////////////////////////////////////

typedef char *(*cmd_set_pt)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
typedef ngx_int_t(*add_event_pt)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
typedef void(*channel_pt)(ngx_event_t *ev);
typedef void(*finalize_request_pt)(ngx_http_request_t *r, ngx_int_t rc);
typedef void(*sigchld_pt)(int signo);

typedef struct   /* copy from ngx_process.c */
{
    int     signo;
    char    *signame;
    char    *name;
    void    (*handler)(int signo);
    
} ngx_signal_t;

typedef struct  /* copy from ngx_http_upstream_keepalive_module */
{
    ngx_uint_t                         max_cached;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_upstream_keepalive_srv_conf_t;


typedef struct  /* copy from ngx_http_upstream_keepalive_module */
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                             queue;
    ngx_connection_t                        *connection;

    socklen_t                               socklen;
    u_char                                  sockaddr[NGX_SOCKADDRLEN];

} ngx_http_upstream_keepalive_cache_t;

typedef struct
{
    ngx_http_upstream_server_t  *server;
    ngx_http_upstream_rr_peer_t **running_server;

} uc_server_t;

typedef struct
{
    ngx_flag_t         upstreams_admin;

    ngx_array_t        upstreams;/* array member type is uc_srv_conf_t * */

    cmd_set_pt         original_iphash_cmd_set_handler;
    cmd_set_pt         original_keepalive_cmd_set_handler;
    cmd_set_pt         original_upstream_block_cmd_set_handler;
    add_event_pt       original_add_event_handler;
    channel_pt         original_channel_handler;
    sigchld_pt         original_sigchld_handler;

    ngx_http_upstream_init_peer_pt original_init_keepalive_peer;//ngx_http_upstream_keepalive_module 's peer init function pointer
    ngx_http_upstream_init_peer_pt original_init_iphash_peer;   //ngx_http_upstream_iphash_module 's peer init function pointer

    ngx_array_t        *syn_key;  /* array member type is uc_syn_key_t */
    ngx_queue_t        syn_queue;

    ngx_event_t        *timeout_ev;

    ngx_array_t        *rcount_key; /* array member type is uc_rcount_key_t */
    ngx_queue_t        rcount_use_queue;
    ngx_queue_t        rcount_free_queue;

    ngx_slab_pool_t    *shpool;
    ngx_shm_zone_t     *shm_zone;

} uc_main_conf_t;

typedef struct
{
    ngx_http_upstream_server_t     server;
    ngx_uint_t                     rcount;      /* request count */
    ngx_atomic_t                   rcount_lock;

} uc_sh_server_t;

typedef struct
{
    ngx_atomic_t                   conf_lock;
    ngx_str_t                      host;
    ngx_uint_t                     ip_hash;
    ngx_uint_t                     keepalive;
    uc_sh_server_t                 *server;
    ngx_uint_t                     num;//server count

} uc_sh_conf_t;

typedef struct
{
    ngx_str_t                              host;
    ngx_uint_t                             ip_hash;
    ngx_uint_t                             keepalive;
    ngx_http_upstream_srv_conf_t           *upstream;                 /* point to original upstream server configuration */

    ngx_array_t                            *uc_servers;               /* array member type is uc_server_t */
    ngx_http_upstream_init_peer_pt         original_peer_init_handler;
    ngx_http_upstream_keepalive_srv_conf_t *kcf;
    ngx_array_t                            *added_caches;             /* array member type is ngx_http_upstream_keepalive_cache_t */
    ngx_array_t                            *cache_status;             /* array member type is uc_cache_status_t */
    ngx_queue_t                            free_caches;

    uc_sh_conf_t                           *temp_conf;                /* the temporary conf for syn */

    ngx_atomic_t                           apply_lock;                /* secure access for apply new conf */
    ngx_uint_t                             apply_lock_tries;          /* apply lock lazy read control */

    ngx_event_t                            *apply_ev;

} uc_srv_conf_t;

typedef struct
{
    uc_srv_conf_t *ucscf;
    ngx_uint_t    confidx;
    ngx_int_t     post_id;
    ngx_socket_t  fd;      //take place

} uc_event_data_t;


typedef struct
{
    ngx_int_t            post_id;
    ngx_int_t            status_code;
    ngx_pid_t            post_pid;                 //the worker process that is performing current upstream control request
    ngx_http_request_t   *r;
    ngx_uint_t           syn_conf;                 //syn confidx

} uc_post_status_t;

typedef struct /* used to share memory zone */
{
    ngx_atomic_t                   post_lock;      //post request process lock

    uc_post_status_t               post_status;
    ngx_atomic_t                   status_lock;

    ngx_uint_t                     number;
    uc_sh_conf_t                   *conf;

    ngx_atomic_t                   time_lock;       /* secure access to last_update */
    ngx_msec_t                     last_update;     /*last_update time */

} uc_sh_t;


typedef struct
{
    ngx_pid_t                      pid;
    ngx_queue_t                    queue;

} uc_syn_key_t;

typedef struct
{
    ngx_uint_t                     conf;           /* uc conf index */
    uc_srv_conf_t                  *ucscf;
    ngx_http_request_t             *r;
    finalize_request_pt            original_finalize_request_handler;
    ngx_queue_t                    queue;

} uc_rcount_key_t;

typedef struct uc_node_s
{
    char               *name;
    char               *value;
    struct uc_node_s   *next;

} uc_node_t;

////////////////// function declares /////////////////////////

//command set functions
static char *uc_cmd_set_upstreams_admin_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

//nginx custome functions
static ngx_int_t uc_module_preconf(ngx_conf_t *cf);
static ngx_int_t uc_module_postconf(ngx_conf_t *cf);
static ngx_int_t uc_module_init(ngx_cycle_t *cycle);
static void *uc_module_create_main_conf(ngx_conf_t *cf);

//hook functions
static char *uc_upstream_block_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *uc_iphash_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *uc_keepalive_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t uc_channel_add_event_hook_handler(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
static ngx_int_t uc_request_count_hook_handler(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);

//share memory functions
static char *uc_reg_shzone(ngx_conf_t *cf, uc_main_conf_t *ucmcf);
static ngx_int_t uc_init_shzone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t uc_download_data_from_shzone(ngx_uint_t confidx);
static ngx_int_t uc_upload_data_to_shzone(uc_sh_conf_t *conf);

//synchronous functions
static void uc_channel_handler(ngx_event_t *ev);
static void uc_sig_syn_handler(int signo, siginfo_t *sig_info, void *unused);
static void uc_sig_syn_ack_handler(int signo, siginfo_t *sig_info, void *unused);
static void uc_sigchld_handler(int signo);
static ngx_int_t uc_apply_new_conf(ngx_uint_t confidx, ngx_log_t *log);
static ngx_int_t uc_backup_peers_switch(ngx_http_upstream_server_t *xserver, ngx_http_upstream_rr_peer_t **xpeerp, ngx_http_upstream_rr_peers_t *peers, ngx_pool_t *pool);
static void uc_reset_peers_data(uc_srv_conf_t *ucscf);
static void uc_apply_conf_post_handler(ngx_event_t *ev);
static void uc_post_timeout_event_handler(ngx_event_t *ev);
static void uc_reset_keepalive_cache(ngx_uint_t new_keepalive, uc_srv_conf_t *ucscf, ngx_log_t *log);
static void uc_reset_peer_init_handler(ngx_uint_t ip_hash, ngx_uint_t keepalive, uc_srv_conf_t *ucscf);
static void uc_syn_init(ngx_int_t post_id, ngx_uint_t confidx, ngx_http_request_t *r);
static void uc_send_finalize_req_channel_cmd(ngx_int_t post_id);
static ngx_int_t uc_apply_lock_trylock(ngx_atomic_t *lock, ngx_uint_t *tries);
static void uc_apply_lock_rlock(ngx_atomic_t *lock, ngx_uint_t *tries);
static void uc_apply_lock_unlock(ngx_atomic_t *lock, ngx_uint_t *tries);
static ngx_int_t uc_post_status_is_valid(ngx_int_t post_id, uc_post_status_t *post_status);
static void uc_finalize_post_request(ngx_http_request_t *r, ngx_int_t rc);
static void uc_set_post_status_code(ngx_int_t code);
static void uc_get_post_status(uc_post_status_t *post_status);
static ngx_int_t uc_new_post_id();
static ngx_pid_t uc_get_post_process();
static ngx_atomic_t *uc_get_post_lock();
static ngx_uint_t uc_get_syn_conf();

//request count functions
static void uc_sig_rcount_write_handler(int signo, siginfo_t *sig_info, void *unused);
static void uc_sig_rcount_rpt_handler(ngx_http_request_t *r, ngx_int_t rc);
static ngx_uint_t uc_get_rcount(ngx_uint_t group, ngx_uint_t server);

//http content handlers
static void uc_post_request_handler(ngx_http_request_t *r);
static ngx_int_t uc_request_handler(ngx_http_request_t *r);

//script output functions
static ngx_int_t uc_output_ui(ngx_http_request_t *r, ngx_int_t days, uc_sh_conf_t *last_post, ngx_uint_t flag);
static void uc_output_server(char **pui, ngx_http_upstream_srv_conf_t *uscf, ngx_http_upstream_server_t *usrv, ngx_uint_t index, ngx_uint_t groupindex, uc_sh_server_t *last_post);
static void uc_output_group(char **pui, ngx_http_upstream_srv_conf_t *uscf, uc_srv_conf_t *ucscf, ngx_uint_t groupindex, uc_sh_conf_t *last_post, ngx_uint_t flag);
static void uc_output_editdlg(char **pui);
static ngx_uint_t uc_get_ui_status_flag(ngx_uint_t confidx, ngx_uint_t flag);

//script parse functions
static ngx_int_t uc_parse_post_para(ngx_chain_t *postbufs, ngx_pool_t *pool, uc_sh_conf_t **confp);
static ngx_int_t uc_para_assign(uc_sh_conf_t *conf, char *name, ngx_uint_t *index, char *value, ngx_pool_t *pool);
static char uc_hex_trans(char ch);
static int uc_cmp_name_key(char *name, char *key);
static char *uc_parse_conf_name(char *name);

//time functions
static ngx_msec_t uc_get_last_update();
static void uc_set_last_update();
static ngx_int_t uc_get_update_days();

//utils functions
static uc_srv_conf_t *uc_get_srv_conf_byhost(uc_main_conf_t *ucmcf, ngx_str_t *host);
static uc_srv_conf_t *uc_get_srv_conf_byidx(ngx_uint_t confidx);
static ngx_int_t uc_get_srv_conf_index(uc_main_conf_t *ucmcf, ngx_str_t *host);
static ngx_int_t uc_get_peer_srv_index(ngx_uint_t conf, ngx_str_t *peer);
static ngx_uint_t uc_queue_move(ngx_queue_t *from, ngx_queue_t *to, ngx_uint_t number);


///////////////////// gloabal variables /////////////////////////////////////

extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_upstream_keepalive_module;
extern ngx_uint_t    ngx_process;
extern ngx_queue_t   ngx_posted_events;
extern ngx_signal_t  signals[];

static ngx_str_t uc_backup[] = {ngx_string("No"), ngx_string("Yes")};
static ngx_str_t uc_down[] = {ngx_string("Normal"), ngx_string("Down")};
static ngx_str_t uc_enable[] = {ngx_string("disable"), ngx_string("enable")};
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
    ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ctl_module_ctx =
{
    uc_module_preconf,          /* preconfiguration */
    uc_module_postconf,         /* postconfiguration */

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


//////////////////// function defines ///////////////////////////////////////////////

/*
 * function: uc apply lock 's try lock. a lock try will not wait and return immediatly.
 * 1.this is a lazy read lock. a new read will wait after a write try.
 * 2.this is a local lock. it only work within a process
 */
static ngx_int_t
uc_apply_lock_trylock( ngx_atomic_t *lock, ngx_uint_t *tries)
{

    if (*(lock) == 0 && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK))
    {
        *tries = 0;
        return 1;
    }
    else
    {
        (*tries)++;
        return 0;
    }
}

/*
 * function: uc apply lock 's read lock.
 */
static void
uc_apply_lock_rlock(ngx_atomic_t *lock, ngx_uint_t *tries)
{
    ngx_uint_t         i, n;
    ngx_atomic_uint_t  readers;

    for ( ;; )
    {
        readers = *lock;

        if (readers != NGX_RWLOCK_WLOCK
                && (*tries) == 0
                && ngx_atomic_cmp_set(lock, readers, readers + 1))
        {
            return;
        }

        if (ngx_ncpu > 1)
        {

            for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1)
            {

                for (i = 0; i < n; i++)
                {
                    ngx_cpu_pause();
                }

                readers = *lock;

                if (readers != NGX_RWLOCK_WLOCK
                        && (*tries) == 0
                        && ngx_atomic_cmp_set(lock, readers, readers + 1))
                {
                    return;
                }
            }
        }

        ngx_sched_yield();
    }
}

static void
uc_apply_lock_unlock(ngx_atomic_t *lock, ngx_uint_t *tries)
{
    ngx_atomic_uint_t  readers;

    readers = *lock;

    if (readers == NGX_RWLOCK_WLOCK)
    {
        *lock = 0;
        *tries = 0;
        return;
    }

    for ( ;; )
    {

        if (ngx_atomic_cmp_set(lock, readers, readers - 1))
        {
            return;
        }

        readers = *lock;
    }
}

/*
 * function: output a upstream server row in html script
 * note: display color is green when post is equal to real value or that is red
 */
static void
uc_output_server(char **pui, ngx_http_upstream_srv_conf_t *uscf, ngx_http_upstream_server_t *usrv, ngx_uint_t index, ngx_uint_t groupindex, uc_sh_server_t *last_post)
{
    char *testui;
    char tmpbuf[TEMPLATE_BUFFER_SIZE];

    memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);
    testui = *pui;

    ngx_sprintf((u_char *)tmpbuf,
                "<tr>"\
                "<td class='editable'>"\
                "<span>%V</span>"\
                "<input type='hidden' value='%V' name='post[%V][server][%ui][name]' id= 'post[%V][server][%ui][name]'/>"\
                "</td>"\
                "<td align='center' class='editable'>"\
                "<span run='%ui' style='color:%s'>%ui</span>"\
                "<input type='hidden' value='%ui' name='post[%V][server][%ui][weight]' id= 'post[%V][server][%ui][weight]'/>"\
                "</td>"\
                "<td align='center' class='editable'>"\
                "<span run='%V' style='color:%s'>%V</span>"\
                "<input type='hidden' value='%V' name='post[%V][server][%ui][backup]' id= 'post[%V][server][%ui][backup]'/>"\
                "</td>"\
                "<td align='center' class='editable'>"\
                "<span run='%ui' style='color:%s'>%ui</span>"\
                "<input type='hidden' value='%ui' name='post[%V][server][%ui][max_fails]' id= 'post[%V][server][%ui][max_fails]'/>"\
                "</td>"\
                "<td align='center' class='editable'>"\
                "<span run='%T' style='color:%s'>%T</span>"\
                "<input type='hidden' value='%T' name='post[%V][server][%ui][fail_timeout]' id= 'post[%V][server][%ui][fail_timeout]'/>"\
                "</td>"\
                "<td align='center' class='editable status'>"\
                "<span run='%V' style='color:%s'>%V</span>"\
                "<input type='hidden' value='%V' name='post[%V][server][%ui][status]' id= 'post[%V][server][%ui][status]'/>"\
                "</td>"\
                "<td align='right'>"\
                "%ui"\
                "</td>"\
                "<td><a data-toggle='modal' data-target='#editdlg' data-whatever='post[%V][server][%ui]' style='cursor:pointer;'>edit</a> <a style='cursor:pointer;' class='switch-status'>%V</a></td>"\
                "</tr>",
                &usrv->name,
                &usrv->name,
                &uscf->host,
                index,
                &uscf->host,
                index,
                usrv->weight,
                uc_get_display_color(weight),
                uc_get_display_value(weight),
                uc_get_display_value(weight),
                &uscf->host,
                index,
                &uscf->host,
                index,
                &uc_backup[usrv->backup],
                uc_get_display_color(backup),
                uc_get_display_string(backup),
                uc_get_display_string(backup),
                &uscf->host,
                index,
                &uscf->host,
                index,
                usrv->max_fails,
                uc_get_display_color(max_fails),
                uc_get_display_value(max_fails),
                uc_get_display_value(max_fails),
                &uscf->host,
                index,
                &uscf->host,
                index,
                usrv->fail_timeout,
                uc_get_display_color(fail_timeout),
                uc_get_display_value(fail_timeout),
                uc_get_display_value(fail_timeout),
                &uscf->host,
                index,
                &uscf->host,
                index,
                &uc_down[usrv->down],
                uc_get_display_color(down),
                uc_get_display_string(down),
                uc_get_display_string(down),
                &uscf->host,
                index,
                &uscf->host,
                index,
                uc_get_rcount(groupindex, index),
                &uscf->host,
                index,
                &uc_enable[usrv->down]
               );
    strcat(testui, (const char *)tmpbuf);
}

/*
 * function: output a upstream servers group in html script
 */
static void
uc_output_group(char **pui, ngx_http_upstream_srv_conf_t *uscf, uc_srv_conf_t *ucscf, ngx_uint_t groupindex, uc_sh_conf_t *last_post, ngx_uint_t flag)
{
    char *testui;
    ngx_uint_t m;
    ngx_http_upstream_server_t      *usrv;
    ngx_str_t iphash_checked, keepalive_checked;
    u_char tmpbuf[TEMPLATE_BUFFER_SIZE];
    ngx_uint_t confidx, realflag;

    testui = *pui;
    memset(tmpbuf, 0, sizeof(tmpbuf));

    if (ucscf->ip_hash)
    {
        ngx_str_set(&iphash_checked, "checked='checked'");
    }
    else
    {
        ngx_str_set(&iphash_checked, "");
    }
    ngx_sprintf(tmpbuf,
                "<form class='form-inline' method='post' name='post[%V]' action='/upstreams'>"\
                "<fieldset>"\
                "<legend><h2>%V</h2></legend>"\
                "<div class='checkbox-inline'>"\
                "<label><input type='checkbox' id='post[%V][iphash]' name='post[%V][iphash]' value='1' %V />ip_hash</label>"\
                "</div>"\
                "<div class='form-group' style='margin-left:20px;'>"\
                "<label for='post[%V][keepalive]'>keepalive:</label>"\
                "<select id='post[%V][keepalive]' name='post[%V][keepalive]'>",            
                &uscf->host,
                &uscf->host,
                &uscf->host,
                &uscf->host,
                &iphash_checked,
                &uscf->host,
                &uscf->host,
                &uscf->host);
    strcat(testui, (const char *)tmpbuf);

    for (m = 0; m < 33; m++)
    {
        if (ucscf->keepalive == m)
        {
            ngx_str_set(&keepalive_checked, "selected='selected'");
        }
        else
        {
            ngx_str_set(&keepalive_checked, "");
        }
        memset(tmpbuf, 0, sizeof(tmpbuf));
        ngx_sprintf(tmpbuf, "<option value='%ui' %V>%ui</option>", m, &keepalive_checked, m);
        strcat(testui, (const char *)tmpbuf);
    }
    strcat(testui, (const char *)"</select></div>");

    memset(tmpbuf, 0, sizeof(tmpbuf));
    ngx_sprintf(tmpbuf,
                "<div class='form-group' style='margin-left:20px;'><label><input name='post[%V][submit]' type='submit' value='update'></input></label></div><br>", &uscf->host);
    strcat(testui, (const char *)tmpbuf);

    confidx = flag % UC_MAX_GROUP_NUMBER;
    realflag = flag / UC_MAX_GROUP_NUMBER;
    if(confidx == groupindex)
    {
        switch (realflag)
        {
        case UI_STATUS_GET:
            //strcat(testui, (const char *)"");
            break;
        case UI_STATUS_POST_OK:
            strcat(testui, (const char *)"<div class='alert alert-success' role='alert'>Update upstreams OK!</div>");
            break;
        case UI_STATUS_POST_TIMEOUT:
            strcat(testui, (const char *)"<div class='alert alert-warning' role='alert'>Update upstreams timeout.</div>");
            break;
        case UI_STATUS_POST_SRV_ERR:
            strcat(testui, (const char *)"<div class='alert alert-danger' role='alert'>An error occurs when update upstreams.</div>");
            break;
        case UI_STATUS_POST_SRV_BUSY:
            strcat(testui, (const char *)"<div class='alert alert-info' role='alert'>Server is busy, please wait for a moment and try again.</div>");
            break;
        case UI_STATUS_POST_SRV_ZERO:
            strcat(testui, (const char *)"<div class='alert alert-danger' role='alert'>No servers in this upstream (All is backup).</div>");
            break;
        default:
            strcat(testui, (const char *)"<div class='alert alert-danger' role='alert'>An unknown error occurs in server.</div>");

        }
    }
    strcat(testui, (const char *)"<table  style='margin-top:10px;' class='table table-striped table-bordered'>"\
           "<tr>"\
           "<th>Server</th>"\
           "<th align='center' style='text-align:center'>Weight</th>"\
           "<th align='center' style='text-align:center'>Backup</th>"\
           "<th align='center' style='text-align:center'>max_fails</th>"\
           "<th align='center' style='text-align:center'>fail_timeout</th>"\
           "<th align='center' style='text-align:center'>Status</th>"\
           "<th align='right' style='text-align:right'>Requests</th>"\
           "<th>Operations</th>"\
           "</tr>");

    usrv = uscf->servers->elts;
    for (m = 0; m < uscf->servers->nelts; m++, usrv++)
    {
        uc_output_server(pui, uscf, usrv, m, groupindex, ((last_post) ? &last_post->server[m] : 0));
    }
    strcat(testui, (const char *)"</table></fieldset></form>");
}

/*
 * function:output response content of html script
 */
static ngx_int_t
uc_output_ui(ngx_http_request_t *r, ngx_int_t days, uc_sh_conf_t *last_post, ngx_uint_t flag)
{
    ngx_chain_t                     out;
    ngx_buf_t                       *b;
    ngx_uint_t                      i;
    ngx_uint_t                      uilen;
    ngx_http_upstream_srv_conf_t    *uscf;
    uc_main_conf_t                  *ucmcf;
    uc_srv_conf_t                   *ucscf, **ucscfp;
    char *p, **pui;

    char testui[UC_MAX_RESPONSE_SIZE];

    memset(testui, 0, sizeof(testui));
    p = &testui[0];
    pui = &p;
    char tmpbuf[TEMPLATE_BUFFER_SIZE];
    memset(tmpbuf, 0, sizeof(char)*TEMPLATE_BUFFER_SIZE);

    strcat(testui, (const char *)"<!DOCTYPE html><html lang='zh-CN'>"\
           "<head>"\
           "<meta charset='utf-8'>"\
           "<meta http-equiv='X-UA-Compatible' content='IE=edge'>"\
           "<meta name='viewport' content='width=device-width, initial-scale=1'>"\
           "<meta http-equiv='content-type' content='text/html; charset=UTF-8'>"\
           "<meta name='keywords' content='Nginx, Upstreams, Control, Nginx module' />"\
           "<meta name='description' content='Nginx Upstreams Control' />"\
           "<meta name='author' content='dss_liuhl(QQ:1610153337 email:15817409379@163.com)' />"\
           "<title>Nginx Upstreams</title>"\
           "<script>"\
           "window.jQuery || document.write(\'<script src=\"/jquery.min.js\"><\\/script>\');"\
           "</script>"\
           "<script src='/bootstrap/js/bootstrap.min.js'></script>"\
           "<link type='text/css' href='/bootstrap/css/bootstrap.min.css' rel='stylesheet'>"\
           "</head>"\
           "<body>"\
           "<div style='padding:20px;'>");


    ucmcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_ctl_module);
    ucscfp = ucmcf->upstreams.elts;

    memset(tmpbuf, 0, sizeof(char) * 3);
    ngx_sprintf((u_char *)tmpbuf, "<h1>Nginx Upstreams(%ui)</h1><label>Uptime: %d days</label>", ucmcf->upstreams.nelts, days);
    strncat(testui, (const char *)tmpbuf, strlen(tmpbuf));

    if((ngx_int_t)last_post == -1)
    {
        strcat(testui, (const char *)"<div class='alert alert-info' role='alert'>The post page has just expired. Please try again.</div>");
        last_post = 0;
    }

    uc_sh_conf_t *lpost;
    for (i = 0; i < ucmcf->upstreams.nelts; i++)
    {

        ucscf = ucscfp[i];
        uscf = ucscf->upstream;
        if ((last_post) && (ngx_strncmp(last_post->host.data, ucscf->host.data, ucscf->host.len) == 0))
        {
            lpost = last_post;
        }
        else
        {
            lpost = 0;
        }
        uc_output_group(pui, uscf, ucscf, i, lpost, flag);
    }
    strcat(testui, (const char *)"</div>");

    uc_output_editdlg(pui);
    strcat(testui, (const char *)"</body></html>");

    uilen = strlen(testui);
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = uilen;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *)"text/html";

    ngx_http_send_header(r);

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

    return ngx_http_output_filter(r, &out);
}

/*
 * function:output server edit dialog of html script
 */
static void
uc_output_editdlg(char **pui)
{
    char *testui;
    testui = *pui;
    strcat(testui, (const char *)"<div class='modal fade' id='editdlg' tabindex='-1' role='dialog' aria-labelledby='editdlglabel' datakey=''>"\
           "<div class='modal-dialog' role='document'>"\
           "<div class='modal-content'>"\
           "<div class='modal-header'>"\
           "<button type='button' class='close' data-dismiss='modal' aria-label='Close'><span aria-hidden='true'>&times;</span></button>"\
           "<h4 class='modal-title' id='editdlglabel'>Edit</h4>"\
           "</div>"\
           "<div class='modal-body'>"\
           "<form class='form-horizontal'>"\
           "<div class='form-group'>"\
           "<label for='m_server' class='col-sm-3 control-label'>Server:</label>"\
           "<p class='col-sm-9 form-control-static' id='m_server'>192.168.1.105:8525</p>"\
           "</div>"\
           "<div class='form-group'>"\
           "<label for='m_weight' class='col-sm-3 control-label'>Weight:</label>"\
           "<div class='col-sm-9'><input type='text' class='form-control' id='m_weight' value=''/></div>"\
           "</div>"\
           "<div class='form-group'>"\
           "<label for='m_backup' class='col-sm-3 control-label'>Backup:</label>"\
           "<div class='col-sm-9'><select class='form-control' id='m_backup'>"\
           "<option>Yes</option>"\
           "<option>No</option>"\
           "</select></div>"\
           "</div>"\
           "<div class='form-group'>"\
           "<label for='m_max_fails' class='col-sm-3 control-label'>max_fails:</label>"\
           "<div class='col-sm-9'><input type='text' class='form-control' id='m_max_fails' value=''/></div>"\
           "</div>"\
           "<div class='form-group'>"\
           "<label for='m_fail_timeout' class='col-sm-3 control-label'>fail_timeout:</label>"\
           "<div class='col-sm-9'><input type='text' class='form-control' id='m_fail_timeout' value=''/></div>"\
           "</div>"\
           "</form>"\
           "</div>"\
           "<div class='modal-footer'>"\
           "<button type='button' class='btn btn-primary'>OK</button>"\
           "</div>"\
           "</div>"\
           "</div>"\
           "</div>"\
           "<script src='/uc.js'></script>"
          );
}

static ngx_uint_t
uc_get_ui_status_flag(ngx_uint_t confidx, ngx_uint_t flag)
{
    return confidx + flag * UC_MAX_GROUP_NUMBER;
}

static void
uc_post_request_handler(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "uc_post_request_handler");

    if(!uc_trylock(uc_get_post_lock()))
    {
        //can't get post lock
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "the last uc post process has been running, wait next chance");
        uc_sh_conf_t *conf;
        ngx_uint_t confidx;
        ngx_int_t rc;

        conf = 0;
        rc = uc_parse_post_para(r->request_body->bufs, r->pool, &conf);
        if( rc == -1)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "page dismatch error.please refresh and try again");
            uc_output_ui(r, uc_get_update_days(), (uc_sh_conf_t *) - 1, 0);
        }
        else
        {
            if(conf == 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "failed to parse post para.");
                uc_output_ui(r, uc_get_update_days(), 0, 0);
            }
            else
            {
                confidx = uc_get_srv_conf_index(sucmcf, &conf->host);
                if(rc == 1)
                {
                    uc_output_ui(r, uc_get_update_days(), conf, uc_get_ui_status_flag(confidx, UI_STATUS_POST_SRV_ZERO));
                }
                else
                {
                    uc_output_ui(r, uc_get_update_days(), conf, uc_get_ui_status_flag(confidx, UI_STATUS_POST_SRV_BUSY));
                }
            }
        }

        ngx_http_finalize_request(r, NGX_OK);
        return;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "lock post");

    //parse post parameter of request
    if (r->request_body == NULL || r->request_body->bufs == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no request body");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        uc_unlock(uc_get_post_lock());
        return;
    }

    uc_sh_conf_t *conf;
    ngx_int_t rc;
    ngx_uint_t confidx;
    conf = 0;

    rc = uc_parse_post_para(r->request_body->bufs, r->pool, &conf);
    if( rc == -1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "page dismatch error.please refresh and try again");
        uc_output_ui(r, uc_get_update_days(), (uc_sh_conf_t *) - 1, 0);
        ngx_http_finalize_request(r, NGX_OK);
        uc_unlock(uc_get_post_lock());
        return;
    }
    else
    {

        if(conf == 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "failed to parse post para");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            uc_unlock(uc_get_post_lock());
            return;
        }
        else
        {
            if(rc == 1)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "no server in the upstream");
                confidx = uc_get_srv_conf_index(sucmcf, &conf->host);
                uc_output_ui(r, uc_get_update_days(), conf, uc_get_ui_status_flag(confidx, UI_STATUS_POST_SRV_ZERO));
                ngx_http_finalize_request(r, NGX_OK);
                uc_unlock(uc_get_post_lock());
                return;
            }
        }
    }

    ngx_int_t post_id;
    post_id = uc_new_post_id();
    //upload new upstream configuration to share memory zone
    if(uc_upload_data_to_shzone(conf) == -1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to upload post data to share memory zone");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        uc_unlock(uc_get_post_lock());
        return;
    }

    //notice all worker to synchronous new configuration
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "send sig SIG_UPSTREAM_SYN to master process");


    confidx = uc_get_srv_conf_index(sucmcf, &conf->host);

    uc_syn_init(post_id, confidx, r);

    if (sigqueue(getppid(), SIG_UPSTREAM_SYN, (const union sigval)(int)post_id) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "failed to send sig SIG_UPSTREAM_SYN.");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        uc_unlock(uc_get_post_lock());
    }
    ngx_http_finalize_request(r, NGX_OK);
}

static int
uc_cmp_name_key(char *name, char *key)
{
    char *n, *k;
    ngx_int_t nlen, klen;
    nlen = strlen(name);
    klen = strlen(key);
    if(nlen < klen)
    {
        return -1;
    }

    for(n = name + nlen, k = key + klen;; n--, k--)
    {
        if(*k != *n)
        {
            return -1;
        }
        if(k == key)
        {
            break;
        }

    }
    return 0;

}

static char *
uc_parse_conf_name(char *name)
{

    char *p, *conf;

    conf = 0;

    if(strstr(name, "post[") != 0)
    {
        p = name + strlen("post[");
        conf = p;

        while(*p != 0)
        {
            if(*p == ']')
            {
                *p = 0;
                break;
            }
            p++;
        }

    }
    return conf;

}


static ngx_int_t
uc_para_assign(uc_sh_conf_t *conf, char *name, ngx_uint_t *index, char *value, ngx_pool_t *pool)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "uc_para_assign");
    if(uc_cmp_name_key(name, "[iphash]") == 0)
    {
        conf->ip_hash = ngx_atoi((u_char *)value, strlen(value));
    }
    else if(uc_cmp_name_key(name, "[keepalive]") == 0)
    {
        conf->keepalive = ngx_atoi((u_char *)value, strlen(value));
    }
    else if(uc_cmp_name_key(name, "[submit]") == 0)
    {
        uc_srv_conf_t *ucscf;
        char *host;
        host = uc_parse_conf_name(name);
        conf->host.len = strlen(host);
        conf->host.data = ngx_pcalloc(pool, conf->host.len);
        if(conf->host.data == NULL)
        {
            ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                          "failed to alloc post host para space");
            return -1;
        }
        ngx_memcpy(conf->host.data, host, conf->host.len);

        ucscf = uc_get_srv_conf_byhost(sucmcf, &conf->host);
        if(ucscf == NULL)
        {
            ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                          "request group name dismatch runing group name");
            return -1;
        }
        conf->server = ngx_pcalloc(pool, sizeof(uc_sh_server_t) * ucscf->upstream->servers->nelts);
        if(conf->server == NULL)
        {
            ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                          "failed to alloc uc_sh_server_t when parse post para and assign value");
            return -1;
        }
        conf->num = ucscf->upstream->servers->nelts;

    }
    else if(uc_cmp_name_key(name, "[name]") == 0)
    {
        if((*index) >= conf->num)  return -1;
        conf->server[*index].server.name.len = strlen(value);
        conf->server[*index].server.name.data = ngx_pcalloc(pool, conf->server[*index].server.name.len);
        if(conf->server[*index].server.name.data == NULL)
        {
            ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                          "failed to alloc post server name para space");
            return -1;
        }
        ngx_memcpy(conf->server[*index].server.name.data, value, conf->server[*index].server.name.len);


    }
    else if(uc_cmp_name_key(name, "[weight]") == 0)
    {
        if((*index) >= conf->num)  return -1;
        conf->server[*index].server.weight = ngx_atoi((u_char *)value, strlen(value));
    }
    else if(uc_cmp_name_key(name, "[backup]") == 0)
    {
        if((*index) >= conf->num)  return -1;
        if(ngx_strncasecmp((u_char *)value, (u_char *)"Yes", 3) == 0)
        {
            conf->server[*index].server.backup = 1;
        }
        else if(ngx_strncasecmp((u_char *)value, (u_char *)"No", 2) == 0)
        {
            conf->server[*index].server.backup = 0;
        }
    }
    else if(uc_cmp_name_key(name, "[max_fails]") == 0)
    {
        if((*index) >= conf->num)  return -1;
        conf->server[*index].server.max_fails = ngx_atoi((u_char *)value, strlen(value));
    }
    else if(uc_cmp_name_key(name, "[fail_timeout]") == 0)
    {
        if((*index) >= conf->num)  return -1;
        conf->server[*index].server.fail_timeout = ngx_atoi((u_char *)value, strlen(value));
    }
    else if(uc_cmp_name_key(name, "[status]") == 0)
    {
        if((*index) >= conf->num)  return -1;
        if(ngx_strncasecmp((u_char *)value, (u_char *)"Normal", 6) == 0)
        {
            conf->server[*index].server.down = 0;
        }
        else if(ngx_strncasecmp((u_char *)value, (u_char *)"Down", 4) == 0)
        {
            conf->server[*index].server.down = 1;
        }

        (*index)++;
    }
    else
    {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "post para dosen't exist");
        return -1;
    }
    return 0;
}

/*
 * parse post parameters from html POST request
 */
static ngx_int_t
uc_parse_post_para(ngx_chain_t *postbufs, ngx_pool_t *pool, uc_sh_conf_t **confp)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "uc_parse_post_para");
    char *start, *end, *b, *token;
    ngx_chain_t *c;
    uc_node_t *head, *iter;
    ngx_uint_t i, blen;
    uc_sh_conf_t *conf;

    //compute post parameter string's total length

    c = postbufs;
    blen = 0;
    while(c != 0)
    {
        blen += (c->buf->last - c->buf->pos);
        c = c->next;
    }

    //copy chain's content to single buffer

    start = (char *)ngx_pnalloc(pool, blen);
    if(start == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "faile to alloc buffer when copy chain content");
        return -1;
    }
    end = start + blen;

    b = start;
    c = postbufs;
    while(c != 0)
    {
        ngx_memcpy(b, c->buf->pos, c->buf->last - c->buf->pos);
        b = b + (c->buf->last - c->buf->pos);
        c = c->next;
    }

    //parse buffer to node struct

    head = ngx_pcalloc(pool, sizeof(uc_node_t));
    if(head == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "faile to alloc node when parse node struct");
        return -1;
    }

    iter = head;


    b = start;
    token = start;
    iter -> name = token;


    while (1)
    {
        if (*b == '=')
        {
            *token = 0;
            iter->value = token + 1;
        }
        else if (*b == '+')
        {
            *token = ' ';
        }
        else if (*b == '%')
        {
            *token = uc_hex_trans(*(b + 1)) * 16 + uc_hex_trans(*(b + 2));
            b += 2;
        }
        else if (*b == '&')
        {
            *token = 0;
            iter->next = ngx_pcalloc(pool, sizeof(uc_node_t));
            if(iter->next == NULL)
            {
                ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                              "faile to alloc node when parse node struct");
                return -1;
            }

            iter = iter->next;
            iter->name = token + 1;
        }
        else
        {

            *token = *b;
        }

        if(b >= end)
        {
            token++;
            *token = 0;
            break;
        }
        b++;
        token++;
    }

    //parse node struct to uc_sh_conf_t struct

    conf = ngx_pcalloc(pool, sizeof(uc_sh_conf_t));
    if(conf == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "faile to alloc uc_sh_conf_t when parse post para");
        return -1;
    }

    i = 0;
    iter = head;
    while(iter != 0)
    {
        if(uc_para_assign(conf, iter->name, &i, iter->value, pool) == -1)
        {
            return -1;
        }
        iter = iter->next;
    }
    if(conf->num != i)
    {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "request server row count dismatch runing server row count");
        return -1;
    }

    *confp = conf;

    //if all server is backup a mistacke will occur
    ngx_uint_t active_peer;
    active_peer = 0;
    for(i = 0; i < conf->num; i++)
    {
        if(!conf->server[i].server.backup)
        {
            active_peer++;
        }
    }
    if(active_peer == 0)
    {
        ngx_log_error(NGX_LOG_ALERT, pool->log, 0,
                      "all server is backup server");
        return 1;
    }


    return 0;
}

static char
uc_hex_trans(char ch)
{
    char c;
    if (ch < 'A')
    {
        c = ch - 48;
    }
    else if (ch < 'a')
    {
        c = ch - 55;
    }
    else
    {
        c = ch - 87;
    }
    return c;
}

static ngx_int_t
uc_request_handler(ngx_http_request_t *r)
{

    if (r->method & NGX_HTTP_POST)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                       "uc_request_handler this is a post request.");
        ngx_http_read_client_request_body(r, uc_post_request_handler);
        return NGX_DONE;
    }
    else
    {

        ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                       "uc_request_handler this is a get request.");

        return uc_output_ui(r, uc_get_update_days(), 0, UI_STATUS_GET);

    }
}

static char *
uc_cmd_set_upstreams_admin_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    uc_main_conf_t            *ucmcf;
    ngx_str_t                 *value;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_cmd_set_upstreams_admin_handler");

    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);

    value = cf->args->elts;    //ex:upstreams_admin on

    if (ngx_strcmp(value[1].data, "off") == 0)
    {
        ucmcf->upstreams_admin = UPSTREAM_CTL_ADM_OFF;
        return NGX_CONF_OK;
    }
    else if (ngx_strcmp(value[1].data, "on") == 0)
    {
        ucmcf->upstreams_admin = UPSTREAM_CTL_ADM_ON;
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = uc_request_handler;

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
    ngx_command_t   *cmd;
    uc_main_conf_t  *ucmcf;

    if(ngx_process == NGX_PROCESS_SIGNALLER)
    {
        return 0;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_module_preconf");
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

static ngx_int_t
uc_module_postconf(ngx_conf_t *cf)
{
    if(ngx_process == NGX_PROCESS_SIGNALLER)
    {
        return 0;
    }
    if(sucmcf->upstreams_admin != UPSTREAM_CTL_ADM_ON)
    {
        return NGX_OK;
    }
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_module_postconf");
    uc_reg_shzone(cf, sucmcf);

    return NGX_OK;

}

/*
 * function:hook upstream finalize request handler when initial upstream request
 */
static ngx_int_t
uc_request_count_hook_handler(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    uc_srv_conf_t *ucscf, **ucscfp;
    ngx_uint_t    i;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                   "uc_request_count_hook_handler");
    ucscfp = sucmcf->upstreams.elts;
    for (i = 0; i < sucmcf->upstreams.nelts; i++)
    {
        ucscf = ucscfp[i];
        if (ucscf->upstream == us)
        {
            uc_rcount_key_t *key;
            ngx_queue_t *q;

            if (ngx_queue_empty(&sucmcf->rcount_free_queue))
            {
                key = ngx_array_push(sucmcf->rcount_key);
                if (NULL == key)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "failed to hook finalize_request because of alloction of uc_rcount_key");
                    return NGX_ERROR;
                }
                ngx_queue_insert_head(&sucmcf->rcount_free_queue, &key->queue);
            }

            q = ngx_queue_head(&sucmcf->rcount_free_queue);
            key = ngx_queue_data(q, uc_rcount_key_t, queue);

            key->r = r;
            if (uc_sig_rcount_rpt_handler != r->upstream->finalize_request)
            {
                key->original_finalize_request_handler = r->upstream->finalize_request;
                r->upstream->finalize_request = uc_sig_rcount_rpt_handler;
                ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                               "hook upstream finalize_request using uc_sig_rcount_rpt_handler");
            }
            key->conf = i;
            key->ucscf = ucscf;

            ngx_queue_remove(q);
            ngx_queue_insert_head(&sucmcf->rcount_use_queue, q);

            ngx_http_upstream_init_peer_pt peer_init_handler;

            uc_apply_lock_rlock(&ucscf->apply_lock, &ucscf->apply_lock_tries);

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0,
                           "lock before upstream peer init handle");
            peer_init_handler = ucscf->original_peer_init_handler;
            if (peer_init_handler)
            {
                return peer_init_handler(r, us);
            }
        }
    }
    return NGX_ERROR;

}


static char *
uc_upstream_block_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    uc_main_conf_t                  *ucmcf;
    uc_srv_conf_t                   *ucscf, **ucscfp;
    ngx_http_upstream_main_conf_t   *umcf;
    ngx_http_upstream_srv_conf_t    *uscf, **uscfp;
    ngx_str_t                       *value;
    ngx_uint_t                      i;
    char                            *rc;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_upstream_block_hook_handler");
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
            //point original upstream server conf to module'server conf's upstream member
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

            //catch kcp
            ucscf->kcf = ngx_http_conf_upstream_srv_conf(ucscf->upstream, ngx_http_upstream_keepalive_module);
            ngx_queue_init(&ucscf->free_caches);
            ucscf->added_caches = ngx_array_create(cf->pool, 5, sizeof(ngx_http_upstream_keepalive_cache_t));

            //try keepalive and iphash
            if (ucscf->ip_hash == 0 || ucscf->keepalive == 0)
            {
                ngx_conf_t                     pcf;
                ngx_http_conf_ctx_t           *ctx;

                pcf = *cf;
                ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
                if (ctx == NULL)
                {
                    return NGX_CONF_ERROR;
                }
                ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * (ngx_http_upstream_module.ctx_index + 1));
                if (ctx->srv_conf == NULL)
                {
                    return NGX_CONF_ERROR;
                }
                ctx->srv_conf[ngx_http_upstream_module.ctx_index] = ucscf->upstream;
                cf->ctx = ctx;

                if (ucscf->ip_hash == 0)
                {
                    rc = ucmcf->original_iphash_cmd_set_handler(cf, 0, 0);
                    if (rc != NGX_CONF_OK)
                    {
                        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "fail to try iphash");
                        return NGX_CONF_ERROR;
                    }
                }

                if (ucscf->keepalive == 0)
                {
                    ngx_array_t *oldargs;
                    ngx_str_t *sname, *svalue;
                    char *name, *value;

                    name = (char *)ngx_pcalloc(cf->pool, sizeof("keepalive"));
                    value = (char *)ngx_pcalloc(cf->pool, sizeof("2"));
                    ngx_memcpy(name, "keepalive", sizeof("keepalive") - 1);
                    ngx_memcpy(value, "2", sizeof("2") - 1);

                    oldargs = cf->args;
                    cf->args = ngx_array_create(cf->pool, 2, sizeof(ngx_str_t));
                    sname = (ngx_str_t *)ngx_array_push(cf->args);
                    sname->data = (u_char *) name;
                    sname->len = sizeof("keepalive") - 1;
                    svalue = (ngx_str_t *)ngx_array_push(cf->args);
                    svalue->data = (u_char *) value;
                    svalue->len = sizeof("2") - 1;

                    rc = ucmcf->original_keepalive_cmd_set_handler(cf, 0, ucscf->kcf);

                    cf->args = oldargs;
                    if (rc != NGX_CONF_OK)
                    {
                        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "fail to try keepalive");
                        return NGX_CONF_ERROR;
                    }
                }
                *cf = pcf;
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
uc_get_srv_conf_byhost(uc_main_conf_t *ucmcf, ngx_str_t *host)
{
    uc_srv_conf_t *ucscf, **ucscfp;
    ngx_uint_t    i;

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

static uc_srv_conf_t *
uc_get_srv_conf_byidx(ngx_uint_t confidx)
{
    uc_srv_conf_t **ucscfp;
    ucscfp = (uc_srv_conf_t **)sucmcf->upstreams.elts;
    return (uc_srv_conf_t *)ucscfp[confidx];
}

static ngx_int_t
uc_get_srv_conf_index(uc_main_conf_t *ucmcf, ngx_str_t *host)
{
    uc_srv_conf_t *ucscf, **ucscfp;
    ngx_uint_t    i;

    ucscfp = ucmcf->upstreams.elts;
    for (i = 0; i < ucmcf->upstreams.nelts; i++)
    {
        ucscf = ucscfp[i];
        if ((ucscf->host.len == host->len)
                && (ngx_strncasecmp(ucscf->host.data, host->data, host->len) == 0))
        {
            return i;
        }
    }

    return -1;
}

static ngx_int_t
uc_get_peer_srv_index(ngx_uint_t conf, ngx_str_t *peer)
{
    uc_srv_conf_t *ucscf, **ucscfp;
    uc_server_t *ucsrv;
    ngx_uint_t i, j;

    ucscfp = (uc_srv_conf_t **)sucmcf->upstreams.elts;
    ucscf = (uc_srv_conf_t *)ucscfp[conf];
    ucsrv = (uc_server_t *)ucscf->uc_servers->elts;

    for (i = 0; i < ucscf->uc_servers->nelts; i++)
    {
        for (j = 0; j < ucsrv[i].server->naddrs; j++)
        {
            if ((peer->len == ucsrv[i].running_server[j]->name.len)
                    && (ngx_strncmp(peer->data, ucsrv[i].running_server[j]->name.data, peer->len) == 0))
            {
                return i;
            }
        }

    }
    return -1;
}


static char *
uc_iphash_hook_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    uc_main_conf_t               *ucmcf;
    uc_srv_conf_t                *ucscf;
    ngx_http_upstream_srv_conf_t *uscf;
    char                         *rc;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_iphash_hook_handler");
    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ucscf = uc_get_srv_conf_byhost(ucmcf, &uscf->host);

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
    uc_main_conf_t                         *ucmcf;
    uc_srv_conf_t                          *ucscf;
    ngx_http_upstream_srv_conf_t           *uscf;
    ngx_http_upstream_keepalive_srv_conf_t *ukscf;
    char                                   *rc;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_keepalive_hook_handler");

    ucmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_ctl_module);
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ucscf = uc_get_srv_conf_byhost(ucmcf, &uscf->host);

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

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "uc_module_create_main_conf");
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
        ucmcf->original_init_keepalive_peer = sucmcf->original_init_keepalive_peer;
        ucmcf->original_init_iphash_peer = sucmcf->original_init_iphash_peer;
        ucmcf->original_sigchld_handler = sucmcf->original_sigchld_handler;
    }
    sucmcf = ucmcf;

    return ucmcf;
}

static ngx_int_t
uc_module_init(ngx_cycle_t *cycle)
{
    void                ***cf;
    ngx_event_conf_t    *ecf;
    ngx_core_conf_t     *ccf;
    ngx_uint_t          i, j;
    ngx_int_t           n;
    ngx_event_module_t  *m;
    uc_main_conf_t      *ucmcf;
    uc_syn_key_t        *syn_key;
    ngx_signal_t        *sig;

    if(ngx_process == NGX_PROCESS_SIGNALLER)
    {
        return NGX_OK;
    }

    if(sucmcf->upstreams_admin != UPSTREAM_CTL_ADM_ON)
    {
        uc_srv_conf_t *ucscf, **ucscfp;
        ucscfp = sucmcf->upstreams.elts;

        for (i = 0; i < sucmcf->upstreams.nelts; i++)
        {

            ucscf = ucscfp[i];
            //catch keepalive and iphash init peer handler
            if (ucscf->kcf->original_init_peer == 0)
            {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "init peer handler has an error");
                return NGX_ERROR;
            }

            if (sucmcf->original_init_keepalive_peer == 0 && sucmcf->original_init_iphash_peer == 0)
            {
                sucmcf->original_init_keepalive_peer = ucscf->upstream->peer.init;
                sucmcf->original_init_iphash_peer = ucscf->kcf->original_init_peer;
            }

            //return to real status before try keepalive and iphash
            uc_reset_peer_init_handler(ucscf->ip_hash, ucscf->keepalive, ucscf);
            uc_reset_keepalive_cache(ucscf->keepalive, ucscf, cycle->log);

            //recover peer_init_handler
            ucscf->upstream->peer.init = ucscf->original_peer_init_handler;


        }
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "uc_module_init");

    //setup SIGCHLD hook handler
    for (sig = signals; sig->signo != 0; sig++)
    {
        if(ngx_strcmp(sig->signame, "SIGCHLD") == 0)
        {
            if(uc_sigchld_handler != sig->handler)
            {
                sucmcf->original_sigchld_handler = sig->handler;
                sig->handler = uc_sigchld_handler;
            }
            break;
        }
    }


    //install channel add event hook
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
            }
            break;
        }
    }

    //install sig handler
    struct sigaction sa;

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_sigaction = uc_sig_syn_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIG_UPSTREAM_SYN, &sa, NULL) == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigaction(SIG_UPSTREAM_SYN) failed");
        return NGX_ERROR;
    }

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_sigaction = uc_sig_syn_ack_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIG_UPSTREAM_SYN_ACK, &sa, NULL) == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigaction(SIG_UPSTREAM_SYN_ACK) failed");
        return NGX_ERROR;
    }

    ngx_memzero(&sa, sizeof(struct sigaction));
    sa.sa_sigaction = uc_sig_rcount_write_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIG_UPSTREAM_REQUEST_COUNT_REPORT, &sa, NULL) == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "sigaction(SIG_UPSTREAM_REQUEST_COUNT_REPORT) failed");
        return NGX_ERROR;
    }

    //upgrade sig access
    ccf = (ngx_core_conf_t *)ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (geteuid() == 0)
    {
        ccf->group = getgid();
        ccf->user = getuid();
        struct passwd *passwd;
        passwd = getpwuid(ccf->user);
        ccf->username = passwd->pw_name;
    }

    //init syn key
    sucmcf->syn_key = ngx_array_create(cycle->pool, ccf->worker_processes, sizeof(uc_syn_key_t));
    for (n = 0; n < ccf->worker_processes; n++)
    {
        syn_key = ngx_array_push(sucmcf->syn_key);
        if (syn_key == NULL)
        {
            return NGX_ERROR;
        }
    }

    //init timeout event
    sucmcf->timeout_ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (sucmcf->timeout_ev == NULL)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "failed to init timeout events");
        return NGX_ERROR;

    }
    sucmcf->timeout_ev->handler = uc_post_timeout_event_handler;
    sucmcf->timeout_ev->log = cycle->log;
    sucmcf->timeout_ev->data = ngx_pcalloc(cycle->pool, sizeof(uc_event_data_t)); //only use post_id member of the struct

    uc_srv_conf_t *ucscf, **ucscfp;
    uc_server_t *ucsrv;
    ngx_http_upstream_server_t *ussrv;


    ucscfp = ucmcf->upstreams.elts;

    for (i = 0; i < ucmcf->upstreams.nelts; i++)
    {

        ucscf = ucscfp[i];

        //init apply event
        ucscf->apply_ev = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
        if (ucscf->apply_ev == NULL)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "failed to init apply conf events");
            return NGX_ERROR;
        }
        ucscf->apply_ev->handler = uc_apply_conf_post_handler;
        ucscf->apply_ev->log = cycle->log;
        ucscf->apply_ev->data = ngx_pcalloc(cycle->pool, sizeof(uc_event_data_t));

        //catch keepalive and iphash init peer handler
        if (ucscf->kcf->original_init_peer == 0)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "init peer handler has an error");
            return NGX_ERROR;
        }

        if (sucmcf->original_init_keepalive_peer == 0 && sucmcf->original_init_iphash_peer == 0)
        {
            sucmcf->original_init_keepalive_peer = ucscf->upstream->peer.init;
            sucmcf->original_init_iphash_peer = ucscf->kcf->original_init_peer;
        }

        //return to real status before try keepalive and iphash
        uc_reset_peer_init_handler(ucscf->ip_hash, ucscf->keepalive, ucscf);
        uc_reset_keepalive_cache(ucscf->keepalive, ucscf, cycle->log);

        //hook peer_init_handler
        if (uc_request_count_hook_handler != ucscf->upstream->peer.init)
        {
            ucscf->upstream->peer.init = uc_request_count_hook_handler;
        }
        else
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "failed to hook upstream peer init handler");
            return NGX_ERROR;
        }

        //init uc server data
        ussrv = (ngx_http_upstream_server_t *)ucscf->upstream->servers->elts;
        ucscf->uc_servers = ngx_array_create(cycle->pool, ucscf->upstream->servers->nelts, sizeof(uc_server_t));

        for (j = 0; j < ucscf->upstream->servers->nelts; j++)
        {
            ucsrv = (uc_server_t *)ngx_array_push(ucscf->uc_servers);
            if(ucsrv == NULL)
            {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "failed to push uc_server array");
                return NGX_ERROR;
            }
            ucsrv->server = &ussrv[j];
            ucsrv->running_server = ngx_pcalloc(cycle->pool, sizeof(ngx_http_upstream_rr_peer_t *) * ussrv[j].naddrs);

            if(ucsrv->running_server == NULL)
            {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "failed to alloc ucsrv->running_server");
                return NGX_ERROR;
            }

            ngx_uint_t k;
            ngx_http_upstream_rr_peers_t *peers;
            ngx_http_upstream_rr_peer_t *peer;

            peers = (ngx_http_upstream_rr_peers_t *)ucscf->upstream->peer.data;
            k = 0;

            while (peers != 0)
            {
                peer = peers->peer;
                while (peer != 0)
                {
                    if((peer->server.len == ussrv[j].name.len)
                            && (ngx_strncmp(peer->server.data, ussrv[j].name.data, ussrv[j].name.len) == 0))
                    {
                        ucsrv->running_server[k] = peer;
                        k++;
                    }
                    peer = peer->next;
                }
                peers = peers->next;
            }
        }

        //init temporary conf
        ucscf->temp_conf = ngx_pcalloc(cycle->pool, sizeof(uc_sh_conf_t));
        if(ucscf->temp_conf == NULL)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "failed to alloc temporary conf space");
        }
        ucscf->temp_conf->server = ngx_pcalloc(cycle->pool, sizeof(uc_sh_server_t) * ucscf->upstream->servers->nelts);
        if(ucscf->temp_conf->server == NULL)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "failed to alloc temporary conf's server space");
        }
    }

    //init rcount key
    sucmcf->rcount_key = ngx_array_create(cycle->pool, UC_RCOUNT_KEY_ARRAY_INIT_SIZE, sizeof(uc_rcount_key_t));
    ngx_queue_init(&sucmcf->rcount_use_queue);
    ngx_queue_init(&sucmcf->rcount_free_queue);

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
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "uc_channel_add_event_hook_handler");
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

/*
 * function: worker's channel command handler
 */
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

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

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
        case CHANNEL_CMD_UPSTREAM_SYN:
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "CHANNEL_CMD_UPSTREAM_SYN handler");

            ngx_int_t post_id;
            uc_srv_conf_t *ucscf;
            uc_event_data_t *ev_data;
            uc_post_status_t post_status;

            post_id = ch.slot;
            if(!uc_post_status_is_valid(post_id, &post_status))
            {
                ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "post has aborted. postid1:%d postid2:%d code:%d", post_id, post_status.post_id, post_status.status_code);
                break;
            }
            uc_download_data_from_shzone(post_status.syn_conf);

            ucscf = uc_get_srv_conf_byidx(post_status.syn_conf);
            ev_data = (uc_event_data_t *)ucscf->apply_ev->data;
            ev_data->ucscf = ucscf;
            ev_data->confidx = post_status.syn_conf;
            ev_data->post_id = post_id;
            ngx_post_event(ucscf->apply_ev, &ngx_posted_events);

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "post apply conf event");

            break;
        case CHANNEL_CMD_UPSTREAM_FINALIZE_REQ:
        {

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "CHANNEL_CMD_UPSTREAM_FINALIZE_REQ handler");

            uc_post_status_t post_status;
            uc_get_post_status(&post_status);
            uc_finalize_post_request(post_status.r, post_status.status_code);
        }

        break;
        }
    }

    //ucmcf->original_channel_handler(ev);

}

static void
uc_apply_conf_post_handler(ngx_event_t *ev)
{
    uc_event_data_t *ev_data;
    ngx_int_t post_id;
    uc_post_status_t post_status;

    ev_data = (uc_event_data_t *)ev->data;
    post_id = ev_data->post_id;

    if(!uc_post_status_is_valid(post_id, &post_status))
    {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "post has aborted. postid1:%d postid2:%d code:%d", post_id, post_status.post_id, post_status.status_code);
        return;
    }

    if(uc_apply_lock_trylock(&ev_data->ucscf->apply_lock, &ev_data->ucscf->apply_lock_tries))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "get apply conf lock");
        uc_apply_new_conf(ev_data->confidx, ev->log);
        uc_apply_lock_unlock(&ev_data->ucscf->apply_lock, &ev_data->ucscf->apply_lock_tries);

        if (sigqueue(getppid(), SIG_UPSTREAM_SYN_ACK, (const union sigval)(int)post_id) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "failed to send sig SIG_UPSTREAM_SYN_ACK.");
        }

    }
    else
    {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "failed to get apply conf lock,repost event");
        ngx_add_timer(ev, UC_APPCONF_TIMESPAN);
    }

}


/*
 * function:finalize uc post request,output response script and unlock post
 */
static void
uc_finalize_post_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, r->connection->log, 0, "uc_finalize_post_request");

    ngx_uint_t flag;

    //del timeout timer
    if(sucmcf->timeout_ev->timer_set)
    {
        ngx_del_timer(sucmcf->timeout_ev);
    }
    if(rc == UI_STATUS_POST_OK)
    {
        uc_set_last_update();

    }
    flag = uc_get_ui_status_flag(uc_get_syn_conf(), rc);
    uc_output_ui(r, uc_get_update_days(), 0, flag);
    r->blocked--;
    ngx_http_finalize_request(r, NGX_DONE);

    uc_unlock(uc_get_post_lock());
}

static void
uc_post_timeout_event_handler(ngx_event_t *ev)
{

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "uc_post_timeout_event_handler");

    ngx_int_t post_id;
    uc_event_data_t *ev_data;
    uc_post_status_t post_status;

    ev_data = (uc_event_data_t *)ev->data;
    post_id = ev_data->post_id;

    if(!uc_post_status_is_valid(post_id, &post_status))
    {
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "post has aborted. postid1:%d postid2:%d code:%d", post_id, post_status.post_id, post_status.status_code);
        return;
    }

    uc_set_post_status_code(UI_STATUS_POST_TIMEOUT);
    uc_finalize_post_request(post_status.r, UI_STATUS_POST_TIMEOUT);
}

/*
 * function:worker core dump unlock post. executed within master process.
 */
static void
uc_sigchld_handler(int signo)
{
    sucmcf->original_sigchld_handler(signo);

    ngx_int_t i;
    for (i = 0; i < ngx_last_process; i++)
    {
        if ((ngx_processes[i].exited == 1)                  //process exited
                && (WIFSIGNALED(ngx_processes[i].status))   //process fail exited
           )
        {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "uc_sigchld_handler");

            uc_post_status_t post_status;

            uc_get_post_status(&post_status);
            uc_set_post_status_code(UI_STATUS_POST_SRV_ERR);
            if(post_status.post_pid != ngx_processes[i].pid)
            {
                uc_send_finalize_req_channel_cmd(0);
            }
            else
            {
                uc_unlock(uc_get_post_lock());
            }
            break;
        }
    }

}


/*
 * function:handle SIG_UPSTREAM_SYN signal of workers. running in master process.
 */
static void
uc_sig_syn_handler(int signo, siginfo_t *sig_info, void *unused)
{
    ngx_int_t      i, n;
    ngx_channel_t  ch;
    uc_syn_key_t   *syn_key;
    ngx_int_t post_id;
    uc_post_status_t post_status;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                   "uc_sig_syn_handler");
    post_id = (ngx_int_t)sig_info->si_value.sival_int;

    if(!uc_post_status_is_valid(post_id, &post_status))
    {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "post has aborted. postid1:%d postid2:%d code:%d", post_id, post_status.post_id, post_status.status_code);
        return;
    }

    ngx_memzero(&ch, sizeof(ngx_channel_t));
    ch.command = CHANNEL_CMD_UPSTREAM_SYN;
    ch.fd = -1;
    ch.slot = post_id;

    ngx_queue_init(&sucmcf->syn_queue);
    syn_key = sucmcf->syn_key->elts;
    n = 0;

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
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "Failed to write channel for send CHANNEL_CMD_UPSTREAM_SYN. child: %d %P e:%d t:%d d:%d r:%d j:%d   err:%s",
                          i,
                          ngx_processes[i].pid,
                          ngx_processes[i].exiting,
                          ngx_processes[i].exited,
                          ngx_processes[i].detached,
                          ngx_processes[i].respawn,
                          ngx_processes[i].just_spawn,
                          strerror(errno));
            uc_set_post_status_code(UI_STATUS_POST_SRV_ERR);
            //send finalize post request channel cmd
            uc_send_finalize_req_channel_cmd(post_id);
            return;
        }

        syn_key[n].pid = ngx_processes[i].pid;
        ngx_queue_insert_head(&sucmcf->syn_queue, &syn_key[n].queue);
        n++;
    }
}

/*
 * function:send CHANNEL_CMD_UPSTREAM_UNLOCK back to the launched worker process when synchronous finished
 */
static void
uc_send_finalize_req_channel_cmd(ngx_int_t post_id)
{
    ngx_channel_t  ch;
    ngx_pid_t pid;
    ngx_int_t i;
    ngx_int_t process_is_dead;

    ngx_memzero(&ch, sizeof(ngx_channel_t));
    ch.command = CHANNEL_CMD_UPSTREAM_FINALIZE_REQ;
    ch.fd = -1;
    ch.slot = post_id;
    pid = uc_get_post_process();
    process_is_dead = 1;

    for (i = 0; i < ngx_last_process; i++)
    {
        if (ngx_processes[i].pid == pid)
        {
            process_is_dead = 0;
            if (ngx_write_channel(ngx_processes[i].channel[0], &ch, sizeof(ngx_channel_t), ngx_cycle->log)
                    != NGX_OK)
            {
                ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, ngx_errno, "failed to send CHANNEL_CMD_UPSTREAM_UNLOCK");
                uc_set_post_status_code(UI_STATUS_POST_SRV_ERR);
                uc_unlock(uc_get_post_lock());
            }

        }
    }
    if (process_is_dead)
    {
        uc_set_post_status_code(UI_STATUS_POST_SRV_ERR);
        uc_unlock(uc_get_post_lock());
    }
}

/*
 * function:handle SIG_UPSTREAM_SYN_ACK signal of workers. running in master process.
 */
static void
uc_sig_syn_ack_handler(int signo, siginfo_t *sig_info, void *unused)
{
    ngx_pid_t pid;
    ngx_queue_t *q;
    uc_syn_key_t *syn_key;
    ngx_int_t i, post_id;
    uc_post_status_t post_status;


    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "uc_sig_syn_ack_handler");

    pid = sig_info->si_pid;
    post_id = (ngx_int_t)sig_info->si_value.sival_int;

    if(!uc_post_status_is_valid(post_id, &post_status))
    {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "post has aborted. postid1:%d postid2:%d code:%d", post_id, post_status.post_id, post_status.status_code);
        return;
    }


    for (q = ngx_queue_head(&sucmcf->syn_queue);
            q != ngx_queue_sentinel(&sucmcf->syn_queue);
            q = ngx_queue_next(q))
    {
        syn_key = ngx_queue_data(q, uc_syn_key_t, queue);

        if (syn_key->pid == pid)
        {
            ngx_queue_remove(q);
            break;
        }
    }

    if(ngx_queue_empty(&sucmcf->syn_queue))
    {
        uc_send_finalize_req_channel_cmd(post_id);

    }
    else
    {

        for (q = ngx_queue_head(&sucmcf->syn_queue);
                q != ngx_queue_sentinel(&sucmcf->syn_queue);
                q = ngx_queue_next(q))
        {
            syn_key = ngx_queue_data(q, uc_syn_key_t, queue);

            for (i = 0; i < ngx_last_process; i++)
            {

                if(syn_key->pid == ngx_processes[i].pid)
                {
                    return;
                }

            }
        }

        uc_send_finalize_req_channel_cmd(post_id);

    }
}

/*
 * function:update request count when receive SIG_UPSTREAM_REQUEST_COUNT_REPORT in master process
 */
static void
uc_sig_rcount_write_handler(int signo, siginfo_t *sig_info, void *unused)
{
    ngx_uint_t rpt, group, server;
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "uc_sig_rcount_write_handler");

    rpt = (ngx_uint_t)sig_info->si_value.sival_int;
    group = rpt / UC_MAX_GROUPSRV_NUMBER;
    server = rpt % UC_MAX_GROUPSRV_NUMBER;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "receive SIG_UPSTREAM_REQUEST_COUNT_REPORT sig param:group(%d), server(%d)", group, server);

    shpool = (ngx_slab_pool_t *) sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_wlock(&ucsh->conf[group].server[server].rcount_lock);
    ucsh->conf[group].server[server].rcount++;
    ngx_rwlock_unlock(&ucsh->conf[group].server[server].rcount_lock);

}

/*
 * function:send SIG_UPSTREAM_REQUEST_COUNT_REPORT when finalize a upstream request
 */
static void
uc_sig_rcount_rpt_handler(ngx_http_request_t *r, ngx_int_t rc)
{
    uc_rcount_key_t *key;
    ngx_queue_t *q;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "uc_sig_rcount_rpt_handler");
    for (q = ngx_queue_head(&sucmcf->rcount_use_queue);
            q != ngx_queue_sentinel(&sucmcf->rcount_use_queue);
            q = ngx_queue_next(q))
    {
        key = ngx_queue_data(q, uc_rcount_key_t, queue);

        if (key->r == r)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&sucmcf->rcount_free_queue, q);

            ngx_uint_t rpt;
            ngx_int_t server;

            server = uc_get_peer_srv_index(key->conf, r->upstream->peer.name);
            if (server != -1)
            {
                rpt = key->conf * UC_MAX_GROUPSRV_NUMBER + server;//combine group index and server index for a signal value
                if (sigqueue(getppid(), SIG_UPSTREAM_REQUEST_COUNT_REPORT, (const union sigval)(int)rpt) == -1)
                {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "failed to send sig SIG_UPSTREAM_REQUEST_COUNT_REPORT.");
                }
            }
            else
            {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "failed to get peer srv index. conf:%d,peer:%V", key->conf, r->upstream->peer.name);
            }

            if (key->original_finalize_request_handler)
            {
                key->original_finalize_request_handler(r, rc);
                uc_apply_lock_unlock(&key->ucscf->apply_lock, &key->ucscf->apply_lock_tries);
                ngx_log_debug0(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "unlock apply lock");
                return;
            }
            else
            {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "can't find  original_finalize_request_handler");
                return;
            }

            break;
        }
    }
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, "an unknown error occurs when reporting rcount");
}

static ngx_uint_t
uc_get_rcount(ngx_uint_t group, ngx_uint_t server)
{
    ngx_uint_t rcount;
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    shpool = (ngx_slab_pool_t *) sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_rlock(&ucsh->conf[group].server[server].rcount_lock);
    rcount = ucsh->conf[group].server[server].rcount;
    ngx_rwlock_unlock(&ucsh->conf[group].server[server].rcount_lock);
    return rcount;
}

static char *
uc_reg_shzone(ngx_conf_t *cf, uc_main_conf_t *ucmcf)
{
    ssize_t                        size;
    ngx_str_t                      name;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "uc_reg_shzone");

    size = UC_SHZONE_PAGE_COUNT * ngx_pagesize;
    ngx_str_set(&name, "uc_shzone");

    ucmcf->shm_zone = ngx_shared_memory_add(cf, &name, size,
                                            &ngx_http_upstream_ctl_module);
    if (ucmcf->shm_zone == NULL)
    {
        return NGX_CONF_ERROR;
    }


    ucmcf->shm_zone->init = uc_init_shzone;
    ucmcf->shm_zone->data = ucmcf;
    ucmcf->shm_zone->noreuse = 1;

    return NGX_CONF_OK;
}

static ngx_int_t
uc_init_shzone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_uint_t                     i;
    ngx_slab_pool_t                *shpool;
    uc_main_conf_t                 *ucmcf;
    uc_srv_conf_t                  *ucscf, **ucscfp;
    uc_sh_t                        *ucsh;

    ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0,
                  "uc_init_shzone");
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ucmcf = shm_zone->data;

    //alloc init space;
    ucsh = ngx_slab_calloc(shpool, sizeof(uc_sh_t));

    ucsh->number = ucmcf->upstreams.nelts;
    ucsh->last_update = ngx_current_msec;

    //alloc init conf space
    ucsh->conf = ngx_slab_calloc(shpool, sizeof(uc_sh_conf_t) * ucmcf->upstreams.nelts);
    ucscfp = (uc_srv_conf_t **)ucmcf->upstreams.elts;

    for (i = 0; i < ucmcf->upstreams.nelts; i++)
    {
        ucscf = ucscfp[i];
        ucsh->conf[i].server = ngx_slab_calloc(shpool, sizeof(uc_sh_server_t) * ucscf->upstream->servers->nelts);

    }

    shpool->data = ucsh;

    return NGX_OK;
}

static ngx_atomic_t *
uc_get_post_lock()
{
    ngx_atomic_t                   *p;
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    shpool = (ngx_slab_pool_t *) sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;
    p = &ucsh->post_lock;

    return p;
}

static ngx_pid_t
uc_get_post_process()
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;
    ngx_pid_t                      post_pid;

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_rlock(&ucsh->status_lock);
    post_pid = ucsh->post_status.post_pid;
    ngx_rwlock_unlock(&ucsh->status_lock);
    return post_pid;
}


static ngx_uint_t
uc_get_syn_conf()
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;
    ngx_uint_t                     confidx;

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;
    ngx_rwlock_rlock(&ucsh->status_lock);
    confidx = ucsh->post_status.syn_conf;
    ngx_rwlock_unlock(&ucsh->status_lock);
    return confidx;
}

static ngx_int_t
uc_new_post_id(ngx_int_t code)
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;
    ngx_uint_t                     post_id;

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;
    ngx_rwlock_wlock(&ucsh->status_lock);
    ucsh->post_status.post_id++;
    post_id = ucsh->post_status.post_id;
    ngx_rwlock_unlock(&ucsh->status_lock);
    return post_id;
}

static void
uc_get_post_status(uc_post_status_t *post_status)
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;
    ngx_rwlock_rlock(&ucsh->status_lock);
    post_status->post_id = ucsh->post_status.post_id;
    post_status->status_code = ucsh->post_status.status_code;
    post_status->r = ucsh->post_status.r;
    post_status->syn_conf = ucsh->post_status.syn_conf;
    post_status->post_pid = ucsh->post_status.post_pid;

    ngx_rwlock_unlock(&ucsh->status_lock);
}

/*
 * function:determine post status validation base post id and post status
 */
static ngx_int_t
uc_post_status_is_valid(ngx_int_t post_id, uc_post_status_t *post_status)
{
    uc_get_post_status(post_status);
    if(post_id != post_status->post_id)
    {
        return 0;
    }
    if(post_status->status_code != UI_STATUS_POST_OK)
    {
        return 0;
    }
    return 1;
}


/*
 * initialize synchronous data, set synchronous event and block the request
 */
static void
uc_syn_init(ngx_int_t post_id, ngx_uint_t confidx, ngx_http_request_t *r)
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    //init post status
    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;
    ngx_rwlock_wlock(&ucsh->status_lock);
    ucsh->post_status.status_code = UI_STATUS_POST_OK;
    ucsh->post_status.post_pid = getpid();
    ucsh->post_status.syn_conf = confidx;
    ucsh->post_status.post_id = post_id;
    ucsh->post_status.r = r;
    ngx_rwlock_unlock(&ucsh->status_lock);

    //clear old timeout timer
    if(sucmcf->timeout_ev->timer_set)
    {
        ngx_del_timer(sucmcf->timeout_ev);
    }

    //set new timer
    uc_event_data_t *ev_data;
    ev_data = (uc_event_data_t *)sucmcf->timeout_ev->data;
    ev_data->post_id = post_id;
    ngx_add_timer(sucmcf->timeout_ev, UC_WAIT_OUTTIME);

    //block request
    r->blocked++;

}

static void
uc_set_last_update()
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, sucmcf->shm_zone->shm.log, 0,
                   "uc_set_last_update");

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_wlock(&ucsh->time_lock);
    ucsh->last_update = ngx_current_msec;
    ngx_rwlock_unlock(&ucsh->time_lock);

}

static ngx_msec_t
uc_get_last_update()
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;
    ngx_msec_t t;

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_rlock(&ucsh->time_lock);
    t = ucsh->last_update;
    ngx_rwlock_unlock(&ucsh->time_lock);

    return t;
}

static ngx_int_t
uc_get_update_days()
{
    ngx_msec_t last_update, now;
    ngx_int_t days;

    last_update = uc_get_last_update();
    now = ngx_current_msec;

    days = (now - last_update) / (1000 * 3600 * 24);
    return days;
}

static void
uc_set_post_status_code(ngx_int_t code)
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_wlock(&ucsh->status_lock);
    ucsh->post_status.status_code = code;
    ngx_rwlock_unlock(&ucsh->status_lock);

}

static ngx_int_t
uc_upload_data_to_shzone(uc_sh_conf_t *conf)
{
    ngx_int_t confidx;
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, sucmcf->shm_zone->shm.log, 0,
                   "uc_upload_data_to_shzone");
    confidx = uc_get_srv_conf_index(sucmcf, &conf->host);
    if (confidx != -1)
    {

        shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
        ucsh = (uc_sh_t *)shpool->data;

        ngx_rwlock_wlock(&ucsh->conf[confidx].conf_lock);

        ucsh->conf[confidx].ip_hash = conf->ip_hash;
        ucsh->conf[confidx].keepalive = conf->keepalive;

        ngx_uint_t i;
        uc_srv_conf_t *ucscf, **ucscfp;

        ucscfp = (uc_srv_conf_t **)sucmcf->upstreams.elts;
        ucscf = (uc_srv_conf_t *)ucscfp[confidx];

        for (i = 0; i < ucscf->upstream->servers->nelts; i++)
        {
            ngx_memcpy(&ucsh->conf[confidx].server[i].server, &conf->server[i].server, sizeof(ngx_http_upstream_server_t));
        }

        ngx_rwlock_unlock(&ucsh->conf[confidx].conf_lock);
        return 0;

    }
    return -1;
}

static ngx_int_t
uc_download_data_from_shzone(ngx_uint_t confidx)
{
    ngx_slab_pool_t                *shpool;
    uc_sh_t                        *ucsh;
    ngx_uint_t i;
    uc_srv_conf_t *ucscf, **ucscfp;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, sucmcf->shm_zone->shm.log, 0,
                   "uc_download_data_from_shzone");

    shpool = (ngx_slab_pool_t *)sucmcf->shm_zone->shm.addr;
    ucsh = (uc_sh_t *)shpool->data;

    ngx_rwlock_rlock(&ucsh->conf[confidx].conf_lock);

    ucscfp = (uc_srv_conf_t **)sucmcf->upstreams.elts;
    ucscf = (uc_srv_conf_t *)ucscfp[confidx];

    ucscf->temp_conf->ip_hash = ucsh->conf[confidx].ip_hash;
    ucscf->temp_conf->keepalive = ucsh->conf[confidx].keepalive;

    for (i = 0; i < ucscf->upstream->servers->nelts; i++)
    {
        ngx_memcpy(&ucscf->temp_conf->server[i].server, &ucsh->conf[confidx].server[i].server, sizeof(ngx_http_upstream_server_t));
    }

    ngx_rwlock_unlock(&ucsh->conf[confidx].conf_lock);

    return 0;
}


static void
uc_reset_peer_init_handler(ngx_uint_t ip_hash, ngx_uint_t keepalive, uc_srv_conf_t *ucscf)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "uc_reset_peer_init_handler");

    if (ip_hash && keepalive)
    {
        ucscf->original_peer_init_handler = sucmcf->original_init_keepalive_peer;
        ucscf->kcf->original_init_peer = sucmcf->original_init_iphash_peer;
    }
    else if (ip_hash && (keepalive == 0))
    {
        ucscf->original_peer_init_handler = sucmcf->original_init_iphash_peer;
        ucscf->kcf->original_init_peer = 0;
    }
    else if (ip_hash == 0 && keepalive)
    {
        ucscf->original_peer_init_handler = sucmcf->original_init_keepalive_peer;
        ucscf->kcf->original_init_peer = ngx_http_upstream_init_round_robin_peer;
    }
    else if (ip_hash == 0 && keepalive == 0)
    {
        ucscf->original_peer_init_handler = ngx_http_upstream_init_round_robin_peer;
        ucscf->kcf->original_init_peer = 0;
    }
}

/*
 * function: the real modification of configuration
 */
static ngx_int_t
uc_apply_new_conf(ngx_uint_t confidx, ngx_log_t *log)
{
    uc_srv_conf_t *ucscf, **ucscfp;
    uc_server_t *ucsrv;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0,
                   "uc_apply_new_conf");

    ucscfp = (uc_srv_conf_t **)sucmcf->upstreams.elts;
    ucscf = (uc_srv_conf_t *)ucscfp[confidx];

    ngx_uint_t i, j;
    ucsrv = (uc_server_t *)ucscf->uc_servers->elts;
    for (i = 0; i < ucscf->uc_servers->nelts; i++)
    {

        //modify server
        ucsrv[i].server->weight = ucscf->temp_conf->server[i].server.weight;
        ucsrv[i].server->max_fails = ucscf->temp_conf->server[i].server.max_fails;
        ucsrv[i].server->fail_timeout = ucscf->temp_conf->server[i].server.fail_timeout;
        ucsrv[i].server->down = ucscf->temp_conf->server[i].server.down;

        //modify peer
        for (j = 0; j < ucsrv[i].server->naddrs; j++)
        {
            ucsrv[i].running_server[j]->weight = ucscf->temp_conf->server[i].server.weight;
            ucsrv[i].running_server[j]->max_fails = ucscf->temp_conf->server[i].server.max_fails;
            ucsrv[i].running_server[j]->fail_timeout = ucscf->temp_conf->server[i].server.fail_timeout;
            ucsrv[i].running_server[j]->down = ucscf->temp_conf->server[i].server.down;
        }

        //modify backup
        if (ucsrv[i].server->backup != ucscf->temp_conf->server[i].server.backup)
        {
            if (uc_backup_peers_switch(ucsrv[i].server, ucsrv[i].running_server, (ngx_http_upstream_rr_peers_t *)ucscf->upstream->peer.data, ucscf->uc_servers->pool) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, 0, "an error occur when switch backup");
            }
            ucsrv[i].server->backup = ucscf->temp_conf->server[i].server.backup;
        }

    }

    //modify peers
    uc_reset_peers_data(ucscf);

    ucscf->ip_hash = ucscf->temp_conf->ip_hash;

    if (ucscf->temp_conf->ip_hash)
    {
        ucscf->upstream->flags = NGX_HTTP_UPSTREAM_CREATE
                                 | NGX_HTTP_UPSTREAM_WEIGHT
                                 | NGX_HTTP_UPSTREAM_MAX_FAILS
                                 | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                                 | NGX_HTTP_UPSTREAM_DOWN;
    }

    //modify init peer handler
    uc_reset_peer_init_handler(ucscf->temp_conf->ip_hash, ucscf->temp_conf->keepalive, ucscf);

    //modify cache setting
    uc_reset_keepalive_cache(ucscf->temp_conf->keepalive, ucscf, log);
    ucscf->keepalive = ucscf->temp_conf->keepalive;

    return 0;
}

static void
uc_reset_peers_data(uc_srv_conf_t *ucscf)
{
    uc_server_t *ucsrv;
    ngx_http_upstream_rr_peers_t *peers, *peers_backup;
    ngx_uint_t i, n, w, nb, wb;

    ucsrv = (uc_server_t *)ucscf->uc_servers->elts;
    n = 0;
    w = 0;
    nb = 0;
    wb = 0;
    for (i = 0; i < ucscf->uc_servers->nelts; i++)
    {

        if (ucsrv[i].server->backup)
        {
            nb += ucsrv[i].server->naddrs;
            wb += ucsrv[i].server->naddrs * ucsrv[i].server->weight;
        }
        else
        {
            n += ucsrv[i].server->naddrs;
            w += ucsrv[i].server->naddrs * ucsrv[i].server->weight;
        }


    }

    peers = (ngx_http_upstream_rr_peers_t *)ucscf->upstream->peer.data;
    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = (w != n);
    peers->total_weight = w;

    /* backup servers */
    peers_backup = peers->next;
    if(peers_backup)
    {
        peers_backup->single = 0;
        peers_backup->number = nb;
        peers_backup->weighted = (wb != nb);
        peers_backup->total_weight = wb;
    }

}

static void
uc_reset_keepalive_cache(ngx_uint_t new_keepalive, uc_srv_conf_t *ucscf, ngx_log_t *log)
{

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0,
                   "uc_reset_keepalive_cache");

    if (new_keepalive > ucscf->kcf->max_cached)
    {
        //add cache
        ngx_uint_t delta, num;
        ngx_http_upstream_keepalive_cache_t *cache;
        delta = new_keepalive - ucscf->kcf->max_cached;

        //insert free_caches into kcf->free queue
        num = uc_queue_move(&ucscf->free_caches, &ucscf->kcf->free, delta);
        delta -= num;

        //insert new cache into kcf->free queue
        while (delta)
        {
            cache = (ngx_http_upstream_keepalive_cache_t *)ngx_array_push(ucscf->added_caches);
            cache->conf = ucscf->kcf;
            ngx_queue_insert_head(&ucscf->kcf->free, &cache->queue);
            delta--;
        }
    }
    else if (new_keepalive < ucscf->kcf->max_cached)
    {
        //subtract cache
        ngx_uint_t delta, num;

        delta = ucscf->kcf->max_cached - new_keepalive;

        //remove from kcf->free queue
        num = uc_queue_move(&ucscf->kcf->free, &ucscf->free_caches, delta);
        delta -= num;

        //remove from kcf->cache queue
        num = uc_queue_move(&ucscf->kcf->cache, &ucscf->free_caches, delta);
        delta -= num;

        if (delta > 0)
        {
            //an error occurs.
            ngx_log_error(NGX_LOG_ALERT, log, 0, "an error occur when subtract keepalive cache");
        }
    }

    ucscf->kcf->max_cached = new_keepalive;
}

static ngx_uint_t
uc_queue_move(ngx_queue_t *from, ngx_queue_t *to, ngx_uint_t number)
{
    ngx_uint_t i;
    ngx_queue_t *q, *qold;

    qold = 0;
    i = 0;
    if (i < number)
    {
        for (q = ngx_queue_head(from);
                q != ngx_queue_sentinel(from);
                q = ngx_queue_next(q))
        {
            if (qold)
            {
                ngx_queue_remove(qold);
                ngx_queue_insert_head(to, qold);
                i++;
                if (i >= number)
                {
                    break;
                }
            }
            qold = q;
        }
    }

    if (i < number)
    {
        if (qold)
        {
            ngx_queue_remove(qold);
            ngx_queue_insert_head(to, qold);

            i++;
        }
    }
    return i;
}

/*
 * switch upstream server's backup value and move some backup peers's peer to non-backup peers's link table or some non-backup peers's peer to backup peers's link table
 **/
static ngx_int_t
uc_backup_peers_switch(ngx_http_upstream_server_t *xserver, ngx_http_upstream_rr_peer_t **xpeerp, ngx_http_upstream_rr_peers_t *peers, ngx_pool_t *pool)
{

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "uc_backup_peers_switch");

    ngx_http_upstream_rr_peer_t *p;
    p = xpeerp[xserver->naddrs - 1]->next;

    if (xserver->backup)
    {
        //append to non-backup peer link
        ngx_http_upstream_rr_peers_t *peers_backup;
        ngx_http_upstream_rr_peer_t *peer, *peerold;

        peers_backup = peers->next;

        peer = peers->peer;
        if(peer == NULL)
        {
            peers->peer = xpeerp[0];
            xpeerp[xserver->naddrs - 1]->next = 0;
        }
        else
        {
            while (1)
            {
                peerold = peer;
                peer = peer->next;
                if (peer == NULL)
                {
                    peerold->next = xpeerp[0];
                    xpeerp[xserver->naddrs - 1]->next = 0;
                    break;
                }
            }
        }

        //remove from backup peer link
        if (peers_backup)
        {
            peerold = 0;
            peer = peers_backup->peer;
            while (peer)
            {
                if (peer == xpeerp[0])
                {
                    if (peerold)
                    {
                        peerold->next = p;
                    }
                    else
                    {
                        peers_backup->peer = p;
                    }
                    break;
                }
                peerold = peer;
                peer = peer->next;
            }
        }
        else
        {
            //an error occurs
            return -1;
        }
    }
    else
    {
        //append to backup peer link
        ngx_http_upstream_rr_peers_t *peers_backup;
        ngx_http_upstream_rr_peer_t *peer, *peerold;

        peers_backup = peers->next;

        if (peers_backup)
        {
            peerold = 0;
            peer = peers_backup->peer;
            if (peer == NULL)
            {
                peers_backup->peer = xpeerp[0];
                xpeerp[xserver->naddrs - 1]->next = 0;
            }
            else
            {
                while (1)
                {
                    peerold = peer;
                    peer = peer->next;
                    if (peer == NULL)
                    {
                        peerold->next = xpeerp[0];
                        xpeerp[xserver->naddrs - 1]->next = 0;
                        break;
                    }
                }
            }
        }
        else
        {
            peers->next = ngx_pcalloc(pool, sizeof(ngx_http_upstream_rr_peers_t));
            if (peers->next == NULL)
            {
                //an error occurs
                return -1;
            }
            else
            {
                peers->next->peer = xpeerp[0];
                xpeerp[xserver->naddrs - 1]->next = 0;
            }

        }

        //remove from non-backup peer link
        peer = peers->peer;
        peerold = 0;
        while (peer)
        {
            if (peer == xpeerp[0])
            {
                if (peerold)
                {
                    peerold->next = p;
                }
                else
                {
                    peers->peer = p;
                }
                break;
            }
            peerold = peer;
            peer = peer->next;
        }
    }
    return 0;
}
