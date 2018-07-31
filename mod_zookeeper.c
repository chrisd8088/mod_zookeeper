/*
 * mod_zookeeper.c
 *
 * ZooKeeper connection module for Apache httpd 2.4.x.
 *
 * Copyright 2009, 2018 Chris Darroch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mod_zookeeper.h"

#include "http_log.h"

#include "apr_hash.h"
#include "apr_lib.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_thread_rwlock.h"


#define DEFAULT_ZOOKEEPER_RECV_TIMEOUT 4000 /* milliseconds */

#define DEFAULT_ZOOKEEPER_CONN_TRIES 5


#if !APR_HAS_THREADS
#error Threads required for ZooKeeper connections
#endif


struct ap_zk_priv_t
{
    apr_pool_t *pool;
    server_rec *server;
    apr_thread_rwlock_t *rwlock;
    int invalid;
};

struct ap_zk_watch_priv_t
{
    apr_pool_t *pool;
    server_rec *server;
    ap_zk_t *zk;
};


static apr_hash_t *zk_handles;

module AP_MODULE_DECLARE_DATA zookeeper_module;


static const char *zk_hosts_cmd(cmd_parms *cmd, void *dconf,
                                const char *name, const char *hosts,
                                const char *arg)
{
    ap_zk_t *zk;
    int recv_timeout = DEFAULT_ZOOKEEPER_RECV_TIMEOUT;
    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST | NOT_IN_LIMIT);

    if (err) {
        return err;
    }

    if (apr_hash_get(zk_handles, name, APR_HASH_KEY_STRING)) {
        return apr_psprintf(cmd->pool, "non-unique connection name: %s", name);
    }

    if (arg) {
        const char *p;

        for (p = arg; *p; ++p) {
            if (!apr_isdigit(*p)) {
                return apr_psprintf(cmd->pool,
                                    "non-numeric ping timeout value: %s", arg);
            }
        }

        recv_timeout = atoi(arg);
    }

    zk = apr_pcalloc(cmd->pool, sizeof(ap_zk_t));

    zk->name = name;
    zk->hosts = hosts;
    zk->recv_timeout = recv_timeout;
    zk->priv = apr_pcalloc(cmd->pool, sizeof(ap_zk_priv_t));

    apr_hash_set(zk_handles, name, APR_HASH_KEY_STRING, zk);

    return NULL;
}

static apr_status_t ap_zk_error(server_rec *s, ap_zk_t *zk, int ret,
                                const char *msg)
{
    apr_status_t status;

    if (!s) {
        return APR_EINVAL;
    }

    if (!zk || !zk->priv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "invalid ZooKeeper connection");

        return APR_EINVAL;
    }

    if (ret == ZSYSTEMERROR) {
        status = errno;
    }
    else {
        status = APR_ECONNABORTED;

        if (ret == ZINVALIDSTATE || ret == ZCONNECTIONLOSS) {
            zk->priv->invalid = 1;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                 "%s [%s]: %s", msg, zk->name, zerror(ret));

    return status;
}

static void zk_session_watcher(zhandle_t *handle, int type, int state,
                               const char *path, void *context)
{
    if (type == ZOO_SESSION_EVENT
        && (state == ZOO_AUTH_FAILED_STATE ||
            state == ZOO_EXPIRED_SESSION_STATE)) {
        ap_zk_t *zk = (ap_zk_t *)zoo_get_context(handle);

        ap_zk_error(zk->priv->server, zk, ZINVALIDSTATE,
                    "ZooKeeper session expired or authorization failed");
    }
}

static apr_status_t zk_cleanup(void *data)
{
    ap_zk_t *zk = data;

    if (zk->handle) {
        int ret;

        ret = zookeeper_close(zk->handle);

        zk->handle = NULL;

        if (ret != ZOK) {
            return ap_zk_error(zk->priv->server, zk, ret,
                               "unable to close ZooKeeper connection");
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, zk->priv->server,
                     "closed connection to ZooKeeper [%s]", zk->name);
    }

    return APR_SUCCESS;
}

static void zk_connect(ap_zk_t *zk)
{
    int i = 0;

    while (i++ < DEFAULT_ZOOKEEPER_CONN_TRIES) {
        zk->handle = zookeeper_init(zk->hosts, zk_session_watcher,
                                    zk->recv_timeout, NULL, zk, 0);

        if (zk->handle) {
            apr_pool_cleanup_register(zk->priv->pool, zk, zk_cleanup,
                                      apr_pool_cleanup_null);

            zk->priv->invalid = 0;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS,
                         zk->priv->server,
                         "opened connection to ZooKeeper [%s]", zk->name);

            return;
        }
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, APR_TIMEUP, zk->priv->server,
                 "unable to open ZooKeeper connection [%s]", zk->name);
}

static int zk_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    zk_handles = apr_hash_make(p);

    return OK;
}

static void zk_child_init(apr_pool_t *p, server_rec *s)
{
    apr_hash_index_t *index;

    zoo_set_debug_level(0);

    for (index = apr_hash_first(p, zk_handles); index;
         index = apr_hash_next(index)) {
        ap_zk_t *zk;
        apr_status_t status;

        apr_hash_this(index, NULL, NULL, (void *)&zk);

        status = apr_pool_create(&zk->priv->pool, p);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                         "unable to create memory pool for "
                         "ZooKeeper connection [%s]", zk->name);

            continue;
        }

        zk->priv->server = s;

        status = apr_thread_rwlock_create(&zk->priv->rwlock, zk->priv->pool);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                         "unable to create lock for ZooKeeper connection [%s]",
                         zk->name);

            continue;
        }

        zk->priv->invalid = 1;

        zk_connect(zk);
    }
}

static int ap_zk_lookup(const char *name)
{
    ap_zk_t *zk;

    zk = apr_hash_get(zk_handles, name, APR_HASH_KEY_STRING);

    return zk ? 1 : 0;
}

static apr_status_t zk_release(server_rec *s, ap_zk_t *zk, const char *type)
{
    apr_status_t status;

    status = apr_thread_rwlock_unlock(zk->priv->rwlock);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "unable to release %s lock for "
                     "ZooKeeper connection [%s]", type, zk->name);
    }

    return status;
}

static apr_status_t zk_acquire(server_rec *s, const char *name,
                               ap_zk_t **zk_ptr, int try)
{
    ap_zk_t *zk;
    apr_status_t status;

    if (!s) {
        return APR_EINVAL;
    }

    if (!zk_ptr) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "invalid ZooKeeper connection pointer");

        return APR_EINVAL;
    }

    *zk_ptr = NULL;

    zk = apr_hash_get(zk_handles, name, APR_HASH_KEY_STRING);

    if (!zk) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_NOTFOUND, s,
                     "ZooKeeper connection not registered [%s]", name);

        return APR_NOTFOUND;
    }

    if (!zk->priv || !zk->priv->rwlock) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, APR_ENOLOCK, s,
                     "no lock available for ZooKeeper connection [%s]", name);

        return APR_ENOLOCK;
    }

    if (zk->priv->invalid) {
        status = apr_thread_rwlock_wrlock(zk->priv->rwlock);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                         "unable to acquire write lock for "
                         "ZooKeeper connection [%s]", name);

            return status;
        }

        if (zk->priv->invalid) {
            status = apr_pool_cleanup_run(zk->priv->pool, zk, zk_cleanup);

            if (status == APR_SUCCESS) {
                zk_connect(zk);
            }
        }

        status = zk_release(s, zk, "write");

        if (status != APR_SUCCESS) {
            return status;
        }
    }

    status = try ? apr_thread_rwlock_tryrdlock(zk->priv->rwlock)
                 : apr_thread_rwlock_rdlock(zk->priv->rwlock);

    if (status == APR_SUCCESS) {
        if (!zk->priv->invalid && zk->handle != NULL) {
            *zk_ptr = zk;
        }
        else {
            zk_release(s, zk, "read");

            status = APR_ECONNABORTED;

            ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                         "unable to initialize handle for "
                         "ZooKeeper connection [%s]", name);
        }
    }
    else if (!try || !APR_STATUS_IS_EBUSY(status)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to acquire read lock for "
                     "ZooKeeper connection [%s]", name);
    }

    return status;
}

static apr_status_t ap_zk_acquire(server_rec *s, const char *name,
                                  ap_zk_t **zk_ptr)
{
    return zk_acquire(s, name, zk_ptr, 0);
}

static apr_status_t ap_zk_tryacquire(server_rec *s, const char *name,
                                     ap_zk_t **zk_ptr)
{
    return zk_acquire(s, name, zk_ptr, 1);
}

static apr_status_t ap_zk_release(server_rec *s, ap_zk_t *zk)
{
    if (!s) {
        return APR_EINVAL;
    }

    if (!zk || !zk->priv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "invalid ZooKeeper connection");

        return APR_EINVAL;
    }

    if (!zk->priv->rwlock) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, APR_ENOLOCK, s,
                     "no lock available for ZooKeeper connection [%s]",
                     zk->name);

        return APR_ENOLOCK;
    }

    return zk_release(s, zk, "read");
}

static void ap_zk_watcher(zhandle_t *handle, int type, int state,
                          const char *path, void *context)
{
    ap_zk_watch_t *watch = (ap_zk_watch_t *)context;
    server_rec *s = watch->priv->server;
    const char *name = watch->priv->zk->name;
    int count;
    apr_status_t status;

    status = apr_thread_mutex_lock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to acquire watch mutex for "
                     "ZooKeeper connection [%s]", name);

        return;
    }

    --watch->count;

    status = apr_thread_cond_broadcast(watch->cond);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to signal watch condition variable for "
                     "ZooKeeper connection [%s]", name);
    }

    status = apr_thread_mutex_unlock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to release watch mutex for "
                     "ZooKeeper connection [%s]", name);

        return;
    }

    if (watch->watcher) {
        watch->watcher(handle, type, state, path, watch->context);
    }

    status = apr_thread_mutex_lock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to acquire watch mutex for "
                     "ZooKeeper connection [%s]", name);

        return;
    }

    count = --watch->count;

    status = apr_thread_mutex_unlock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to release watch mutex for "
                     "ZooKeeper connection [%s]", name);
    }

    /* Only safe to access watch structure now if we made final decrement. */

    if (count >= 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, s,
                     "unexpected watch count %d for "
                     "ZooKeeper connection [%s]", count, name);
    }

    if (count < -1) {
        apr_pool_destroy(watch->priv->pool);
    }

    return;
}

static apr_status_t ap_zk_create_watch(server_rec *s, ap_zk_t *zk,
                                       ap_zk_watcher_t *watcher,
                                       void *context,
                                       ap_zk_watch_t **watch_ptr)
{
    apr_pool_t *pool;
    ap_zk_watch_t *new_watch;
    apr_status_t status;

    if (!s) {
        return APR_EINVAL;
    }

    if (!zk || !zk->priv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "invalid ZooKeeper connection");

        return APR_EINVAL;
    }

    if (!watch_ptr) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "invalid ZooKeeper watch pointer");

        return APR_EINVAL;
    }

    *watch_ptr = NULL;

    status = apr_pool_create(&pool, zk->priv->pool);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "unable to create watch memory pool for "
                     "ZooKeeper connection [%s]", zk->name);

        return status;
    }

    new_watch = apr_pcalloc(pool, sizeof(ap_zk_watch_t));

    status = apr_thread_mutex_create(&new_watch->mutex,
                                     APR_THREAD_MUTEX_DEFAULT, pool);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "unable to create watch mutex for "
                     "ZooKeeper connection [%s]", zk->name);

        apr_pool_destroy(pool);

        return status;
    }

    status = apr_thread_cond_create(&new_watch->cond, pool);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, status, s,
                     "unable to create watch condition variable for "
                     "ZooKeeper connection [%s]", zk->name);

        apr_pool_destroy(pool);

        return status;
    }

    new_watch->count = 1;

    if (watcher) {
        new_watch->watcher = watcher;

        if (context) {
            new_watch->context = context;
        }
    }

    new_watch->priv = apr_pcalloc(pool, sizeof(ap_zk_watch_priv_t));

    new_watch->priv->pool = pool;
    new_watch->priv->server = s;
    new_watch->priv->zk = zk;

    *watch_ptr = new_watch;

    return APR_SUCCESS;
}

static apr_status_t ap_zk_destroy_watch(server_rec *s, ap_zk_watch_t *watch)
{
    const char *name;
    int count;
    apr_status_t status;

    if (!s) {
        return APR_EINVAL;
    }

    if (!watch || !watch->priv || !watch->priv->zk) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "invalid watch monitor");

        return APR_EINVAL;
    }

    name = watch->priv->zk->name;

    status = apr_thread_mutex_lock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to acquire watch mutex for "
                     "ZooKeeper connection [%s]", watch->priv->zk->name);

        return status;
    }

    count = --watch->count;

    status = apr_thread_mutex_unlock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "unable to release watch mutex for "
                     "ZooKeeper connection [%s]", watch->priv->zk->name);

        return status;
    }

    /* Only safe to access watch structure now if we made final decrement. */

    if (count >= 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, APR_EGENERAL, s,
                     "unexpected watch count %d for "
                     "ZooKeeper connection [%s]", count, name);
    }

    if (count < -1) {
        apr_pool_destroy(watch->priv->pool);
    }

    return APR_SUCCESS;
}

static const command_rec zk_cmds[] = {
    AP_INIT_TAKE23("ZKCluster", zk_hosts_cmd, NULL, RSRC_CONF,
                   "ZooKeeper connection name, hosts, and timeout"),
    {NULL}
};

static void zk_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(zk_pre_config, NULL, NULL,
                       APR_HOOK_MIDDLE);
    ap_hook_child_init(zk_child_init, NULL, NULL,
                       APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(ap_zk_error);
    APR_REGISTER_OPTIONAL_FN(ap_zk_lookup);
    APR_REGISTER_OPTIONAL_FN(ap_zk_acquire);
    APR_REGISTER_OPTIONAL_FN(ap_zk_tryacquire);
    APR_REGISTER_OPTIONAL_FN(ap_zk_release);
    APR_REGISTER_OPTIONAL_FN(ap_zk_watcher);
    APR_REGISTER_OPTIONAL_FN(ap_zk_create_watch);
    APR_REGISTER_OPTIONAL_FN(ap_zk_destroy_watch);
}

AP_DECLARE_MODULE(zookeeper) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    zk_cmds,
    zk_hooks
};

