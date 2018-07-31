/*
 * mod_zookeeper.h
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

/**
 * @file  mod_zookeeper.h
 * @brief ZooKeeper Module for Apache
 *
 * @defgroup MOD_ZOOKEEPER mod_zookeeper
 * @ingroup  APACHE_MODS
 * @{
 */

#ifndef MOD_ZOOKEEPER_H
#define MOD_ZOOKEEPER_H

#include "httpd.h"
#include "http_config.h"

#include "apr_optional.h"
#include "apr_thread_cond.h"
#include "apr_thread_mutex.h"

#include "zookeeper.h"


/** Function prototype for ZooKeeper watch callback functions.
 * @param handle ZooKeeper connection handle.
 * @param type ZooKeeper event type.
 * @param state ZooKeeper connection state.
 * @param path ZooKeeper node path.
 * @param context Pointer to private data.
 */

typedef void (ap_zk_watcher_t)(zhandle_t *handle, int type, int state,
                               const char *path, void *context);

typedef struct ap_zk_watch_priv_t ap_zk_watch_priv_t;

typedef struct
{
    apr_thread_mutex_t *mutex;
    apr_thread_cond_t *cond;
    int count;
    ap_zk_watcher_t *watcher;
    void *context;
    ap_zk_watch_priv_t *priv;
} ap_zk_watch_t;

typedef struct ap_zk_priv_t ap_zk_priv_t;

typedef struct
{
    const char *name;
    const char *hosts;
    int recv_timeout;
    zhandle_t *handle;
    ap_zk_priv_t *priv;
} ap_zk_t;


/**
 * Log an error from a failed ZooKeeper method.
 *
 * @param s Server on which to log error messages.
 * @param zk Shared mod_zookeeper connection structure.
 * @param ret ZooKeeper return code.
 * @param msg Error message.
 * @return APR status code derived from ZooKeeper connection status.
 */

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_zk_error,
                        (server_rec *s, ap_zk_t *zk, int ret,
                         const char *msg));

/**
 * Look up ZooKeeper connection by name.
 *
 * @param name ZooKeeper connection name.
 * @return True if connection is registered, false otherwise.
 */

APR_DECLARE_OPTIONAL_FN(int, ap_zk_lookup, (const char *name));

/**
 * Acquire shared lock and active ZooKeeper handle.
 *
 * @param s Server on which to log error messages.
 * @param name ZooKeeper connection name.
 * @param zk_ptr Location to be initialized with reference to shared
 *               mod_zookeeper connection structure.
 * @return APR status code.
 */

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_zk_acquire,
                        (server_rec *s, const char *name, ap_zk_t **zk_ptr));

/**
 * Attempt to acquire shared lock and active ZooKeeper handle.
 *
 * @param s Server on which to log error messages.
 * @param name ZooKeeper connection name.
 * @param zk_ptr Location to be initialized with reference to shared
 *               mod_zookeeper connection structure.
 * @return APR status code; APR_EBUSY if shared lock not available.
 */

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_zk_tryacquire,
                        (server_rec *s, const char *name, ap_zk_t **zk_ptr));

/**
 * Release shared lock and ZooKeeper handle.
 *
 * @param s Server on which to log error messages.
 * @param zk Shared mod_zookeeper connection structure.
 * @return APR status code.
 */

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_zk_release,
                        (server_rec *s, ap_zk_t *zk));

/**
 * ZooKeeper callback function to signal watch monitor.
 *
 * @param handle ZooKeeper connection handle.
 * @param type ZooKeeper event type.
 * @param state ZooKeeper connection state.
 * @param path ZooKeeper node path.
 * @param context An ap_zk_watch_t mod_zookeeper watch monitor structure.
 */

APR_DECLARE_OPTIONAL_FN(void, ap_zk_watcher,
                        (zhandle_t *handle, int type, int state,
                         const char *path, void *context));

/**
 * Create and initialize a watch structure and monitor.
 *
 * @param s Server on which to log error messages.
 * @param zk Shared mod_zookeeper connection structure.
 * @param watcher Optional custom watch callback function.
 * @param context Optional custom watch callback data.
 * @param watch_ptr Location to be initialized with reference to
 *                  mod_zookeeper watch monitor structure.
 * @return APR status code.
 */

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_zk_create_watch,
                        (server_rec *s, ap_zk_t *zk,
                         ap_zk_watcher_t *watcher, void *context,
                         ap_zk_watch_t **watch_ptr));

/**
 * Destroy a watch structure and monitor.
 *
 * @param s Server on which to log error messages.
 * @param watch Watch monitor structure for ZooKeeper methods.
 * @return APR status code.
 */

APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_zk_destroy_watch,
                        (server_rec *s, ap_zk_watch_t *watch));


extern module AP_MODULE_DECLARE_DATA zookeeper_module;

#endif /* MOD_ZOOKEEPER_H */

/** @} */

