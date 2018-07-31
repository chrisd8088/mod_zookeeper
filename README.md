# mod_zookeeper


## Apache ZooKeeper connection module for Apache httpd

The mod_zookeeper module for the Apache [httpd](http://httpd.apache.org)
2.4.x Web server maintains a set of connection handles to one or more Apache
[ZooKeeper](http://zookeeper.apache.org) clusters.

These connection handles may be utilized by additional httpd modules
to create, retrieve, and monitor (watch) ZooKeeper nodes.

Each httpd child process maintains a connection to each ZooKeeper
cluster specified in the httpd configuration files using the
`ZKCluster` directive.


### Building and Installing

To build mod_zookeeper, use of the
`[apxs](https://httpd.apache.org/docs/2.4/programs/apxs.html)` script
(as provided with most httpd installations) is recommended.

The location of the ZooKeeper C include and multi-threaded library files,
`zookeeper.c` and `libzookeeper_mt.so` respectively, may be specified
using the `-I`, `-L`, and `-l` options, unless they are already in your
standard build paths:

    apxs -c -Wall \
        -I/path/to/zk/include -L/path/to/zk/lib -lzookeeper_mt mod_zookeeper.c

The `-A` option to the installation `apxs` command will add a
commented-out `LoadModule` directive to your httpd.conf configuration file;
use `-a` instead if you prefer an uncommented `LoadModule` directive:

    apxs -i -A mod_zookeeper.la

Note that mod_zookeeper requires that OS threads be available through
the Apache Portable Runtime ([APR](http://apr.apache.org)) library
used with httpd.  The httpd MPM does not need to be multi-threaded
(i.e., the prefork MPM is fine) but thread support must be available as
each httpd child process will contain several native ZooKeeper client
threads, such as the I/O thread and the event processing thread.


### Configuration

A `LoadModule` directive must be present in the httpd configuration
files in order to dynamically load the compiled mod_zookeeper module at runtime:

    LoadModule zk_module modules/mod_zookeeper.so

Each `ZKCluster` directive must provide a unique name for the ZooKeeper
cluster (i.e., unique within the httpd configuration) and also list the
available ZooKeeper hosts within that cluster, any one of which may be
used by the `mod_zookeeper` client when connecting to the cluster.

An optional receive timeout value, in milliseconds, may also be provided;
the ZooKeeper client will use this as the session timeout value when
determining if a connection has been lost.  If no receive timeout value
is configured, mod_zookeeper defaults to 4000 ms (4 seconds).

ZooKeeper hosts should be identified using a comma-separated list of
host:port pairs, followed by the timeout value, if any.  For example:

    ZKCluster main_cluster zkhost1:2181,zkhost2:2181,zkhost3:2181
    ZKCluster test_cluster localhost:2181 1000


### API Usage

The mod_zookeeper API is provided to other httpd modules via the use of APR
optional functions; these may be "imported" into other modules as needed.

Typically this would be done as follows, with at least these four
functions "imported" for use:

```c
#include "mod_zookeeper.h"
#include "http_log.h"

static apr_status_t (*zk_error_fn)(server_rec *s, ap_zk_t *zk, int ret,
                                   const char *msg) = NULL;
static int (*zk_lookup_fn)(const char *name) = NULL;
static apr_status_t (*zk_acquire_fn)(server_rec *s, const char *name,
                                     ap_zk_t **zk) = NULL;
static apr_status_t (*zk_release_fn)(server_rec *s, ap_zk_t *zk) = NULL;

static void example(server_rec *s)
{
    char *name = "main_cluster";
    ap_zk_t *zk;
    apr_status_t status;
    int ret;

    /* import mod_zookeeper function on first initialization */
    if (!zk_error_fn) {
        zk_error_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_error);

        if (!zk_error_fn) {
            ap_log_error(APLOG_MARK, APLOG_ERR, APR_ESYMNOTFOUND, s,
                         "mod_zookeeper not loaded");
            return;
        }

        zk_lookup_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_lookup);
        zk_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_acquire);
        zk_release_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_release);
    }

    /* check for mod_zookeeper ZKCluster configuration */
    if (!zk_lookup_fn(name)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, APR_EINVAL, s,
                     "mod_zookeeper config for '%s' not found", name);
        return;
    }

    /* acquire shared mod_zookeeper connection lock and handle */
    status = zk_acquire_fn(s, name, &zk);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "mod_zookeeper connection not acquired");
        return;
    }

    // utilize ZooKeeper native C API methods as desired, for example:

    ret = zoo_exists(zk->handle, "/", 0, NULL);

    if (ret != ZOK && ret != ZNONODE) {
        status = zk_error_fn(s, zk, ret, "zoo_exists() failed");

        if (APR_STATUS_IS_ECONNABORTED(status)) {
            goto release;
        }
    }

    // see following sample code for watch monitor example usage:
    // status = watch_example(s, zk);

    // ...

release:
    /* release shared mod_zookeeper connection lock and handle */
    status = zk_release_fn(s, zk);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "mod_zookeeper connection not released");
    }
}
```

The `ap_zk_acquire()` (blocking) or `ap_zk_tryacquire()` (non-blocking)
functions must be used to retrieve an open connection handle from
mod_zookeeper.  They also, internal to mod_zookeeper, acquire a shared
read lock on the connection.

The use of a shared lock permits mod_zookeeper to detect when it is safe
to drop a failed connection and attempt to re-establish a new one with the
ZooKeeper cluster.

In general, the preferred usage pattern is for mod_zookeeper clients to
to execute an acquire-use-release cycle in a constrained time period,
e.g., within a single HTTP response processing sequence, so as to
ensure that the shared lock is not held indefinitely, which would prevent
mod_zookeeper from dropping a failed connection.


#### Watch Monitor Usage

The majority of ZooKeeper C API methods accept a callback function
which will be invoked asynchronously by the event processing thread
when an event occurs on the given watched node.

Clients of mod_zookeeper can manage these callbacks independently
without use of the mod_zookeeper watch monitor functions.  However,
clients must be aware of the context in which the callback function
runs, i.e., in a server-lifetime thread and one which should not
access per-request data structures such as `request_rec` (unless
specific steps are taken to ensure these request-lifetime variables
are guaranteed to exist at the time the callback executes, which may
be difficult to achieve).

Therefore mod_zookeeper provides a set of watch monitor functions
which create a small server-lifetime memory pool for each watch monitor
and allocate the watch monitor's data structures from it.  The watch
monitor includes a semaphore `count` variable, an APR condition variable
`cond` and an associated `mutex`.  When passed to a ZooKeeper C API
function as the watcher context, along with the `ap_zk_watcher()`
function as the watcher, clients may then expect a signal broadcast via
the `cond` condition variable when the next event occurs on the
watched node.

Clients should use the `ap_zk_create_watch()` function to allocate an
`ap_zk_watch_t` structure, and then pass this structure as the
`watcherCtx` argument to the desired ZooKeeper C API function along
with the `ap_zk_watcher()` function as the `watcher` argument.

Clients may then wait on the condition variable in a loop, after
acquiring the mutex, as shown in the example code below.  Once the
event has been received or the watch is abandoned, clients should call
`ap_zk_destroy_watch()` to decrement the semaphore and, if appropriate,
deallocate the watch monitor structure and destroy its private memory
pool.  If the watcher is still active at this point (i.e., no event
has been received), deallocation will be performed by the watcher
when it eventually executes within the ZooKeeper event processing thread.

It is not necessary for clients to provide a custom callback function,
but if desired, they may do so by setting the `watcher` member of
the `ap_zk_watch_t` structure; otherwise, this should be NULL.
The `context` member may also be set to reference a private data context
for the client's custom callback.

The following sample code continues the example from above:

```c
static void (*zk_watcher_fn)(zhandle_t *handle, int type, int state,
                             const char *path, void *context) = NULL;
static apr_status_t (*zk_create_watch_fn)(server_rec *s, ap_zk_t *zk,
                                          ap_zk_watcher_t *watcher,
                                          void *context,
                                          ap_zk_watch_t **watch_ptr) = NULL;
static apr_status_t (*zk_destroy_watch_fn)(server_rec *s,
                                           ap_zk_watch_t *watch) = NULL;

static apr_status_t watch_example(server_rec *s, ap_zk_t *zk)
{
    ap_zk_watch_t *watch;
    apr_status_t status;
    int ret, event = 0;

    /* import mod_zookeeper function on first initialization */
    if (!zk_watcher_fn) {
        zk_watcher_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_watcher);
        zk_create_watch_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_create_watch);
        zk_destroy_watch_fn = APR_RETRIEVE_OPTIONAL_FN(ap_zk_destroy_watch);
    }

    /* create watch monitor structure without custom callback function */
    status = zk_create_watch_fn(s, zk, NULL, NULL, &watch);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "mod_zookeeper watch monitor not created");
        return status;
    }

    /* test "/watch/1" ZooKeeper node and set watch in ZooKeeper cluster */
    ret = zoo_wexists(zk->handle, "/watch/1", zk_watcher_fn, watch, NULL);

    if (ret != ZOK) {
        if (ret == ZNONODE) {
            status = APR_NOTFOUND;

            ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                         "/watch1 ZooKeeper node does not exist");
        }
        else {
            status = zk_error_fn(s, zk, ret, "zoo_wexists() failed");
        }

        goto destroy;
    }

    /* acquire watch monitor mutex */
    status = apr_thread_mutex_lock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "mod_zookeeper watch monitor mutex not locked");

        goto destroy;
    }

    /* wait for event on "/watch/1" ZooKeeper node */
    while (watch->count > 0) {
        status = apr_thread_cond_wait(watch->cond, watch->mutex);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                         "mod_zookeeper watch monitor condition wait failed");

            goto unlock;
        }
    }

    event = 1;

unlock:
    /* release watch monitor mutex */
    status = apr_thread_mutex_unlock(watch->mutex);

    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                     "mod_zookeeper watch monitor mutex not unlocked");
    }

destroy:
    /* destroy watch monitor structure or mark for deallocation by watcher */
    {
        apr_status_t status2;

        status2 = zk_destroy_watch_fn(s, watch);

        if (status2 != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, status2, s,
                         "mod_zookeeper watch monitor not destroyed");
        }

        if (status == APR_SUCCESS) {
            status = status2;
        }
    }

    if (event) {
        // ...
    }

    return status;
}
```


### API Types

Type | Description
---- | -----------
[ap_zk_t](#ap_zk_t) | Shared per-cluster mod_zookeeper connection structure
[ap_zk_watch_t](#ap_zk_watch_t) | Per-client mod_zookeeper watch structure
[ap_zk_watcher_t](#ap_zk_watcher_t) | Watch callback function prototype


#### ap_zk_t

For each ZooKeeper cluster defined by a ZKCluster mod_zookeeper configuration
directive, one `ap_zk_t` structure is shared by all mod_zookeeper clients
of that cluster (within a given httpd process).  Clients pass the `handle`
member to ZooKeeper C API methods such as `zoo_get()`, `zoo_set_watcher()`,
etc.

Note that ZooKeeper's C API is thread-safe and so the `handle` member
of the `ap_zk_t` structure may be utilized by multiple threads within
an httpd process without explicit concurrency control.

```c
typedef struct
{
    const char *name;
    const char *hosts;
    int recv_timeout;
    zhandle_t *handle;
    ap_zk_priv_t *priv;
} ap_zk_t;
```

- Members:
  - `const char *name` - ZooKeeper connection name.
  - `const char *hosts` - Comma-separated list of ZooKeeper host:port pairs.
  - `int recv_timeout` - ZooKeeper receive timeout value, in milliseconds.
  - `zhandle_t *handle` - ZooKeeper connection handle.
  - `ap_zk_priv_t *priv` - Internal mod_zookeeper connection structure.


#### ap_zk_watch_t

In order to receive notifications from ZooKeeper when events of interest
occur on a node, clients may establish watches on specific nodes and events.
Many ZooKeeper C API methods accept a `watcher_fn` watch callback argument
and a `void*` watch callback context argument.

Clients of mod_zookeeper may choose to use the `ap_zk_watch_t` structure,
which should be initialized by `ap_zk_create_watch()`, as the watch
callback context argument to ZooKeeper C API methods.  The `ap_zk_watch_t`
structure provides a thread-safe APR condition variable and associated
mutex and count members.  The `cond` condition variable member of
`ap_zk_watch_t` may then be monitored by mod_zookeeper clients using
`apr_thread_cond_wait()` or `apr_thread_cond_timedwait()`.

If non-NULL, the client function pointed to by `watcher` will be
dispatched within the ZooKeeper C API's processing thread, after the
condition variable has been signalled.  The `context` member of
`ap_zk_watch_t` will be passed to the `watcher` callback function.

```c
typedef struct
{
    apr_thread_mutex_t *mutex;
    apr_thread_cond_t *cond;
    int count;
    ap_zk_watcher_t *watcher;
    void *context;
    ap_zk_watch_priv_t *priv;
} ap_zk_watch_t;
```

- Members:
  - `apr_thread_mutex_t *mutex` - Mutex for watch condition variable.
  - `apr_thread_cond_t *cond` - Watch condition variable for reference count.
  - `int count` - Watch reference count.
  - `ap_zk_watcher_t *watcher` - Optional client watch callback function.
  - `void *context` - Optional client private watch callback data.
  - `ap_zk_watch_priv_t *priv` - Internal mod_zookeeper watch structure.


#### ap_zk_watcher_t

Clients of mod_zookeeper which establish watches on ZooKeeper nodes
using `ap_zk_create_watch()` may provide a custom callback function
to be executed by ZooKeeper C API's event processing thread.

Clients are responsible for ensuring that their custom callback functions
do not reference any thread-local data which might go out of scope
during execution; in particular, per-request httpd structures such as
`request_rec *r` should not be accessed within the callback function,
only httpd process globals such as `server_rec *s`, which may be passed
via the client-defined `context` argument.

Note that he `ap_zk_watcher_t` function prototype has arguments identical
to those of the `watcher_fn` prototype of the ZooKeeper C API.

```c
typedef void (ap_zk_watcher_t)(zhandle_t *handle, int type, int state,
                               const char *path, void *context);
```

- Arguments:
  - `zhandle_t *handle` - ZooKeeper connection handle.
  - `int type` - ZooKeeper event type.
  - `int state` - ZooKeeper connection state.
  - `const char *path` - ZooKeeper node path.
  - `void *context` - Client private callback data.


### API Methods

Function | Description
-------- | -----------
[ap_zk_acquire](#ap_zk_acquire) | Acquire shared lock and active ZooKeeper handle
[ap_zk_tryacquire](#ap_zk_tryacquire) | Attempt to acquire shared lock and active ZooKeeper handle
[ap_zk_release](#ap_zk_release) | Release shared lock and ZooKeeper handle
[ap_zk_lookup](#ap_zk_lookup) | Check if ZooKeeper connection is registered
[ap_zk_error](#ap_zk_error) | Log an error from a failed ZooKeeper method
[ap_zk_watcher](#ap_zk_watcher) | ZooKeeper callback function to signal watch monitor
[ap_zk_create_watch](#ap_zk_create_watch) | Initialize mod_zookeeper watch monitor
[ap_zk_destroy_watch](#ap_zk_destroy_watch) | Destroy mod_zookeeper watch monitor


#### ap_zk_acquire

Acquire a mod_zookeeper shared connection lock and an active
ZooKeeper connection handle.  Blocks until the lock is acquired, then
attempts to initialize a ZooKeeper connection handle for the cluster,
unless an active one already exists.  If no connection handle exists or
can be initialized, the lock is released and `APR_ECONNABORTED` is returned.

On success, the location addressed by the `zk_ptr` argument will be set
to point to a previously allocated `ap_zk_t` structure; otherwise, it
will be set to NULL.  The `ap_zk_t` structure is shared by all threads
connecting to the same ZooKeeper cluster.  Callers should not modify or
free this structure, but may read its contents.

**NOTE** - Do not call directly; call indirectly through function pointer
initialized using `APR_RETRIEVE_OPTIONAL_FN(ap_zk_acquire)`.


```c
apr_status_t ap_zk_acquire(server_rec *s,
                           const char *name,
                           ap_zk_t **zk_ptr)
```

- Arguments:
  - `server_rec *s` - Apache httpd server configuration on which to log error messages.
  - `const char *name` - ZooKeeper connection name.
  - `ap_zk_t **zk_ptr` - Location to be initialized with reference to shared mod_zookeeper connection structure.
- Return:
  - `apr_status_t` - APR status code:
    - `APR_SUCCESS`
    - `APR_ECONNABORTED` - ZooKeeper handle could not be initialized.
    - `APR_EINVAL` - Invalid arguments.
    - `APR_ENOLOCK` - Shared lock does not exist.
    - `APR_NOTFOUND` - Connection name not found.
    - other - OS `errno` error code.


#### ap_zk_tryacquire

Attempt to acquire a mod_zookeeper shared connection lock and an active
ZooKeeper connection handle.  If the lock is available, it is acquired;
otherwise `APR_EBUSY` is returned immediately.  Once the lock is acquired,
attempts to initialize a ZooKeeper connection handle for the cluster,
unless an active one already exists.  If no connection handle exists or
can be initialized, the lock is released and `APR_ECONNABORTED` is returned.

On success, the location addressed by the `zk_ptr` argument will be set
to point to a previously allocated `ap_zk_t` structure; otherwise, it
will be set to NULL.  The `ap_zk_t` structure is shared by all threads
connecting to the same ZooKeeper cluster.  Callers should not modify or
free this structure, but may read its contents.

**NOTE** - Do not call directly; call indirectly through function pointer
initialized using `APR_RETRIEVE_OPTIONAL_FN(ap_zk_tryacquire)`.


```c
apr_status_t ap_zk_tryacquire(server_rec *s,
                              const char *name,
                              ap_zk_t **zk_ptr)
```

- Arguments:
  - `server_rec *s` - Apache httpd server configuration on which to log error messages.
  - `const char *name` - ZooKeeper connection name.
  - `ap_zk_t **zk_ptr` - Location to be initialized with reference to shared mod_zookeeper connection structure.
- Return:
  - `apr_status_t` - APR status code:
    - `APR_SUCCESS`
    - `APR_EBUSY` - Unable to acquire shared lock.
    - `APR_ECONNABORTED` - ZooKeeper handle could not be initialized.
    - `APR_EINVAL` - Invalid arguments.
    - `APR_ENOLOCK` - Shared lock does not exist.
    - `APR_NOTFOUND` - Connection name not found.
    - other - OS `errno` error code.


#### ap_zk_release

Release a mod_zookeeper shared connection lock and associated
ZooKeeper connection handle.

**NOTE** - Do not call directly; call indirectly through function pointer
initialized using `APR_RETRIEVE_OPTIONAL_FN(ap_zk_release)`.


```c
apr_status_t ap_zk_release(server_rec *s,
                           ap_zk_t *zk)
```

- Arguments:
  - `server_rec *s` - Apache httpd server configuration on which to log error messages.
  - `ap_zk_t *zk` - Reference to shared mod_zookeeper connection structure.
- Return:
  - `apr_status_t` - APR status code:
    - `APR_SUCCESS`
    - `APR_EINVAL` - Invalid arguments.
    - `APR_ENOLOCK` - Shared lock does not exist.
    - other - OS `errno` error code.


#### ap_zk_lookup

Determine if a ZooKeeper cluster is registered in the mod_zookeeper
configuration.

May be utilized in other httpd modules' configuration code to validate
a connection name before invoking `ap_zk_acquire()` or `ap_zk_tryacquire()`.

```c
int ap_zk_lookup(const char *name)
```

- Arguments:
  - `const char *name` - ZooKeeper connection name.
- Return:
  - `int` - True (non-zero) if the connection is registered, otherwise
            false (zero).


#### ap_zk_error

Log an httpd server error after a failed ZooKeeper method.  The
return value from the ZooKeeper operation should be passed in the
`ret` argument.

If the ZooKeeper error code is either `ZINVALIDSTATE` or `ZCONNECTIONLOSS`,
`ap_zk_error()` will return `APR_ECONNABORTED` after internally marking
the ZooKeeper connection handle as failed.

Clients of mod_zookeeper should test the return from `ap_zk_error()` with
`APR_STATUS_IS_ECONNABORTED()` and if true, release and attempt to
re-acquire the shared mod_zookeeper connection using `ap_zk_release()`
and either `ap_zk_acquire()` or `ap_zk_tryacquire()`.  See the sample code
in [API Usage](#api-usage) for a simple example.

```c
apr_status_t ap_zk_error(server_rec *s,
                         ap_zk_t *zk,
                         int ret,
                         const char *msg)
```

- Arguments:
  - `server_rec *s` - Apache httpd server configuration on which to log error messages.
  - `ap_zk_t *zk` - Reference to shared mod_zookeeper connection structure.
  - `int ret` - Error return code from ZooKeeper failed method.
  - `const char *msg` - Error message to be logged in httpd server log.
- Return:
  - `apr_status_t` - APR status code:
    - `APR_ECONNABORTED` - ZooKeeper connection lost or invalid.
    - `APR_EINVAL` - Invalid arguments.
    - other - OS `errno` error code.


#### ap_zk_watcher

Clients which wish to make use of an APR condition variable and
mod_zookeeper watch monitor to be notified of ZooKeeper events
should pass the `ap_zk_watcher()` function as their designated
callback function to ZooKeeper C API methods which accept a callback.

**NOTE** - Do not call directly; pass the function pointer
initialized using `APR_RETRIEVE_OPTIONAL_FN(ap_zk_watcher)` to
ZooKeeper C API methods as their `watcher_fn watcher` argument,
in conjunction with an initialized `ap_zk_watch_t` structure
as the `void* watcherCtx` argument.

```c
void ap_zk_watcher(zhandle_t *handle,
                   int type,
                   int state,
                   const char *path,
                   void *context)
```

- Arguments:
  - `zhandle_t *handle` - ZooKeeper connection handle.
  - `int type` - ZooKeeper event type.
  - `int state` - ZooKeeper connection state.
  - `const char *path` - ZooKeeper node path.
  - `void *context` - Client private callback data; expected to be an `ap_zk_watch_t` structure.


#### ap_zk_create_watch

Create a mod_zookeeper watch monitor structure and associated
memory pool.

On success, the location addressed by the `watch_ptr` argument will be set
to point to a newly allocated `ap_zk_watch_t` structure; otherwise, it
will be set to NULL.

Once initialized, the `ap_zk_watch_t` structure should be utilized
in conjunction with the `ap_zk_watcher()` callback function.  When the
`ap_zk_watcher` function is passed as the `watcher` argument to any
ZooKeeper C API method which accepts a watch callback (e.g.,
`zoo_exists()` or `zoo_wget()`, etc.), an initialized `ap_zk_watch_t`
structure must be passed as the `watcherCtx` context data.

Clients may choose to further define their own custom callback function,
which will be invoked by `ap_zk_watcher()` once the watch monitor
signal has been broadcast.  Such custom callbacks may be passed in the
`watcher` argument to `ap_zk_create_watch()`, along with custom
callback data in the `context` argument.  If the `watcher` argument is
NULL, no custom callback will be invoked in `ap_zk_watcher()`.

**NOTE** - Do not call directly; call indirectly through function pointer
initialized using `APR_RETRIEVE_OPTIONAL_FN(ap_zk_create_watch)`.


```c
apr_status_t ap_zk_create_watch(server_rec *s,
                                ap_zk_t *zk,
                                ap_zk_watcher_t *watcher,
                                void *context,
                                ap_zk_watch_t **watch_ptr)
```

- Arguments:
  - `server_rec *s` - Apache httpd server configuration on which to log error messages.
  - `ap_zk_t *zk` - Reference to shared mod_zookeeper connection structure.
  - `ap_zk_watcher_t *watcher` - Optional client watch callback function.
  - `void *context` - Optional client private watch callback data.
  - `ap_zk_watch_t **watch_ptr` - Location to be initialized with reference to mod_zookeeper watch monitor structure.
- Return:
  - `apr_status_t` - APR status code:
    - `APR_SUCCESS`
    - `APR_EINVAL` - Invalid arguments.
    - other - OS `errno` error code.


#### ap_zk_destroy_watch

Destroy a mod_zookeeper watch monitor structure and associated
memory pool.  If the watch monitor is still in use by another thread
(specifically the event processing thread of the ZooKeeper C API),
the watch monitor structure will be deallocated by the event callback
instead.

**NOTE** - Do not call directly; call indirectly through function pointer
initialized using `APR_RETRIEVE_OPTIONAL_FN(ap_zk_destroy_watch)`.


```c
apr_status_t ap_zk_destroy_watch(server_rec *s,
                                 ap_zk_watch_t *watch)
```

- Arguments:
  - `server_rec *s` - Apache httpd server configuration on which to log error messages.
  - `ap_zk_watch_t *watch` - Reference to mod_zookeeper watch monitor structure.
- Return:
  - `apr_status_t` - APR status code:
    - `APR_SUCCESS`
    - `APR_EINVAL` - Invalid arguments.
    - other - OS `errno` error code.

