/*
 * Licensed Materials - Property of IBM
 * (C) Copyright IBM Corp. 2013  All Rights Reserved
 * US Government Users Restricted Rights - 
 * Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp. 
 */

#ifndef _WRT_DECODER_API_H
#define _WRT_DECODER_API_H

#include <stdlib.h>

#ifndef _WIN32
#  include <inttypes.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Basic data types. */
typedef char             wrt_int8_t;
typedef unsigned char    wrt_uint8_t;
typedef short            wrt_int16_t;
typedef unsigned short   wrt_uint16_t;
typedef int              wrt_int32_t;
typedef unsigned int     wrt_uint32_t;
#ifdef _WIN32
typedef __int64          wrt_int64_t;
typedef unsigned __int64 wrt_uint64_t;
#else
typedef int64_t          wrt_int64_t;
typedef uint64_t         wrt_uint64_t;
#endif

/* Metrics. */
typedef enum wrt_metric_type
{
    WRT_METRIC_INVALID,
    WRT_METRIC_INT8,
    WRT_METRIC_INT16,
    WRT_METRIC_INT32,
    WRT_METRIC_INT64,
    WRT_METRIC_UINT8,
    WRT_METRIC_UINT16,
    WRT_METRIC_UINT32,
    WRT_METRIC_UINT64,

    /* Leave me last. */
    WRT_METRIC_TYPE_COUNT
} wrt_metric_type_t;

/**
 * wrt_metric_id_t is a unique numeric ID for a metric.
 * Zero values are invalid.
 */
typedef wrt_uint32_t wrt_metric_id_t;

typedef union wrt_metric_value
{
    wrt_int8_t   i8;
    wrt_int16_t  i16;
    wrt_int32_t  i32;
    wrt_int64_t  i64;
    wrt_uint8_t  u8;
    wrt_uint16_t u16;
    wrt_uint32_t u32;
    wrt_uint64_t u64;
} wrt_metric_value_t;

/* Context. */
typedef enum wrt_context_type
{
    WRT_CONTEXT_INVALID,
    WRT_CONTEXT_INT8,
    WRT_CONTEXT_INT16,
    WRT_CONTEXT_INT32,
    WRT_CONTEXT_INT64,
    WRT_CONTEXT_UINT8,
    WRT_CONTEXT_UINT16,
    WRT_CONTEXT_UINT32,
    WRT_CONTEXT_UINT64,
    WRT_CONTEXT_STRING,
    WRT_CONTEXT_IPV4, /* struct in_addr */

    /* Leave me last. */
    WRT_CONTEXT_TYPE_COUNT
} wrt_context_type_t;

/**
 * wrt_context_id_t is a unique numeric ID for a context name.
 * Zero values are invalid.
 */
typedef wrt_uint32_t wrt_context_id_t;

/* API status codes. */
typedef enum wrt_api_status
{
    WRT_API_STATUS_OK = 0,

    WRT_API_STATUS_ERROR,    /* Generic error */
    WRT_API_STATUS_NOMEM,    /* Out of memory */
    WRT_API_STATUS_BADCFG,   /* Bad configuration */
    WRT_API_STATUS_BADARGS,  /* Bad API call arguments */
    WRT_API_STATUS_BADSTATE, /* API called in an invalid state */
    WRT_API_STATUS_ABORT,    /* Session should be aborted */
    WRT_API_STATUS_NODATA,   /* No data available */

    WRT_API_STATUS_COUNT
} wrt_api_status_t;

/* Log levels */
typedef enum wrt_api_log_level
{
    WRT_API_LOG_ERROR = 0,
    WRT_API_LOG_INFO  = 1,
    WRT_API_LOG_DEBUG = 2,
    WRT_API_LOG_LEVEL_COUNT
} wrt_api_log_level_t;

/**
 * wrt_api_log_handle_t is a handle for use in the logging API.
 */
typedef void* wrt_api_log_handle_t;

/**
 * wrt_api_session_t is an opaque structure that is passed to each invocation of
 * wrt_module_t.process, to enable association of user data with a session.
 */
typedef void* wrt_api_session_t;

/**
 * wrt_api_data_t is an opaque structure that is passed to each invocation of
 * wrt_module_t.process, containing payload, context, and metrics.
 */
typedef void* wrt_api_data_t;

/**
 * wrt_api_data_destructor_t is a function pointer type for
 * destructor functions associated with user-data set in
 * a session using the set_key API.
 */
typedef void (*wrt_api_data_destructor_t)(wrt_api_session_t session, void *data);

/**
 * WRT module API function pointers.
 */
typedef struct wrt_module_api
{
    /**
     * get_metric obtains the value of a specified metric, with an ID
     * registered during module initialisation.
     */
    wrt_api_status_t (*get_metric)(wrt_api_data_t data,
                                   wrt_metric_id_t id,
                                   wrt_metric_type_t *type,
                                   wrt_metric_value_t *value);

    /**
     * set_metric sets the value of a specified metric, with an ID
     * registered during module initialisation.
     */
    wrt_api_status_t (*set_metric)(wrt_api_data_t data,
                                   wrt_metric_id_t id,
                                   wrt_metric_type_t type,
                                   wrt_metric_value_t value);

    /**
     * get_context obtains the value and size of a specified context item,
     * with an ID registered during module initialisation.
     */
    wrt_api_status_t (*get_context)(wrt_api_data_t data,
                                    wrt_context_id_t id,
                                    wrt_context_type_t *type,
                                    const void **value,
                                    size_t *size);

    /**
     * set_context sets the value of a specified context item, with an ID
     * registered during module initialisation.
     */
    wrt_api_status_t (*set_context)(wrt_api_data_t data,
                                    wrt_context_id_t id,
                                    wrt_context_type_t type,
                                    const void *value,
                                    size_t size);

    /**
     * get_request_data obtains a pointer to and the size of the currently
     * available request data.
     */
    wrt_api_status_t (*get_request_data)(wrt_api_data_t data,
                                         const void **request_data,
                                         size_t *size);

    /**
     * set_request_data copies the provided data into the session state for
     * the next processor in the chain. After the current session state has
     * been processed, the request data is expected to be entirely consumed by
     * the next processor.
     *
     * If this function is not called, then the input request data will be
     * passed along as-is.
     */
    wrt_api_status_t (*set_request_data)(wrt_api_data_t data,
                                         const void *request_data,
                                         size_t size);

    /**
     * get_reply_data obtains a pointer to and the size of the currently
     * available reply data.
     */
    wrt_api_status_t (*get_reply_data)(wrt_api_data_t data,
                                       const void **reply_data,
                                       size_t *size);

    /**
     * set_reply_data is equivalent to set_request_data, but deals with
     * reply data instead of request data.
     *
     * @see set_request_data.
     */
    wrt_api_status_t (*set_reply_data)(wrt_api_data_t data,
                                       const void *reply_data,
                                       size_t size);

    /**
     * send_data sends some data to the next processor in the chain.
     *
     * send_data must only be invoked from a thread in which the
     * corresponding module's process function is being executed.
     */
    wrt_api_status_t
    (*send_data)(wrt_api_session_t session, wrt_api_data_t data);

    /**
     * clone_data clones an API data structure, with copy-on-write semantics.
     */
    wrt_api_status_t
    (*clone_data)(wrt_api_data_t in, wrt_api_data_t *out);

    /**
     * destroy_data destroys an API data structure.
     */
    wrt_api_status_t
    (*destroy_data)(wrt_api_data_t data);

    /**
     * send_error generates an error message that will be displayed in the
     * T5 "network errors" workspace.
     */
    wrt_api_status_t
    (*send_error)(wrt_api_session_t state, const char *message);

    /**
     * init_log initializes a log handle, with the specified filename
     * used for log message identification.
     */
    wrt_api_status_t
    (*init_log)(const char *filename, wrt_api_log_handle_t *handle);

    /**
     * log_message logs a message to the standard process log output.
     *
     * @param handle A log handle; this may be NULL, in which case
     *               the API container will provide its own log identifier,
     *               which will not be module-specific.
     * @param level The minimum log level for the message to be logged.
     * @param function The function name the message should be associated with.
     * @param line The file line number the message should be associated with.
     * @param message The printf message format, followed by arguments.
     */
    wrt_api_status_t
    (*log_message)(wrt_api_log_handle_t handle,
                   wrt_api_log_level_t level,
                   const char *function,
                   unsigned int line,
                   const char *message, ...);

    /**
     * set_key associates some arbitrary (data, destructor) tuple with
     * the decoder session. There can be at most one value for the session.
     *
     * If the destructor is non-null, then when the session is terminated, the
     * destructor will be invoked with the state and value as its arguments.
     */
    wrt_api_status_t
    (*set_userdata)(wrt_api_session_t state,
                    void *value,
                    wrt_api_data_destructor_t destructor);

    /**
     * get_userdata obtains the data that was previously associated
     * with the session via set_userdata.
     */
    wrt_api_status_t
    (*get_userdata)(wrt_api_session_t state, void **value);

} wrt_module_api_t;

typedef struct wrt_context_descriptor
{
    struct wrt_context_descriptor *next;
    const char                    *name;
    wrt_context_id_t              id;
    wrt_context_type_t            type;
} wrt_context_descriptor_t;

typedef struct wrt_metric_descriptor
{
    struct wrt_metric_descriptor *next;
    const char                   *name;
    wrt_metric_id_t              id;
    wrt_metric_type_t            type;
} wrt_metric_descriptor_t;

typedef struct wrt_module_filter
{
    /* ports_count is the number of ports specified in the filter.
     *
     * If ports_count = 0, then ports is NULL.
     * If ports_count > USHRT_MAX, then ports is NULL, but all ports
     *                             can be considered to be allowed.
     * If ports_count <= USHRT_MAX, then ports is an array of that many ports.
     */
    wrt_uint32_t ports_count;

    /* ports is the list of ports that have been specified. */
    wrt_uint16_t *ports;
} wrt_module_filter_t;

/**
 * wrt_module_config_t is a structure containing the configuration
 * information for a WRT API module.
 *
 * The configuration information comprises the decoder descriptor
 * information for the upstream processor, and the processor corresponding
 * to the module that has received the structure; and decoder-specific
 * environment/configuration.
 *
 * The decoder description information conveys mappings from metric/context
 * name to ID mappings for use in calling get/set_metric etc. from
 * wrt_module_t.process.
 */
typedef struct wrt_module_config
{
    const char               *name;
    wrt_module_filter_t       filter;
    wrt_context_descriptor_t *input_context;
    wrt_context_descriptor_t *output_context;
    wrt_metric_descriptor_t  *input_metrics;
    wrt_metric_descriptor_t  *output_metrics;
} wrt_module_config_t;

/**
 * wrt_module_instance_t is an opaque void*, which represents an
 * instance of a module.
 *
 * The "init" function in the module may store some data in
 * the pointer, which will then be shared with future calls
 * to "process" and "terminate".
 */
typedef void* wrt_module_instance_t;

/**
 * wrt_module_t is a structure that API implementers must
 * provide to define the functions that WRT will invoke
 * in the processing lifecycle.
 */
typedef struct wrt_module
{
    /**
     * version is the module version, and should always
     * be set to "WRT_MODULE_VERSION" when compiling.
     */
    wrt_uint32_t version;

    /**
     * name is the module's name, for descriptive purposes only.
     */
    const char *name;

    /**
     * init is the module initialisation function, which
     * will be called once for each instance of the module.
     *
     * @return An API status code. If a non-zero (error) status code is
     *         returned, then module initialisation is understood to have
     *         failed, and no further calls (including terminate) will be
     *         made to the module; in this case, it is the repsonsibility of
     *         "init" to ensure all resources are cleaned up before returning.
     */
    wrt_api_status_t (*init)(wrt_module_api_t *api,
                             const wrt_module_config_t *config,
                             wrt_module_instance_t *instance);

    /**
     * terminate is the module terminateion function, which
     * will be called once for each corresponding invocation
     * of "init", at (clean) process termination time.
     */
    wrt_api_status_t (*terminate)(wrt_module_instance_t instance);

    /**
     * process is the main data processing function, and is
     * called to provide a module the opportunity to modify
     * or otherwise analyze the observed network data.
     *
     * @return An API status code. If a non-zero (error) status code is
     *         returned, then the session is understood to be in an erroneous
     *         state and will be not be processed any more.
     */
    wrt_api_status_t (*process)(wrt_module_instance_t instance,
                                wrt_api_session_t session,
                                wrt_api_data_t data);
} wrt_module_t;

#define WRT_MODULE_VERSION_0 0
#define WRT_MODULE_VERSION WRT_MODULE_VERSION_0

/**
 * WRT_MODULE_DEFINE is a macro for defining a module.
 * It is a function-like macro taking a single parameter,
 * the ID of the module, e.g. WRT_MODULE_DEFINE(foo) for the
 * module with the ID foo.
 *
 * The intended usage is:
 *  WRT_MODULE_DEFINE(foo) = {
 *      WRT_MODULE_VERSION,
 *      "foo"
 *      &foo_init_function,
 *      &foo_term_function,
 *      &foo_process_function
 *  };
 */
#ifdef _WIN32
#  define WRT_MODULE_DEFINE(id) \
    __declspec(dllexport) wrt_module_t wrt_module_##id
#else
#  define WRT_MODULE_DEFINE(id) \
    wrt_module_t wrt_module_##id
#endif

#ifdef __cplusplus
}
#endif

#endif

