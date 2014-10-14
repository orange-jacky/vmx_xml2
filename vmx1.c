#include <stdio.h>
#include <string.h>

#include <iconv.h>
#include <errno.h>

#include<pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libxml/parser.h>

#include "api.h"
#include "trans_type.h"
#include "ret_code.h"

typedef struct {
    char *ptr;
    size_t size;
} ByteBuf;


typedef struct {
    ByteBuf request_data;
    ByteBuf reply_data;
} wrt_vmx1_session_t;

typedef struct {
    wrt_module_api_t *api;
    wrt_module_config_t *config;
    wrt_api_log_handle_t log;

    FILE *fp;
    FILE *fp1;

    /* pthread_mutex */
    pthread_mutex_t mutex;

    /* input */
    wrt_context_descriptor_t *ctxid_tcpsrcport;
    wrt_context_descriptor_t *ctxid_tcpdstport;
    wrt_context_descriptor_t *ctxid_ipv4srcaddr;
    wrt_context_descriptor_t *ctxid_ipv4dstaddr;
    wrt_context_descriptor_t *ctxid_ipv4origsrcaddr;
    wrt_context_descriptor_t *ctxid_ipv4origdstaddr;


    wrt_metric_descriptor_t *ctxid_tcpresponse_timetotal;
    wrt_metric_descriptor_t *ctxid_tcpresponse_timeserver;
    wrt_metric_descriptor_t *ctxid_tcpresponse_timenetwork;
    wrt_metric_descriptor_t *ctxid_tcpresponse_timeload;


    /* output */
    wrt_context_descriptor_t *ctxid_transactionname;
    wrt_context_descriptor_t *ctxid_statuscode;
    wrt_context_descriptor_t *ctxid_statusisbad;

} wrt_vmx1_module_instance_t;


static size_t
BB_cpy(ByteBuf *buf, void *src, size_t size)
{
    if(size <= 0 || !src || !buf)
        return -1;

    char *ptr = (char *)malloc( sizeof(char)*(size+1) );
    if(!ptr)
    {
        return -2;
    }

    memcpy((void *)ptr, src, size);
    *(ptr+size) = '\0';

    buf->ptr = ptr;
    buf->size = size+1;

    return size+1;
}

static size_t
BB_size(ByteBuf *buf)
{
    if(NULL != buf)
        return buf->size;

    return -1;
}


static void
BB_free(ByteBuf *buf)
{
    if(NULL != buf)
        if(NULL != buf->ptr)
            free(buf->ptr);
    return;
}


static int
convert_encoding(char *fromencoding,
                 char *toencoding,
                 char *inbuf,
                 size_t inlen,
                 char *outbuf,
                 size_t outlen,
                 wrt_module_instance_t instance)
{
    wrt_vmx1_module_instance_t *vmx1_instance =  (wrt_vmx1_module_instance_t *)instance;
    wrt_module_api_t *api =  vmx1_instance->api;
    wrt_api_log_handle_t log = vmx1_instance->log;
   
    
    if(!inbuf || !outbuf) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "iconv_error: buffers not exist.");
        return -1;
    }

    /*convert data*/
    iconv_t cd = iconv_open(toencoding, fromencoding);
    if ( cd == (iconv_t)(-1) ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__,
                         __LINE__, "iconv_error: iconv_open(%s,%s) fail. err[%s].",
                         toencoding, fromencoding, strerror(errno));
        return -1;
    }

    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                     "iconv_info: start convert %s to %s.",
                     fromencoding, toencoding);

		char **pin = &inbuf, **pout = &outbuf;
    size_t cs = iconv(cd, pin, &inlen, pout, &outlen);
    if ( cs  == (size_t)(-1) ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                         "iconv_error: converting %s to %s fail. errno[%d],errstr[%s],buf[%*s]",
                         fromencoding, toencoding,
                         errno,strerror(errno),
                         inlen, *pin);                       
        return -1;
    } 
 
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                     "iconv_info: convert %s to %s finish. the number of characters converted in a non-reversible way is [%d].",
                     fromencoding, toencoding, cs);


    iconv_close(cd);
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                     "iconv_info: close convert %s to %s success.",
                     fromencoding, toencoding);

    return cs;

}


static void
free_session(wrt_api_session_t session, void *data)
{
    wrt_vmx1_session_t *vmx1_session = (wrt_vmx1_session_t*)data;

    BB_free(&vmx1_session->request_data);
    BB_free(&vmx1_session->reply_data);
    free(vmx1_session);

    return;
}

wrt_context_descriptor_t*
find_context_descriptor(wrt_context_descriptor_t *d,
                        const char *name,
                        wrt_context_type_t type)
{
    for (; d; d = d->next)
    {
        if (strcmp(d->name, name) == 0)
            return d->type == type ? d : NULL;
    }
    return NULL;
}


wrt_metric_descriptor_t*
find_metric_descriptor(wrt_metric_descriptor_t *d,
                       const char *name,
                       wrt_metric_type_t type)
{
    for (; d; d = d->next)
    {
        if (strcmp(d->name, name) == 0)
            return d->type == type ? d : NULL;
    }
    return NULL;
}


wrt_api_status_t
vmx1_init( wrt_module_api_t *api,
           wrt_module_config_t *config,
           wrt_module_instance_t *instance)
{
    wrt_vmx1_module_instance_t *vmx1_instance;
    vmx1_instance  = (wrt_vmx1_module_instance_t *)malloc(sizeof(wrt_vmx1_module_instance_t));
    if(!vmx1_instance)
    {
        return  WRT_API_STATUS_NOMEM;
    }

    memset(vmx1_instance,0x00,sizeof(wrt_vmx1_module_instance_t));

    /*init a log*/
    api->init_log(__FILE__,&vmx1_instance->log);

    /* output */
    /* 1 */
    vmx1_instance->ctxid_transactionname = find_context_descriptor(
            config->output_context, "transaction.name", WRT_CONTEXT_STRING);
    if (!vmx1_instance->ctxid_transactionname)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for transaction.name.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 2 */
    vmx1_instance->ctxid_statuscode = find_context_descriptor(
                                          config->output_context, "status.code", WRT_CONTEXT_INT16);
    if (!vmx1_instance->ctxid_statuscode)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for status.code.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 3 */
    vmx1_instance->ctxid_statusisbad = find_context_descriptor(
                                           config->output_context, "status.isbad", WRT_CONTEXT_INT16);
    if (!vmx1_instance->ctxid_statusisbad)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for status.isbad.");
        return WRT_API_STATUS_BADCFG;
    }



    /* input */
    /* 1 */
    vmx1_instance->ctxid_tcpsrcport = find_context_descriptor(
                                          config->input_context, "tcp.srcport", WRT_CONTEXT_UINT16);
    if (!vmx1_instance->ctxid_tcpsrcport)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.srcport.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 2 */
    vmx1_instance->ctxid_tcpdstport = find_context_descriptor(
                                          config->input_context, "tcp.dstport", WRT_CONTEXT_UINT16);
    if (!vmx1_instance->ctxid_tcpdstport)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.dstport.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 3 */
    vmx1_instance->ctxid_ipv4srcaddr = find_context_descriptor(
                                           config->input_context, "ipv4.srcaddr", WRT_CONTEXT_IPV4);
    if (!vmx1_instance->ctxid_ipv4srcaddr)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.srcaddr.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 4*/
    vmx1_instance->ctxid_ipv4dstaddr = find_context_descriptor(
                                           config->input_context, "ipv4.dstaddr", WRT_CONTEXT_IPV4);
    if (!vmx1_instance->ctxid_ipv4dstaddr)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.dstaddr.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 5 */
    vmx1_instance->ctxid_ipv4origsrcaddr = find_context_descriptor(
            config->input_context, "ipv4.origsrcaddr", WRT_CONTEXT_IPV4);
    if (!vmx1_instance->ctxid_ipv4origsrcaddr)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.origsrcaddr.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 6 */
    vmx1_instance->ctxid_ipv4origdstaddr = find_context_descriptor(
            config->input_context, "ipv4.origdstaddr", WRT_CONTEXT_IPV4);
    if (!vmx1_instance->ctxid_ipv4origdstaddr)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.origdstaddr.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 7 */
    vmx1_instance->ctxid_tcpresponse_timetotal = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.total", WRT_METRIC_UINT64);
    if (!vmx1_instance->ctxid_tcpresponse_timetotal)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.total.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 8 */
    vmx1_instance->ctxid_tcpresponse_timeserver = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.server", WRT_METRIC_UINT64);
    if (!vmx1_instance->ctxid_tcpresponse_timeserver)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.server.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 9 */
    vmx1_instance->ctxid_tcpresponse_timenetwork = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.network", WRT_METRIC_UINT64);
    if (!vmx1_instance->ctxid_tcpresponse_timenetwork)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.network.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 10 */
    vmx1_instance->ctxid_tcpresponse_timeload = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.load", WRT_METRIC_UINT64);
    if (!vmx1_instance->ctxid_tcpresponse_timeload)
    {
        api->log_message(vmx1_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.load.");
        return WRT_API_STATUS_BADCFG;
    }


    vmx1_instance->api = api;
    vmx1_instance->config = config;

    FILE *fp = fopen("/opt/itump/ITM/tmaitm6/wrm/linux/vmx1_payload.txt","a+");
    setbuf(fp, NULL);
    vmx1_instance->fp = fp;

    FILE *fp1 = fopen("/opt/itump/ITM/tmaitm6/wrm/linux/vmx1_inbuilt.txt","a+");
    setbuf(fp1, NULL);
    vmx1_instance->fp1 = fp1;


    pthread_mutex_t aa = PTHREAD_MUTEX_INITIALIZER ;
    vmx1_instance->mutex = aa;

    *instance = vmx1_instance;

    return 	WRT_API_STATUS_OK;

}


wrt_api_status_t
vmx1_terminate(wrt_module_instance_t instance)
{
    wrt_vmx1_module_instance_t *vmx1_instance =  (wrt_vmx1_module_instance_t *)instance;
    if(vmx1_instance->fp != NULL)
        fclose(vmx1_instance->fp);

    if(vmx1_instance->fp1 != NULL)
        fclose(vmx1_instance->fp1);

    free(instance);
    return WRT_API_STATUS_OK;
}


wrt_api_status_t
vmx1_process(wrt_module_instance_t instance,
             wrt_api_session_t session,
             wrt_api_data_t data)
{
    wrt_vmx1_module_instance_t *vmx1_instance =  (wrt_vmx1_module_instance_t *)instance;
    wrt_module_api_t *api =  vmx1_instance->api;
    wrt_api_log_handle_t log = vmx1_instance->log;

    FILE *fp = vmx1_instance->fp;
    FILE *fp1 = vmx1_instance->fp1;

    pthread_mutex_t mutex = vmx1_instance->mutex;

    wrt_api_status_t status =  WRT_API_STATUS_OK;

    wrt_vmx1_session_t *vmx1_session = NULL;

    const void *request_data_part = NULL;
    const void *reply_data_part = NULL;
    size_t request_data_part_size = 0;
    size_t reply_data_part_size = 0;

    api->log_message(log, WRT_API_LOG_INFO, __func__,
                     __LINE__, "start process data.");

    /* Store vmx1 session data in userdata. */
    if (api->get_userdata(session, (void**)&vmx1_session) != WRT_API_STATUS_OK)
    {
        vmx1_session = malloc(sizeof(wrt_vmx1_session_t));
        if (!vmx1_session)
        {
            return WRT_API_STATUS_NOMEM;
        }
        memset(vmx1_session, 0, sizeof(wrt_vmx1_session_t));
        api->set_userdata(session, vmx1_session, free_session);
    }

    /* get the current request/reply data. */
    api->get_request_data(data, &request_data_part, &request_data_part_size);
    api->get_reply_data(data, &reply_data_part, &reply_data_part_size);


    /* save request/reply data in session */
    BB_cpy(&vmx1_session->request_data, request_data_part, request_data_part_size);
    BB_cpy(&vmx1_session->reply_data, reply_data_part, reply_data_part_size);

    
    if( request_data_part_size == 0 || reply_data_part_size == 0){
    	    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "pq_empty");
					return -1;
    }
    
    
    api->log_message(log, WRT_API_LOG_INFO, "vmx1_process", __LINE__, "request_data_buff=[%*s]", (int)request_data_part_size, (char *)request_data_part);
    api->log_message(log, WRT_API_LOG_INFO, "vmx1_process", __LINE__, "replay_data_buff=[%*s]", (int)reply_data_part_size, (char *)reply_data_part);
    


    /* find request xml string content */
    size_t len_req = 0;
    char format[] = "<?";
    char *p_req = NULL;
    if( vmx1_session->request_data.ptr != NULL ) {

        p_req = strstr( vmx1_session->request_data.ptr, format );
        if(!p_req) {
            api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                             "jacky_error: search [%s] fail in request data.",format);
            return -1;
        }
        len_req = strlen(p_req);
    }


    /* find reply xml string content */
    size_t len_reply = 0 ;
    char *p_reply = NULL;


    if( vmx1_session->reply_data.ptr != NULL ) {

        p_reply = strstr( vmx1_session->reply_data.ptr, "GBK" );
        if(!p_reply) {
          
           p_reply = strstr( vmx1_session->reply_data.ptr, format );
           
       		 	if(!p_reply) {
            		api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
            	                 "jacky_error: search [%s] fail in reply data.buff[%*s]",format,
            	                  vmx1_session->reply_data.size,
            	                   vmx1_session->reply_data.ptr);
            	return -1;
        		}
        		len_reply = strlen(p_reply);
            
            goto vmx;
        }
        
    }


    char convert_content[204800];/*buffer 200KB*/
    char *outbuf = convert_content;
    size_t outlen = sizeof(convert_content);

    memset(convert_content, 0x00, sizeof(convert_content));

    /* convert non utf-8 encoding charact set */
    
    /*
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,"before iconv,buf[%*s]",
    								 vmx1_session->reply_data.size,
    								 vmx1_session->reply_data.ptr);
    								 
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,"before iconv,ptr ponitor is [%p]",
    								 vmx1_session->reply_data.ptr);		    								 
		*/
		
    int rec = 0;
    rec = convert_encoding("GB18030", "UTF-8",
                           vmx1_session->reply_data.ptr, vmx1_session->reply_data.size,
                           outbuf, outlen,
                           instance);
		/*                           
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,"after iconv,buf[%*s]",
    								 vmx1_session->reply_data.size,
    								 vmx1_session->reply_data.ptr);                           
		*/    								 
    if(rec == -1) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,"jacky_error:convert encoding fail.");
   		  api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,"jacky_error:before iconv,buf[%*s]",
    								 vmx1_session->reply_data.size,
    								 vmx1_session->reply_data.ptr);        
        return -1;
    }

    p_reply = strstr(convert_content, format);
    if(!p_reply) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                         "jacky_error: search [%s] fail in reply data.",format);
        return -1;
    }

    outlen = strlen(p_reply);
    char *tmpptr = NULL;
    char c1[] = "GBK";
    char c2[] = "UTF-8";
    tmpptr = strstr(p_reply, c1);
    if(!tmpptr) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                         "jacky_error:search [%s] fail in reply data(after convert).",c1);
        return -1;
    }

    len_reply = outlen + (strlen(c2) - strlen(c1));
    memmove(tmpptr+strlen(c2), tmpptr+strlen(c1), strlen(tmpptr)-strlen(c1));
    memmove(tmpptr, c2, strlen(c2));


	
	
	  /*
    pthread_mutex_lock(&mutex);
    if(fp != NULL) {
        fprintf(fp,"request_data[%*s]\n", len_req, p_req);
    }
    if(fp != NULL) {
        fprintf(fp,"reply_data[%*s]\n", len_reply, p_reply);
    }
    pthread_mutex_unlock(&mutex);
		*/

vmx:

    /* start xml parse */
		printf("anything");

    char smsgname[100], dmsgname[100];
    char shostserver[100], dhostserver[100];
    char sjourno[100], djourno[100];
    char svcreturn[10];
    memset(smsgname,0x00,sizeof(smsgname));
    memset(dmsgname,0x00,sizeof(dmsgname));
    memset(shostserver,0x00,sizeof(shostserver));
    memset(dhostserver,0x00,sizeof(dhostserver));
    memset(sjourno,0x00,sizeof(sjourno));
    memset(djourno,0x00,sizeof(djourno));
    memset(svcreturn,0x00,sizeof(svcreturn));
    		
		smsgname[0] = '\0';
		dmsgname[0] = '\0';
		shostserver[0] = '\0';
		dhostserver[0] = '\0';
		sjourno[0] = '\0';
		djourno[0] = '\0';								
		svcreturn[0] = '\0';	


    xmlDocPtr doc = NULL;
    xmlNodePtr curNode = NULL, curNode1 = NULL;
    xmlChar *szkey = NULL;
    
    
    
    doc = xmlParseMemory(p_req, len_req);

    if ( NULL == doc ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request): parse memory fail.");
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
         "xml2(request): buf[%*s]",
         vmx1_session->request_data.size,
         vmx1_session->request_data.ptr);
         
         api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
         "xml2(request): buf1[%*s]",
         len_req,
         p_req);       
        return -1;
    }
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request): parse memory success.");


    curNode = xmlDocGetRootElement(doc);
    if ( NULL == curNode ) {

        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request): empty document.");
        xmlFreeDoc(doc);
        return -1;
    }
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):root tag is [%s].", curNode->name);

    curNode = curNode->xmlChildrenNode;

    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):parse request start.");
    curNode1 = curNode;

    while( curNode != NULL ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):find VMX_HEADER tag.");
        if( (!xmlStrcmp(curNode->name, (xmlChar *)"VMX_HEADER" ))) {
            api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):have VMX_HEADER tag.");
            curNode = curNode->xmlChildrenNode;
            curNode1 = curNode;

            while( curNode != NULL ) {
                api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):find MSGID tag.");
                if( (!xmlStrcmp(curNode->name, (xmlChar *)"MSGID" ))) {
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):have MSGID tag.");
                    szkey = xmlNodeGetContent(curNode);
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):MSGID=[%s].",(char *)szkey);
                    strcpy(smsgname, (char *)szkey);
                    break;
                }
                curNode = curNode->next;
            }

						while( curNode != NULL ) {
                api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):find TermJourNo tag.");
                if( (!xmlStrcmp(curNode->name, (xmlChar *)"TermJourNo" ))) {
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):have TermJourNo tag.");
                    szkey = xmlNodeGetContent(curNode);
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):TermJourNo=[%s].",(char *)szkey);
                    strcpy(sjourno, (char *)szkey);
                    break;
                }
                curNode = curNode->next;
            }
            
            break;
        }
        curNode = curNode->next;
    }

    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(request):parse request finish.");

  
    xmlMemoryDump();
    
   /* convert transaction name */
    int ii,jj,mm,nn,xx = -1;

    for(ii=0,mm=trans_type_max-1; ii<mm; ii++) {
        if( strcmp( smsgname , trans_type[ii][0] ) == 0 )
        {
            xx = ii;
            break;
        }
    }
    if( xx == -1) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, " not find . MSGID[%s].", smsgname);
    } else {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, " find it . arr[%d]=[%s].",xx,trans_type[xx][1]);
    }    
        


    /* parse reply data */
    doc = xmlParseMemory(p_reply, len_reply);
    if ( NULL == doc ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply): parse memory fail.");
        return -1;
    }
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply): parse memory success.");


    curNode = xmlDocGetRootElement(doc);
    if ( NULL == curNode ) {

        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply): empty document.");
        xmlFreeDoc(doc);
        return -1;
    }
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):root tag is [%s].", curNode->name);

    curNode = curNode->xmlChildrenNode;

    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):parse reply start.");
    curNode1 = curNode;

    while( curNode != NULL ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):find VMX_HEADER tag.");
        if( (!xmlStrcmp(curNode->name, (xmlChar *)"VMX_HEADER" ))) {
            api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):have VMX_HEADER tag.");
            curNode = curNode->xmlChildrenNode;

            while( curNode != NULL ) {
                api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):find MSGID tag.");
                if( (!xmlStrcmp(curNode->name, (xmlChar *)"MSGID" ))) {
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):have MSGID tag.");
                    szkey = xmlNodeGetContent(curNode);
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):MSGID=[%s].",(char *)szkey);
                    strcpy(dmsgname, (char *)szkey);
                    break;
                }
                curNode = curNode->next;
            }
            
            while( curNode != NULL ) {
                api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):find TermJourNo tag.");
                if( (!xmlStrcmp(curNode->name, (xmlChar *)"TermJourNo" ))) {
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):have TermJourNo tag.");
                    szkey = xmlNodeGetContent(curNode);
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):TermJourNo=[%s].",(char *)szkey);
                    strcpy(djourno, (char *)szkey);
                    break;
                }
                curNode = curNode->next;
            }     
                   
            break;
        }
        curNode = curNode->next;
    }



 		while( curNode1 != NULL ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):find VMX_MSGOUT tag.");
        if( (!xmlStrcmp(curNode1->name, (xmlChar *)"VMX_MSGOUT" ))) {
            api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):have VMX_MSGOUT tag.");
            curNode1 = curNode1->xmlChildrenNode;

            while( curNode1 != NULL ) {
                api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):find SVC_RETURN.");
                if( (!xmlStrcmp(curNode1->name, (xmlChar *)"SVC_RETURN" ))) {
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):have SVC_RETURN.");
                    szkey = xmlNodeGetContent(curNode1);
                    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):SVC_RETURN=[%s].",(char *)szkey);
                    strcpy(svcreturn, (char *)szkey);
                    break;
                }
                curNode1 = curNode1->next;
            } 
            break;
        }
        curNode1 = curNode1->next;
    }
    
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "xml2(reply):parse reply finish.");


    xmlFreeDoc(doc);
    xmlMemoryDump();


    /* convert transaction name */
    int iii,jjj,mmm,nnn,xxx = -1;

    for(iii=0,mmm=trans_type_max-1; iii<mmm; iii++) {
        if( strcmp( dmsgname , trans_type[iii][0] ) == 0 )
        {
            xxx = iii;
            break;
        }
    }

    if( xxx == -1) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, " not find . MSGID[%s]", dmsgname);
    } else {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, " find it . arr[%d]=[%s].",xxx,trans_type[xxx][1]);
    }


    int rc = 1;
    /* While there are more requests to process, decode and process them. */
    while( rc == 1 && BB_size(&vmx1_session->request_data) != 0)
    {

        wrt_api_data_t out_data = NULL;
        status = api->clone_data(data, &out_data);
        if (status != WRT_API_STATUS_OK)
        {
            /* Break out of loop. */
            break;
        }
        else
        {

            /* inbuilt output */
            wrt_context_descriptor_t *ctx_dsc;
            wrt_context_type_t ctx_type;
            wrt_uint16_t  ctx_value;
            const void  *raw_ctx_value;
            size_t ctx_size = 0;
#if 0
            pthread_mutex_lock(&mutex);


            ctx_dsc = vmx1_instance->ctxid_tcpsrcport;
            status = api->get_context(out_data, ctx_dsc->id,
                                      &ctx_type, &raw_ctx_value, &ctx_size);
            if( status != WRT_API_STATUS_OK ) {
                return 1;
            }
            if( ctx_size > sizeof(void *) ) {
                ctx_value = raw_ctx_value;
            } else {
                ctx_value = &raw_ctx_value;
            }

            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] size[%d] value[%hu]\n",
                        ctx_dsc->name, ctx_type, ctx_size, ctx_value);
            }


            ctx_dsc = vmx1_instance->ctxid_tcpdstport;
            status = api->get_context(out_data, ctx_dsc->id,
                                      &ctx_type, &raw_ctx_value, &ctx_size);
            if( status != WRT_API_STATUS_OK ) {
                return 1;
            }
            if( ctx_size > sizeof(void *) ) {
                ctx_value = raw_ctx_value;
            } else {
                ctx_value = &raw_ctx_value;
            }

            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] size[%d] value[%hu]\n",
                        ctx_dsc->name, ctx_type, ctx_size, ctx_value);
            }


            wrt_uint32_t  sasa;

            ctx_dsc = vmx1_instance->ctxid_ipv4srcaddr;
            api->get_context(out_data, ctx_dsc->id,
                             &ctx_type, &sasa, &ctx_size);

            struct in_addr     inaddr;
            memset(&inaddr, 0x00, sizeof(struct in_addr) );
            inaddr.s_addr = sasa;

            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] size[%d] value[%s]\n",
                        ctx_dsc->name, ctx_type, ctx_size, inet_ntoa(inaddr) );
            }

            ctx_dsc = vmx1_instance->ctxid_ipv4dstaddr;
            api->get_context(out_data, ctx_dsc->id,
                             &ctx_type, &sasa, &ctx_size);

            memset(&inaddr, 0x00, sizeof(struct in_addr) );
            inaddr.s_addr = sasa;

            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] size[%d] value[%s]\n",
                        ctx_dsc->name, ctx_type, ctx_size, inet_ntoa( inaddr) );
            }


            ctx_dsc = vmx1_instance->ctxid_ipv4origsrcaddr;
            api->get_context(out_data, ctx_dsc->id,
                             &ctx_type, &sasa, &ctx_size);

            memset(&inaddr, 0x00, sizeof(struct in_addr) );
            inaddr.s_addr = sasa;

            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] size[%d] value[%s]\n",
                        ctx_dsc->name, ctx_type, ctx_size, inet_ntoa( inaddr) );
            }

            ctx_dsc = vmx1_instance->ctxid_ipv4origdstaddr;
            api->get_context(out_data, ctx_dsc->id,
                             &ctx_type, &sasa, &ctx_size);

            memset(&inaddr, 0x00, sizeof(struct in_addr) );
            inaddr.s_addr = sasa;

            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] size[%d] value[%s]\n",
                        ctx_dsc->name, ctx_type, ctx_size, inet_ntoa( inaddr) );
            }

            /* inbuild cmetric*/
            wrt_metric_descriptor_t *mtc_dsc;
            wrt_metric_type_t mtc_type;
            wrt_metric_value_t mtc_value;

            mtc_dsc = vmx1_instance->ctxid_tcpresponse_timetotal;
            api->get_metric(out_data, mtc_dsc->id, &mtc_type, &mtc_value);
            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] value[%hu]\n",
                        mtc_dsc->name, mtc_type, mtc_value.u64);
            }


            mtc_dsc = vmx1_instance->ctxid_tcpresponse_timeserver;
            api->get_metric(out_data, mtc_dsc->id, &mtc_type, &mtc_value);
            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] value[%hu]\n",
                        mtc_dsc->name, mtc_type, mtc_value.u64);
            }

            mtc_dsc = vmx1_instance->ctxid_tcpresponse_timenetwork;
            api->get_metric(out_data, mtc_dsc->id, &mtc_type, &mtc_value);
            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] value[%hu]\n",
                        mtc_dsc->name, mtc_type, mtc_value.u64);
            }

            mtc_dsc = vmx1_instance->ctxid_tcpresponse_timeload;
            api->get_metric(out_data, mtc_dsc->id, &mtc_type, &mtc_value);
            if(fp1 != NULL) {
                fprintf(fp1,"name[%s] type[%d] value[%hu]\n",
                        mtc_dsc->name, mtc_type, mtc_value.u64);
            }

            pthread_mutex_unlock(&mutex);

#endif
            /* set status.isbad flag */
            wrt_int16_t  kkkk;
            kkkk = 1234;
            ctx_dsc = vmx1_instance->ctxid_statuscode;
            api->set_context(out_data, ctx_dsc->id,
                             WRT_CONTEXT_INT16,
                             &kkkk,
                             sizeof(kkkk));   
                             
 					pthread_mutex_lock(&mutex);       
 						if(fp1 != NULL) {
 								int sa = 1;
                fprintf(fp1,"%s | %s | %s | %s | %d \n",
                			  xx != -1? trans_type[xx][1] : "empty", sjourno, 
                				xxx != -1? trans_type[xxx][1] : "empty", djourno,
                				sa);
            } 					
          pthread_mutex_unlock(&mutex);
    	
    	     api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "return code=[%s]",svcreturn);		 
    	     
    			 if(!strncmp(svcreturn,"P",1) ){
    			 	kkkk = 0;
    			 	
    			 }else if(!strncmp(svcreturn,"F",1) ){
    			 	kkkk = 1;
    			 }else{
    			 	kkkk = 1111;	
    			 }
       
          api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "kkkk=%d \t xxx=%d",kkkk,xxx);
          
          
            ctx_dsc = vmx1_instance->ctxid_statusisbad;
            api->set_context(out_data, ctx_dsc->id,
                             WRT_CONTEXT_INT16,
                             &kkkk,
                             sizeof(kkkk));


            /* custom output */
#if 1
            int bb = 0;
            bb = ( xx == -1 ? 0 : strlen(trans_type[xx][1]) );
            api->set_context(out_data, vmx1_instance->ctxid_transactionname->id,
                             WRT_CONTEXT_STRING,
                             bb > 0 ? trans_type[xx][1] : "empty" ,
                             bb > 0 ? bb +1 : sizeof("empty") );
#endif


            /* Send the request/response transaction to  the next module in the chain. */
            api->send_data(session, out_data);
            api->destroy_data(out_data);
        }
        rc = 0;
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "sent data");
    }

    return status;
}


WRT_MODULE_DEFINE(vmx1) = {
    WRT_MODULE_VERSION,
    "vmx1",
    &vmx1_init,
    &vmx1_terminate,
    &vmx1_process
};