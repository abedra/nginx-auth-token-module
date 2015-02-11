#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <string.h>
#include "hiredis/hiredis.h"


typedef struct {
  ngx_str_t redis_host;
  ngx_int_t redis_port;
  ngx_str_t token_name;
  ngx_str_t redirect_location;
} auth_token_main_conf_t;

typedef struct {
  ngx_flag_t enabled;
} auth_token_loc_conf_t;

ngx_module_t ngx_http_auth_token_module;



static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);

static ngx_table_elt_t *
search_hashed_headers_in(ngx_http_request_t *r, u_char *name, size_t len);



static ngx_int_t
lookup_user(auth_token_main_conf_t *conf, ngx_str_t *auth_token, ngx_str_t *user_id)
{
  redisContext *context = redisConnect((const char*)conf->redis_host.data, conf->redis_port);
  redisReply *reply = redisCommand(context, "GET %s", auth_token->data);

  if (reply->type == REDIS_REPLY_NIL) {
    return NGX_DECLINED;
  } else {
    ngx_str_set(user_id, reply->str);  
    return NGX_OK;
  }
}


static ngx_int_t
redirect(ngx_http_request_t *r, ngx_str_t *location)
{
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "Location");
  h->value = *location;

  return NGX_HTTP_MOVED_TEMPORARILY;
}


static void
append_user_id(ngx_http_request_t *r, ngx_str_t *user_id)
{
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_in.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "X-User-Id");
  h->value = *user_id; 
  h->value.len = strlen((*user_id).data);
}


static ngx_int_t
ngx_http_auth_token_handler(ngx_http_request_t *r)
{
  if (r->main->internal) {
    return NGX_DECLINED;
  }

  auth_token_loc_conf_t *loc = ngx_http_get_module_loc_conf(r, ngx_http_auth_token_module);

  if (!loc->enabled || loc->enabled == NGX_CONF_UNSET) {
    return NGX_DECLINED;
  }

  r->main->internal = 1;

  auth_token_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_auth_token_module);


  /* Now we search within the headers and look for the given header name */
  ngx_str_t user_id;  

  ngx_table_elt_t            *header;
  ngx_http_header_t          *hashedheader;

  header = NULL;

  hashedheader = search_hashed_headers_in(r, conf->token_name.data, conf->token_name.len);

  if (hashedheader != NULL) {
    if (hashedheader->offset){
      header = *((ngx_table_elt_t **) ((char *) &r->headers_in + hashedheader->offset));
      
      ngx_int_t lookup_result = lookup_user(conf, &header->value, &user_id);

      if (lookup_result == NGX_DECLINED) {
        return redirect(r, &conf->redirect_location);
      } else {
        append_user_id(r, &user_id);
        return NGX_DECLINED;
      }
    }
  }

  /* Header is still null if we haven't found in hash so need to brute force */
  if (header == NULL){
    header = search_headers_in(r, conf->token_name.data, conf->token_name.len);
    if (header == NULL) {

      /* If header is still null then its not in headers so check cookies */
      ngx_int_t cookie_location;
      ngx_str_t auth_token;
      cookie_location = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->token_name, &auth_token);

      if (cookie_location == NGX_DECLINED) {
        return redirect(r, &conf->redirect_location);
      } else {
        ngx_int_t lookup_result = lookup_user(conf, &auth_token, &user_id);

        if (lookup_result == NGX_DECLINED) {
          return redirect(r, &conf->redirect_location);
        } else {
          append_user_id(r, &user_id);
          return NGX_DECLINED;
        }
      }
    } else {
      
      ngx_int_t lookup_result = lookup_user(conf, &header->value, &user_id);

      if (lookup_result == NGX_DECLINED) {
        return redirect(r, &conf->redirect_location);
      } else {

 /*       ngx_log_error(NGX_LOG_ERR, r->connection->log,0, user_id3.data);  */

        append_user_id(r, &user_id);
        return NGX_DECLINED;
      }
    }
  }

/* ngx_log_error(NGX_LOG_ERR, r->connection->log,0,"ONE"); */
}


/* Taken from http://wiki.nginx.org/HeadersManagement - thanks ! */
static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len)
{
  ngx_list_part_t            *part;
  ngx_table_elt_t            *h;
  ngx_uint_t                  i;

  part = &r->headers_in.headers.part;
  h = part->elts;

  // headers array may consist of more than one part
  // so loop throgh all of it
  for (i = 0; /* void */ ; i++)
  {
    if (i >= part->nelts)
    {
      if (part->next == NULL)
      {
        break;
      }

      part = part->next;
      h = part->elts;
      i = 0;
    }

    // just compare names case insensitively
    if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0)
    {
      continue;
    }
    // ta-da, we got one
      return &h[i];
  }
  // no plain header was found
  return NULL;
}

ngx_table_elt_t *
search_hashed_headers_in(ngx_http_request_t *r, u_char *name, size_t len) {
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_header_t          *hh;
    u_char                     *lowcase_key;
    ngx_uint_t                  i, hash;

    /*
    Header names are case-insensitive, so have been hashed by lowercases key
    */
    lowcase_key = ngx_palloc(r->pool, len);
    if (lowcase_key == NULL) {
        return NULL;
    }

    /*
    Calculate a hash of lowercased header name
    */
    hash = 0;
    for (i = 0; i < len; i++) {
        lowcase_key[i] = ngx_tolower(name[i]);
        hash = ngx_hash(hash, lowcase_key[i]);
    }

    /*
    The layout of hashed headers is stored in ngx_http_core_module main config.
    All the hashes, its offsets and handlers are pre-calculated
    at the configuration time in ngx_http_init_headers_in_hash() at ngx_http.c:432
    with data from ngx_http_headers_in at ngx_http_request.c:80.
    */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    /*
    Find the current header description (ngx_http_header_t) by its hash
    */
    hh = ngx_hash_find(&cmcf->headers_in_hash, hash, lowcase_key, len);

    if (hh == NULL) {
        /*
        There header is unknown or is not hashed yet.
        */
        return NULL;
    }

    if (hh->offset == 0) {
        /*
        There header is hashed but not cached yet for some reason.
        */
        return NULL;
    }

    /*
    The header value was already cached in some field
    of the r->headers_in struct (hh->offset tells in which one).
    */

    return *((ngx_table_elt_t **) ((char *) &r->headers_in + hh->offset));
}

ngx_http_auth_token_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_token_handler;

  return NGX_OK;
}


static void*
ngx_http_auth_token_create_main_conf(ngx_conf_t *cf)
{
  auth_token_main_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(auth_token_main_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->redis_port = NGX_CONF_UNSET_UINT;

  return conf;
}

static void*
ngx_http_auth_token_create_loc_conf(ngx_conf_t *cf)
{
  auth_token_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(auth_token_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->enabled = NGX_CONF_UNSET;

  return conf;
}

static char*
ngx_http_auth_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  auth_token_loc_conf_t *prev = (auth_token_loc_conf_t*)parent;
  auth_token_loc_conf_t *conf = (auth_token_loc_conf_t*)child;

  ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

  return NGX_CONF_OK;
}

static ngx_command_t ngx_http_auth_token_commands[] = {
  {
    ngx_string("auth_token_redis_host"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, redis_host),
    NULL
  },
  {
    ngx_string("auth_token_redis_port"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, redis_port),
    NULL
  },
  {
    ngx_string("auth_token_token_name"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, token_name),
    NULL
  },
  {
    ngx_string("auth_token_redirect_location"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, redirect_location),
    NULL
  },
  {
    ngx_string("auth_token_enabled"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(auth_token_loc_conf_t, enabled),
    NULL
  },

  ngx_null_command
};


static ngx_http_module_t ngx_http_auth_token_module_ctx = {
  NULL,                                 /* preconfiguration */
  ngx_http_auth_token_init,             /* postconfiguration */
  ngx_http_auth_token_create_main_conf, /* create main configuration */
  NULL,                                 /* init main configuration */
  NULL,                                 /* create server configuration */
  NULL,                                 /* merge server configuration */
  ngx_http_auth_token_create_loc_conf,  /* create location configuration */
  ngx_http_auth_token_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_auth_token_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_token_module_ctx, /* module context */
  ngx_http_auth_token_commands,    /* module directives */
  NGX_HTTP_MODULE,                 /* module type */
  NULL,                            /* init master */
  NULL,                            /* init module */
  NULL,                            /* init process */
  NULL,                            /* init thread */
  NULL,                            /* exit thread */
  NULL,                            /* exit process */
  NULL,                            /* exit master */
  NGX_MODULE_V1_PADDING
};
