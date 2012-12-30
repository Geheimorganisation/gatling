#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <fcntl.h>
#include <polarssl/havege.h>
#include <polarssl/ssl.h>
#include "mmap.h"

#ifdef POLARSSL_ERR_NET_TRY_AGAIN
#error polarssl version too old, try the svn trunk
#endif

static int library_inited;

const char* ssl_server_cert="server.pem";
const char* ssl_client_crl="clientcrl.pem";
const char* ssl_client_ca="clientca.pem";
const char* ssl_ciphers="DEFAULT";
const char* ssl_client_cert="clientcert.pem";

x509_cert srvcert;
rsa_context rsa;
havege_state hs;

int my_ciphersuites[] =
{
    SSL_EDH_RSA_AES_256_SHA,
    SSL_EDH_RSA_CAMELLIA_256_SHA,
    SSL_EDH_RSA_AES_128_SHA,
    SSL_EDH_RSA_CAMELLIA_128_SHA,
    SSL_EDH_RSA_DES_168_SHA,
    SSL_RSA_AES_256_SHA,
    SSL_RSA_CAMELLIA_256_SHA,
    SSL_RSA_AES_128_SHA,
    SSL_RSA_CAMELLIA_128_SHA,
    SSL_RSA_DES_168_SHA,
    SSL_RSA_RC4_128_SHA,
    SSL_RSA_RC4_128_MD5,
    0
};

/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */
ssl_session *s_list_1st = NULL;
ssl_session *cur, *prv;

static int my_get_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    if( ssl->resume == 0 )
        return( 1 );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        if( ssl->timeout != 0 && t - prv->start > ssl->timeout )
            continue;

        if( ssl->session->ciphersuite != prv->ciphersuite ||
            ssl->session->length != prv->length )
            continue;

        if( memcmp( ssl->session->id, prv->id, prv->length ) != 0 )
            continue;

        memcpy( ssl->session->master, prv->master, 48 );
        return( 0 );
    }

    return( 1 );
}

static int my_set_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        if( ssl->timeout != 0 && t - cur->start > ssl->timeout )
            break; /* expired, reuse this slot */

        if( memcmp( ssl->session->id, cur->id, cur->length ) == 0 )
            break; /* client reconnected */

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
        cur = (ssl_session *) malloc( sizeof( ssl_session ) );
        if( cur == NULL )
            return( 1 );

        if( prv == NULL )
              s_list_1st = cur;
        else  prv->next  = cur;
    }

    memcpy( cur, ssl->session, sizeof( ssl_session ) );

    return( 0 );
}

static int my_net_recv( void *ctx, unsigned char *buf, size_t len ) {
  int sock=(int)(uintptr_t)ctx;
  return net_recv(&sock,buf,len);
};

static int my_net_send( void *ctx, const unsigned char *buf, size_t len ) {
  int sock=(int)(uintptr_t)ctx;
  return net_send(&sock,buf,len);
};


int init_serverside_tls(ssl_context* ssl,ssl_session* ssn,int sock) {
  size_t l,i;
  int found=0;
  char* buf;
  if (!library_inited) {
    library_inited=1;
    havege_init(&hs);
  } else
    x509_free(&srvcert);

  memset(&srvcert,0,sizeof(x509_cert));
  /* for compatibility we expect the same file format as openssl, which
   * looks like this:

   -----BEGIN RSA PRIVATE KEY-----
   [base64]
   -----END RSA PRIVATE KEY-----
   -----BEGIN CERTIFICATE-----
   [base64]
   -----END CERTIFICATE-----

   */
  buf=(char*)mmap_read(ssl_server_cert,&l);
  if (!buf) return -1;
  for (i=0; i<l-sizeof("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"); ++i)
    if (!memcmp(buf+i,"-----BEGIN CERTIFICATE-----",sizeof("-----BEGIN CERTIFICATE-----")-1)) {
      found=1;
      break;
    }
  if (!found) {
fail:
    mmap_unmap(buf,l);
    return -1;
  }
  /* parse cert and key */
  if (x509parse_crt(&srvcert,(unsigned char*)buf+i,l-i) ||
      x509parse_key(&rsa,(unsigned char*)buf,i,NULL,0))
    goto fail;
  mmap_unmap(buf,l);

  memset(ssl,0,sizeof(*ssl));
  memset(ssn,0,sizeof(*ssn));

  if (ssl_init(ssl))
    return -1;

  ssl_set_endpoint( ssl, SSL_IS_SERVER );
  ssl_set_authmode( ssl, SSL_VERIFY_NONE );
  ssl_set_rng( ssl, havege_random, &hs );
  ssl_set_bio( ssl, my_net_recv, (void*)(uintptr_t)sock, my_net_send, (void*)(uintptr_t)sock );
  ssl_set_scb( ssl, my_get_session, my_set_session );
  ssl_set_ciphersuites( ssl, my_ciphersuites );
  ssl_set_session( ssl, 1, 0, ssn );

  ssl_set_ca_chain( ssl, srvcert.next, NULL, NULL );
  ssl_set_own_cert( ssl, &srvcert, &rsa );
  ssl_set_dh_param( ssl, "CD95C1B9959B0A135B9D306D53A87518E8ED3EA8CBE6E3A338D9DD3167889FC809FE1AD59B38C98D1A8FCE47E46DF5FB56B8EA3B03B2132C249A99209F62A1AD63511BD08A60655B0463B6F1BB79BEC9D17C71BD269C6B50CF0EDDAAB83290B4C697A7F641FBD21EE0E7B57C698AFEED8DA3AB800525E6887215A61CA62DC437", "04" );

  return 0;
}

