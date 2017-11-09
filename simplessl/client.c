#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

/* OpenSSL includes */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "openssl_hostname_validation.h"

#define BUFFER_MAX	200
static char root_store_filename_redhat[] = "/etc/pki/tls/certs/ca-bundle.crt";

int connect_to_host(char* host, char* port, int protocol);
SSL* openssl_connect_to_host(int sock, char* hostname);

int main() {
	int i;
	int sock;
	SSL* tls;
	char query[2048];
	char response[2048];
	int query_len;
	char hostname[] = "www.google.com";
	
	sock = connect_to_host(hostname, "443", SOCK_STREAM);
	tls = openssl_connect_to_host(sock, hostname);

	sprintf(query ,"GET / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname);
	query_len = strlen(query);
	SSL_write(tls, query, query_len);
	SSL_read(tls, response, sizeof(response));
	printf("Received:\n%s", response);

	close(sock);
	SSL_shutdown(tls);
	SSL_free(tls);
	return 0;
}

SSL* openssl_connect_to_host(int sock, char* hostname) {
	X509* cert;
	SSL_CTX* tls_ctx;
	SSL* tls;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	tls_ctx = SSL_CTX_new(TLS_client_method());
	if (tls_ctx == NULL) {
		fprintf(stderr, "Could not create SSL_CTX\n");
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_load_verify_locations(tls_ctx, root_store_filename_redhat, NULL) != 1) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed\n");
		exit(EXIT_FAILURE);
	}

	tls = SSL_new(tls_ctx);
	SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		fprintf(stderr, "SSL_new from tls_ctx failed\n");
		exit(EXIT_FAILURE);
	}

	/* set server name indication for client hello */
	SSL_set_tlsext_host_name(tls, hostname);

	/* Associate socket with TLS context */
	SSL_set_fd(tls, sock);

	if (SSL_connect(tls) != 1) {
		fprintf(stderr, "Failed in SSL_connect\n");
		exit(EXIT_FAILURE);
	}

	cert = SSL_get_peer_certificate(tls);
	if (cert == NULL) {
		fprintf(stderr, "Failed to get peer certificate\n");
		exit(EXIT_FAILURE);
	}

	if (validate_hostname(hostname, cert) != MatchFound) {
		fprintf(stderr, "Failed to validate hostname in certificate\n");
		exit(EXIT_FAILURE);
	}

	return tls;
}

int connect_to_host(char* host, char* service, int protocol) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = protocol;
	hints.ai_family = AF_UNSPEC; // IP4 or IP6, we don't care
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
		if (sock == -1) {
			perror("socket");
			continue;
		}
		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "Failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}
	return sock;
}
