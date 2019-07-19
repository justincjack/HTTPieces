//
//  db_x_platform.h
//  Portaudio intercom
//
//  Created by Justin Jack on 8/13/18.
//  Copyright © 2018 Justin Jack. All rights reserved.
//  Rev 3

// 3/27/19 1:50PM - Copied to Windows VS Studio "deedlecore" project.


#ifndef db_x_platform_h
#define db_x_platform_h

/* Relative includes */

#ifndef _WIN32
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <errno.h>
#else
#include <WinSock2.h>
#endif


static int wsastartup_been_called = 0;

#ifndef _WIN32
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define Sleep( ms ) usleep((ms*1000))
#define db_inline inline
#define closesocket(s) close(s)
#define OutputDebugString(x) printf("%s", x)
#else 

#define db_inline __forceinline

#endif

#define set_socket_blocking_state( socket, blocking_state) SetSocketBlockingEnabled(socket, blocking_state)


/* Typedefs */
#ifndef _WIN32
typedef pthread_mutex_t MUTEX;
typedef sem_t *SEMAPHORE;
typedef unsigned int DWORD;
typedef int SOCKET;
typedef short WORD;
typedef unsigned char       BYTE;
typedef unsigned long ULONG_PTR, *PULONG_PTR;
typedef ULONG_PTR DWORD_PTR, *PDWORD_PTR;
#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
typedef pthread_t DB_THREAD;


typedef struct WSAData {
    WORD           wVersion;
    WORD           wHighVersion;
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char           *lpVendorInfo;
    char           szDescription[257];
    char           szSystemStatus[129];
} WSADATA, *LPWSADATA;

typedef void *(*DB_THREAD_PROC)(void *param);
typedef void *DB_THREAD_PARAM;

#else

#define SEM_FAILED 0

typedef DWORD(*DB_THREAD_PROC)(LPVOID);

typedef LPVOID DB_THREAD_PARAM;

typedef HANDLE MUTEX;

typedef HANDLE SEMAPHORE;

typedef HANDLE DB_THREAD;

#endif



#ifdef __cplusplus
extern "C" {
#endif
    /* Cross platform network functions */
    int db_send(SOCKET s, char *buff, size_t bufflen, int flags);
    int SetSocketBlockingEnabled(SOCKET fd, int blocking);
    SOCKET tcpconnect(char *ipaddress, unsigned short port, int nonblock);
    SOCKET ltcpconnect(unsigned long ipaddress, unsigned short port, int nonblock);
    /* Connect a TCP socket by unsigned long ip address with keep-alive flag on socket */
    SOCKET ltcpconnectka(unsigned long ipaddress, unsigned short port, int nonblock);

    int set_socket_keepalive(SOCKET s);
    
    SOCKET openudpsocket(unsigned short port, int nonblock);
    SOCKET opentcpsocket(unsigned short port, int nonblock);
    
    /* String IP Address to numeric */
    int db_inet_pton( int family, char *szipaddr, void *paddress );
    /* Numeric IP Address to String */
    char *db_inet_ntop( int family, void *paddress, char *outputstring, size_t buffersize );
    
    /*
     get_ip4_list( unsigned long[10] );
     
     Returns: The IPv4 Address count (up to 10) put into the array passed as the 1st parameter.
     
     Description: This function identifies all the IPv4 IP Addresses on
     the host and puts them into the array pointed to by it's only parameter.
     It SKIPS 127.0.0.1 and any IP Addressess starting with "169".
     
     The function will return up to 10 IP Addresses (array elements) as
     unsigned longs.  They can be converted to dot-decimal form by calling
     "db_inet_ntop()" with the 2nd parameter a pointer to the unsigned long
     to convert.
     
     */
    int get_ip4_list(unsigned long *);
    
    /* Returns the IPv4 address of a hostname pointed at by "hostname" */
    unsigned long db_get_host_ip_address(char *hostname);
    
    /* Returns an array of IPv4 addresses associated with the hostname */
    unsigned long *db_get_host_ip_addresses(char *hostname);

    
    /* String to number functions */
    
    short string_to_s(const char *string, size_t length);
    unsigned short string_to_us(const char *string, size_t length);
    int string_to_int( const char *string, size_t length);
    unsigned int string_to_uint( const char *string, size_t length);
    size_t string_to_size_t( const char *string, size_t length);
    unsigned long string_to_ul( const char *string, size_t length);
    unsigned long long string_to_ull( const char *string, size_t length);
    long long string_to_ll( const char *string, size_t length);
    /* Cross platform thread synchronization functions */
    
    int db_create_mutex(MUTEX *);
    int db_destroy_mutex( MUTEX *);
    int db_lock_mutex( MUTEX *mtx );
    int db_unlock_mutex( MUTEX *mtx );
    int db_sem_post( SEMAPHORE );
    int db_sem_wait( SEMAPHORE );
    SEMAPHORE db_create_sem( char *szsemname );
    int db_destroy_sem( SEMAPHORE );
    int db_destroy_sem_with_name( SEMAPHORE sem, char *szsemname );
    
    /*** DeedleBox Thread Library ***/
#ifndef _WIN32
    int db_create_thread( DB_THREAD_PROC start_routine, DB_THREAD_PARAM param, DB_THREAD *thread) ;
#else
    DWORD db_create_thread(DB_THREAD_PROC start_routine, DB_THREAD_PARAM param, DB_THREAD *thread);
#endif
    unsigned long long db_thread_join(DB_THREAD *thread);
    
    
    
#ifndef _WIN32
    int WSACleanup( void );
    int WSAStartup( WORD wVersionRequired, LPWSADATA lpWSAData);
#endif
    
    
#ifdef __cplusplus
}
#endif
#endif /* db_x_platform_h */
