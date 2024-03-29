//
//  db_x_platform.c
//  Portaudio intercom
//
//  Created by Justin Jack on 8/16/18.
//  Copyright © 2018 Justin Jack. All rights reserved.
//
// https://github.com/justincjack/db-x-platform.git

// 3/27/19 1:50PM - Copied to Windows VS Studio "deedlecore" project.


#include <stdio.h>
#include <string.h>
#include "db_x_platform.h"

#ifndef _WIN32

int WSACleanup(void) {
    return 0;
}
int WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData) {
    return 0;
}
#else
#include <WS2tcpip.h>
#endif

/* Handle setting socket as non-blocking if "nonblock" is 1 */
SOCKET openudpsocket(unsigned short port, int nonblock) {
    SOCKET s = 0;
    WSADATA wsd;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);
    if (!wsastartup_been_called) {
        WSAStartup(MAKEWORD(2, 2), &wsd);
        wsastartup_been_called = 1;
    }
#ifdef _WIN32
    WSAStartup(MAKEWORD(2, 2), &wsd);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (bind(s, (struct sockaddr *) &sa, sizeof(struct sockaddr))) {
        closesocket(s);
        return 0;
    }
#else 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        return 0;
    }
    if (bind(s, (struct sockaddr *)&sa, sizeof(struct sockaddr)) == -1) {
        closesocket(s);
        return 0;
    }
#endif
    return s;
}

SOCKET opentcpsocket(unsigned short port, int nonblock) {
    SOCKET s = 0;
    WSADATA wsd;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);
    if (!wsastartup_been_called) {
        WSAStartup(MAKEWORD(1, 1), &wsd);
        wsastartup_been_called = 1;
    }
#ifdef _WIN32
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind(s, (struct sockaddr *) &sa, sizeof(struct sockaddr))) {
        closesocket(s);
        return 0;
    }
#else 
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        return 0;
    }
    if (bind(s, (struct sockaddr *)&sa, sizeof(struct sockaddr)) == -1) {
        closesocket(s);
        return 0;
    }
#endif
    return s;
}


int db_send(SOCKET s, char *buff, size_t bufflen, int flags) {
#ifdef _WIN32
    return send(s, (const char *)buff, (int)bufflen, flags);
#else
    return (int)send(s, (const void *)buff, bufflen, flags);
#endif
}



int SetSocketBlockingEnabled(SOCKET fd, int blocking) {
    if (fd < 0) return 0;
#ifdef _WIN32
    unsigned long mode = blocking ? 0 : 1;
    return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? 1 : 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return 0;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return (fcntl(fd, F_SETFL, flags) == 0) ? 1 : 0;
#endif
}



int set_socket_keepalive(SOCKET s) {/*}, int level, int optname, void *optval, int optlen) {*/
    int ka_opt = 1;
#ifdef _WIN32
    int ka_opt_size = sizeof(ka_opt);
#else
    socklen_t ka_opt_size = sizeof(ka_opt);
#endif
    return setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&ka_opt, ka_opt_size);
}


/* Connect a TCP socket by unsigned long ip address with keep-alive flag on socket */
SOCKET ltcpconnectka(unsigned long ipaddress, unsigned short port, int nonblock) {
    SOCKET s = 0;
    struct sockaddr_in sa;
    socklen_t socklen = 0;
#ifdef _WIN32
    WSADATA wsd;
#endif
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
#ifndef _WIN32
    s = socket(AF_INET, SOCK_STREAM, 0);
    set_socket_keepalive(s);
    sa.sin_addr.s_addr = (in_addr_t)ipaddress;
    socklen = sizeof(struct sockaddr);
    if (connect(s, (const struct sockaddr *)&sa, socklen) != 0) {
        switch (errno) {
            case EADDRINUSE:
                perror("\n** Error: EADDRINUSE\n");
                break;
            case EADDRNOTAVAIL:
                perror("\n** Error: EADDRNOTAVAIL\n");
                break;
            case EAFNOSUPPORT:
                perror("\n** Error: EAFNOSUPPORT\n");
                break;
            case EAGAIN:
                perror("\n** Error: EAGAIN\n");
                break;
            case EALREADY:
                perror("\n** Error: EALREADY\n");
                break;
            case ECONNREFUSED:
                perror("\n** Error: ECONNREFUSED\n");
                break;
            case EFAULT:
                perror("\n** Error: EFAULT\n");
                break;
            case EINPROGRESS:
                perror("\n** Error: EINPROGRESS\n");
                break;
            case EINTR:
                perror("\n** Error: EINTR\n");
                break;
            case EISCONN:
                perror("\n** Error: EISCONN\n");
                break;
            case ENOTSOCK:
                perror("\n** Error: ENOTSOCK\n");
                break;
            case ETIMEDOUT:
                perror("\n** Error: ETIMEDOUT\n");
                break;
            default:
                perror("\n** Error: DEFAULT\n");
                break;
        }
        closesocket(s);
        return 0;
    } else {
        printf("tcpconnect(): Connected to %s:%u OKAY!\n\n", ipaddress, port);
    }
    if (nonblock) {
        SetSocketBlockingEnabled(s, 0);
    }
#else  
    if (!wsastartup_been_called) {
        WSAStartup(MAKEWORD(2, 2), &wsd);
        wsastartup_been_called = 1;
    }
    //    if (db_inet_pton(AF_INET, ipaddress, &sa.sin_addr.S_un.S_addr) != 1) {
    //        char err[250];
    //        sprintf(err, "tcpconnect(): InetPtonA() failed converting IP Address \"%s\"\n", ipaddress);
    //        perror(err);
    //        return 0;
    //    }
    sa.sin_addr.S_un.S_addr = ipaddress;
    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!s) return 0;
    set_socket_keepalive(s);
    if (connect(s, (struct sockaddr *) &sa, sizeof(struct sockaddr)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    if (nonblock) {
        SetSocketBlockingEnabled(s, 0);
    }
#endif
    return s;
}





SOCKET ltcpconnect(unsigned long ipaddress, unsigned short port, int nonblock) {
    SOCKET s = 0;
    struct sockaddr_in sa;
    socklen_t socklen = 0;
#ifdef _WIN32
    WSADATA wsd;
#endif
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
#ifndef _WIN32
    s = socket(AF_INET, SOCK_STREAM, 0);
    sa.sin_addr.s_addr = (in_addr_t)ipaddress;
    socklen = sizeof(struct sockaddr);
    if (connect(s, (const struct sockaddr *)&sa, socklen) != 0) {
        switch (errno) {
            case EADDRINUSE:
                perror("\n** Error: EADDRINUSE\n");
                break;
            case EADDRNOTAVAIL:
                perror("\n** Error: EADDRNOTAVAIL\n");
                break;
            case EAFNOSUPPORT:
                perror("\n** Error: EAFNOSUPPORT\n");
                break;
            case EAGAIN:
                perror("\n** Error: EAGAIN\n");
                break;
            case EALREADY:
                perror("\n** Error: EALREADY\n");
                break;
            case ECONNREFUSED:
                perror("\n** Error: ECONNREFUSED\n");
                break;
            case EFAULT:
                perror("\n** Error: EFAULT\n");
                break;
            case EINPROGRESS:
                perror("\n** Error: EINPROGRESS\n");
                break;
            case EINTR:
                perror("\n** Error: EINTR\n");
                break;
            case EISCONN:
                perror("\n** Error: EISCONN\n");
                break;
            case ENOTSOCK:
                perror("\n** Error: ENOTSOCK\n");
                break;
            case ETIMEDOUT:
                perror("\n** Error: ETIMEDOUT\n");
                break;
            default:
                perror("\n** Error: DEFAULT\n");
                break;
        }
        //        printf("tcpconnect(): connect() failed...\n");
        closesocket(s);
        return 0;
    } else {
        //        printf("tcpconnect(): Connected to %s:%u OKAY!\n\n", ipaddress, port);
    }
    if (nonblock) {
        SetSocketBlockingEnabled(s, 0);
    }
#else
    if (!wsastartup_been_called) {
        WSAStartup(MAKEWORD(2, 2), &wsd);
        wsastartup_been_called = 1;
    }
    //    if (db_inet_pton(AF_INET, ipaddress, &sa.sin_addr.S_un.S_addr) != 1) {
    //        char err[250];
    //        sprintf(err, "tcpconnect(): InetPtonA() failed converting IP Address \"%s\"\n", ipaddress);
    //        perror(err);
    //        return 0;
    //    }
    sa.sin_addr.S_un.S_addr = ipaddress;
    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!s) return 0;
    if (connect(s, (struct sockaddr *) &sa, sizeof(struct sockaddr)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    if (nonblock) {
        SetSocketBlockingEnabled(s, 0);
    }
#endif
    return s;
}




SOCKET tcpconnect(char *ipaddress, unsigned short port, int nonblock) {
    SOCKET s = 0;
    struct sockaddr_in sa;
    socklen_t socklen = 0;
#ifdef _WIN32
    WSADATA wsd;
#endif
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
#ifndef _WIN32
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (!inet_pton(AF_INET, ipaddress, &sa.sin_addr)) {
        return 0;
    }
    //    printf("tcpconnect(): %s:%u\n", ipaddress, port);
    socklen = sizeof(struct sockaddr);
    if (connect(s, (const struct sockaddr *)&sa, socklen) != 0) {
        //        printf("\ttcpconnect(): FAILED: %s:%u\n", ipaddress, port);
        switch (errno) {
            case EADDRINUSE:
                perror("\n** Error: EADDRINUSE\n");
                break;
            case EADDRNOTAVAIL:
                perror("\n** Error: EADDRNOTAVAIL\n");
                break;
            case EAFNOSUPPORT:
                perror("\n** Error: EAFNOSUPPORT\n");
                break;
            case EAGAIN:
                perror("\n** Error: EAGAIN\n");
                break;
            case EALREADY:
                perror("\n** Error: EALREADY\n");
                break;
            case ECONNREFUSED:
                perror("\n** Error: ECONNREFUSED\n");
                break;
            case EFAULT:
                perror("\n** Error: EFAULT\n");
                break;
            case EINPROGRESS:
                perror("\n** Error: EINPROGRESS\n");
                break;
            case EINTR:
                perror("\n** Error: EINTR\n");
                break;
            case EISCONN:
                perror("\n** Error: EISCONN\n");
                break;
            case ENOTSOCK:
                perror("\n** Error: ENOTSOCK\n");
                break;
            case ETIMEDOUT:
                perror("\n** Error: ETIMEDOUT\n");
                break;
            default:
                perror("\n** Error: DEFAULT\n");
                break;
        }
        //        printf("tcpconnect(): connect() failed...\n");
        closesocket(s);
        return 0;
    } else {
        //        printf("tcpconnect(): Connected to %s:%u OKAY!\n\n", ipaddress, port);
    }
    if (nonblock) {
        SetSocketBlockingEnabled(s, 0);
    }
#else
    if (!wsastartup_been_called) {
        WSAStartup(MAKEWORD(2, 2), &wsd);
        wsastartup_been_called = 1;
    }
    if (db_inet_pton(AF_INET, ipaddress, &sa.sin_addr.S_un.S_addr) != 1) {
        char err[250];
        sprintf(err, "tcpconnect(): InetPtonA() failed converting IP Address \"%s\"\n", ipaddress);
        perror(err);
        return 0;
    }
    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!s) return 0;
    if (connect(s, (struct sockaddr *) &sa, sizeof(struct sockaddr)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    if (nonblock) {
        SetSocketBlockingEnabled(s, 0);
    }
#endif
    return s;
}



int db_create_mutex(MUTEX *mtx) {
#ifndef _WIN32
    pthread_mutexattr_t mta;
    pthread_mutexattr_init(&mta);
    pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(mtx, &mta);
#else
    *mtx = CreateMutex(0, 0, 0);
#endif
    return 1;
}


int db_destroy_mutex(MUTEX *mtx) {
    int retval = 0;
#ifndef _WIN32
    retval = pthread_mutex_destroy(mtx);
#else
    retval = CloseHandle(*mtx);
#endif
    return retval;
}

int db_lock_mutex(MUTEX *mtx) {
    int retval = 0;
#ifndef _WIN32
    retval = pthread_mutex_lock(mtx);
#else
    retval = (int)WaitForSingleObject(*mtx, INFINITE);
#endif
    return retval;
}


int db_unlock_mutex(MUTEX *mtx) {
    int retval = 0;
#ifndef _WIN32
    retval = pthread_mutex_unlock(mtx);
#else
    retval = (int)ReleaseMutex(*mtx);
#endif
    return retval;
}



#ifndef _WIN32
int db_sem_post(SEMAPHORE sem) {
    return sem_post(sem);
}

int db_sem_wait(SEMAPHORE sem) {
    return sem_wait(sem);
}

SEMAPHORE db_create_sem(char *szsemname) {
    char semname[256];
    if (!szsemname) {
        printf("*** db_create_sem() failed. No valid value passed!\n");
        return 0;
    }
    semname[0] = '/';
    sprintf(&semname[1], "%s", szsemname);
    sem_unlink(semname);
    return sem_open(semname, O_CREAT, 0777, 0);
}

int db_destroy_sem(SEMAPHORE sem) {
    return sem_close(sem);
}

int db_destroy_sem_with_name(SEMAPHORE sem, char *szsemname) {
    char semname[256];
    size_t i = 0;
    if (szsemname) {
        semname[0] = '/';
        for (i = 1; (i - 1) <= strlen((const char *)szsemname); i++)
            semname[i] = szsemname[i - 1];
    }
    sem_close(sem);
    return ((szsemname) ? sem_unlink(semname) : 1);
}

#else
int db_sem_post(SEMAPHORE sem) {
    return ReleaseSemaphore(sem, 1, 0);
}
int db_sem_wait(SEMAPHORE sem) {
    return WaitForSingleObject(sem, INFINITE);
}
SEMAPHORE db_create_sem(char *szsemname) {
    return CreateSemaphore(0, 1, 1, 0);
}
int db_destroy_sem(SEMAPHORE sem) {
    return CloseHandle(sem);
}
int db_destroy_sem_with_name(SEMAPHORE sem, char *szsemname) {
    return CloseHandle(sem);
}
#endif



#ifndef _WIN32
int db_create_thread(DB_THREAD_PROC start_routine, DB_THREAD_PARAM param, DB_THREAD *thread) {
    if (!pthread_create(thread, 0, start_routine, param)) {
        return 1;
    }
    return 0;
}

unsigned long long db_thread_join(DB_THREAD *thread) {
    void *retval = 0;
    pthread_join(*thread, &retval);
    return((retval != 0) ? (unsigned long long)*(unsigned long long *)retval : 0);
}

#else

DWORD db_create_thread(DB_THREAD_PROC start_routine, DB_THREAD_PARAM param, DB_THREAD *thread) {
    DWORD tid = 0;
    *thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)start_routine, param, 0, &tid);
    if (*thread) return 1;
    return 0;
}
unsigned long long db_thread_join(DB_THREAD *thread) {
    return (unsigned long long)WaitForSingleObject(*thread, INFINITE);
}
#endif



int db_inet_pton(int family, char *ipaddr, void *paddress) {
#ifdef _WIN32
    return InetPton(family, (PTSTR)ipaddr, (PVOID)paddress);
#else
    return inet_pton(family, (const char *)ipaddr, paddress);
#endif
}

char *db_inet_ntop(int family, void *paddress, char *outputstring, size_t buffersize) {
#ifdef _WIN32
    return (char *)InetNtop(family, (PVOID)paddress, (PTSTR)outputstring, buffersize);
#else
    return (char *)inet_ntop(family, paddress, outputstring, (socklen_t)buffersize);
#endif
}



unsigned long *db_get_host_ip_addresses(char *hostname) {
    size_t ctr = 0;
    unsigned long *address_list = 0;
#ifdef _WIN32
    ADDRINFOA hints;
    ADDRINFOA *paddrinfo = 0;
    WSADATA wsd;
    if (!wsastartup_been_called) {
        WSAStartup(MAKEWORD(2, 2), &wsd);
        wsastartup_been_called = 1;
    }
    
#else
    struct hostent *he = 0;
    struct in_addr **addr_list = 0;
#endif
    if (!hostname) return 0;
#ifndef _WIN32
    he = gethostbyname(hostname);
    if (he) {
        addr_list = (struct in_addr **)he->h_addr_list;
        /* Add an extra spot for NULL, so we know when we're done with valid IP addresses */
        address_list = (unsigned long *)calloc((he->h_length + 1), sizeof(unsigned long));
        for (ctr = 0; addr_list[ctr] != 0; ctr++) {
            address_list[ctr] = (*addr_list[ctr]).s_addr;
        }
        return address_list;
    }
    return 0;
#else
    memset(&hints, 0, sizeof(ADDRINFOA));
    hints.ai_family = AF_INET;
    if (!getaddrinfo(hostname, "", &hints, &paddrinfo)) {
        if (paddrinfo) {
            char ip[100];
            DWORD iplen = 100;
            LPSOCKADDR sockaddr_ip;
            ADDRINFOA *ptr = 0;
            size_t count = 0;
            unsigned long *address_list = 0;
            for (ptr = paddrinfo; ptr != 0; ptr = ptr->ai_next) {
                count++;
            }
            if (count == 0) return 0;
            address_list = (unsigned long *)calloc((count + 1), sizeof(unsigned long));
            count = 0;
            for (ptr = paddrinfo; ptr != 0; ptr = ptr->ai_next) {
                sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
                iplen = 100;
                WSAAddressToStringA(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
                                    ip, &iplen);
                db_inet_pton(AF_INET, ip, &address_list[count++]);
            }
            freeaddrinfo(paddrinfo);
            return address_list;
        }
    } else {
        printf("db_get_host_ip_addresses(): getaddrinfo() failed.\n");
    }
#endif
    return 0;
}



unsigned long db_get_host_ip_address(char *hostname) {
#ifdef _WIN32
    ADDRINFOA hints;
    ADDRINFOA *paddrinfo = 0;
#else
    struct hostent *he = 0;
    struct in_addr **addr_list = 0;
#endif
    if (!hostname) return 0;
#ifndef _WIN32
    he = gethostbyname(hostname);
    if (he) {
        addr_list = (struct in_addr **)he->h_addr_list;
        if (addr_list[0] != 0) {
            return (*addr_list[0]).s_addr;
        }
    }
    return 0;
#else
    memset(&hints, 0, sizeof(ADDRINFO));
    hints.ai_family = AF_INET;
    if (!getaddrinfo(hostname, 0, &hints, &paddrinfo)) {
        if (paddrinfo) {
            char ip[100];
            DWORD iplen = 100;
            LPSOCKADDR sockaddr_ip;
            struct sockaddr_in sa;
            ADDRINFO *ptr = 0;
            for (ptr = paddrinfo; ptr != 0; ptr = paddrinfo->ai_next) {
                sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
                iplen = 100;
                WSAAddressToStringA(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
                                    ip, &iplen);
                db_inet_pton(AF_INET, ip, &sa.sin_addr.S_un.S_addr);
                break;
            }
            freeaddrinfo(paddrinfo);
            return sa.sin_addr.S_un.S_addr;
        }
    }
#endif
    return 0;
}


/* The parameter this takes should be defined as: unsigned long iplist[10] */
int get_ip4_list(unsigned long *list) {
#ifdef _WIN32
    ADDRINFOA hints;
    ADDRINFOA *paddrinfo = 0;
#endif
    
    struct ifaddrs *interfaces = 0;
    struct sockaddr_in *addr = 0;
    char ipaddress[100], netmask[100], broadcast[100];
    ipaddress[0] = 0;
    netmask[0] = 0;
    broadcast[0] = 0;
    int element = 0;
    memset(list, 0, sizeof(unsigned long *) * 10);
#ifndef _WIN32
    if (getifaddrs(&interfaces) == 0) {
        do {
            if (interfaces->ifa_addr->sa_family == AF_INET) {
                addr = (struct sockaddr_in *)interfaces->ifa_addr;
                if (addr->sin_addr.s_addr != ntohl(0x7f000001)) {
                    db_inet_ntop(AF_INET, &addr->sin_addr, ipaddress, 100);
                    if (strncmp(ipaddress, "169", 3)) {
                        list[element++] = addr->sin_addr.s_addr;
                        if (element == 10) break;
                    }
                }
            }
        } while ((interfaces = interfaces->ifa_next) != 0);
    }
#else
    memset(&hints, 0, sizeof(ADDRINFO));
    hints.ai_family = AF_INET;
    if (!getaddrinfo("", 0, &hints, &paddrinfo)) {
        if (paddrinfo) {
            char ip[100];
            DWORD iplen = 100;
            LPSOCKADDR sockaddr_ip;
            struct sockaddr_in sa;
            ADDRINFO *ptr = 0;
            //printf("Success!\n");
            for (ptr = paddrinfo; ptr != 0; ptr = paddrinfo->ai_next) {
                sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
                iplen = 100;
                WSAAddressToStringA(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
                                    ip, &iplen);
                //printf("IP Address found: %s\n", ip);
                db_inet_pton(AF_INET, ip, &sa.sin_addr.S_un.S_addr);
                list[element++] = sa.sin_addr.S_un.S_addr;
                if (element == 10) break;
            }
            freeaddrinfo(paddrinfo);
        }
    } else {
        printf("get_ip4_list() failed.\n");
    }
#endif
    return element;
}


/* String to number functions */
short string_to_s(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (short)strtol(string, &endptr, 10);
}

unsigned short string_to_us(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (unsigned short)strtoul(string, &endptr, 10);
}

int string_to_int(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (int)strtoll(string, &endptr, 10);
}

unsigned int string_to_uint(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (unsigned int)strtoull(string, &endptr, 10);
}


size_t string_to_size_t(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (size_t)strtoull(string, &endptr, 10);
}

unsigned long string_to_ul(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (unsigned long)strtoul(string, &endptr, 10);
}

unsigned long long string_to_ull(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (unsigned long long)strtoull(string, &endptr, 10);
}

long long string_to_ll(const char *string, size_t length) {
    char *endptr;
    if (!string) return 0;
    endptr = (char *)&string[length];
    return (long long)strtoll(string, &endptr, 10);
}

