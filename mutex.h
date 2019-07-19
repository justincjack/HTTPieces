/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   mutex.h
 * Author: justinjack
 *
 * Created on July 10, 2019, 7:17 AM
 */

#ifndef MUTEX_H
#define MUTEX_H

#include <pthread.h>
#include <stdlib.h>

#define MUTEX_IS_INVALID                                    -7
#define MUTEX_NOT_OWNED                                     -6
#define MUTEX_FAILED                                        -3
#define MUTEX_INVALID_ARG                                   -2
#define MUTEX_BAD_MUTEX                                      0
#define MUTEX_SUCCESS                                        1
#define MUTEX_ALREADY_OWNED                                  2


typedef struct __mutex_ {
    int             mutex_valid; /*
                                  * If the mutex is valid, this will be set to 
                                  * ONE and can be locked.
                                  * 
                                  * If the mutex is being destoryed, this will
                                  * be ZERO, and it cannot be locked.
                                  * 
                                  **/ 
    
    pthread_t       current_owner;/*
                                   * The thread that has acquired the lock on
                                   * this mutex.
                                   **/
    
    int             lock_count;   /*
                                   * The lock count for the current thread
                                   * owner.
                                   **/
    
    pthread_mutex_t mutex;        /*
                                   * The mutex object.
                                   **/
} MUTEX, *PMUTEX;







#ifdef __cplusplus
extern "C" {
#endif


/* mutex_new( int lock_now )
 * 
 * This function create a new MUTEX locking/synchronization 
 * object.
 * 
 * PARAMETERS:
 *              lock_now - Set to NON-ZERO if the calling thread
 *                         should immediately obtain a lock on the
 *                         newly created object.
 * 
 *                         Set to ZERO if the newly created object
 *                         should be initialized in an unlocked
 *                         state.
 * 
 * RETURNS:
 *              On success, this function will return a pointer to a 
 *              newly created MUTEX object.
 * 
 *              MUTEX_FAILURE         - The mutex object could not be created.
 *                                    Possibly due to not having enough memory,
 *                                    or due to another (unspecified) error.
 * 
 **/
PMUTEX mutex_new( int lock_now );



/* mutex_retire( PMUTEX m )
 * 
 * Retires an MUTEX object.
 * 
 * First this function acquires a lock on the mutex to destroy. This
 * function WILL WAIT to to acquire the lock.  It calls mutex_lock().
 * 
 * When the lock is acquired, it marks the mutex as no longer valid so
 * no other threads can lock it.  It then unlocks the mutex and unregisters
 * its underlying components with the operating system.
 * 
 * If a program tries to call mutex_lock() on an MUTEX object that
 * has been retired, it will receive 'MUTEX_IS_INVALID'.
 * 
 * It does NOT free the memory associated with the mutex so that if any
 * other threads hold a reference to the mutex, they will simply not
 * be able to lock it, but they will not crash the program by trying
 * to access freed memory.
 * 
 * PARAMETERS:
 *              m - A reference to an MUTEX object to be destroyed
 * 
 * RETURNS:
 *              MUTEX_SUCCESS              - Success.  The mutex has been retired.
 * 
 *              MUTEX_INVALID_ARG          - The 'm' parameter was NULL.
 * 
 *              MUTEX_IS_INVALID           - mutex_retire() is being called on
 *                                           a mutex that has already been retired.
 * 
 *              MUTEX_FAILED               - There is something wrong with the mutex. Its
 *                                           state is indeterminate. This error could have 
 *                                           been raised during mutex_retire()'s
 *                                           attempt to lock the mutex, or during its
 *                                           subsequent attempt to retire it.  This 
 *                                           mutex should no longer be used.
 * 
 **/
int mutex_retire( PMUTEX m );



/* mutex_free( PMUTEX m )
 * 
 * This function frees the memory associated with the MUTEX
 * object referenced by the parameter 'm'.
 * 
 * If the mutex object is still valid, it calls mutex_retire()
 * first before freeing the memory associated with it.
 * 
 * If any other threads hold a reference to this mutex and try to
 * access it the behavior is unspecified and may cause the program
 * to crash.
 * 
 * PARAMETERS:
 *              m                           - The 'm' parameter was NULL
 * 
 * RETURNS:
 * 
 *              MUTEX_SUCCESS               - Success.  The mutex was destroyed (if it had
 *                                            not already been) and freed.  The memory
 *                                            allocated for the MUTEX structure has
 *                                            been released.
 * 
 *              MUTEX_INVALID_ARG           - 'm' was NULL
 * 
 *              MUTEX_FAILED                - An internal call to mutex_retire()
 *                                            failed and the mutex could not be freed.
 *                                            The memory, therefore associated with the
 *                                            MUTEX structure is still allocated.
 * 
 **/
int mutex_free( PMUTEX m );



/* mutex_lock( PMUTEX m)
 * 
 * Locks a protected resource for exclusive access.
 * 
 * PARAMETERS:
 *                  m       - A pointer to an MUTEX object created
 *                            with mutex_new()
 * 
 * RETURNS:         ( A positive value on success )
 * 
 *                  MUTEX_SUCCESS               - The calling thread now owns the mutex and 
 *                                                has exclusive access to the protected resource
 * 
 *                  MUTEX_ALREADY_OWNED         - This is SUCCESS, but be advised that
 *                                                the calling thread ALREADY owns the mutex and
 *                                                has exclusive access to the protected resource.
 * 
 *                  MUTEX_INVALID_ARG           - The argument 'm' was NULL
 * 
 *                  MUTEX_IS_INVALID            - The mutex passed as the argument 'm' is not
 *                                                valid.  It may have been destroyed by a call
 *                                                to mutex_retire() or mutex_free()
 * 
 *                  MUTEX_FAILED                - An unspecified error occured and you should not
 *                                                assume that you have exclusive access to the
 *                                                resource protected by the mutex 'm'
 * 
 **/
int mutex_lock( PMUTEX m);


/* mutex_unlock( PMUTEX m)
 * 
 * Unlocks a protected resource allowing other threads to obtain a lock
 * by calling mutex_lock()
 * 
 * PARAMETERS:
 *              m       - A pointer to an MUTEX object created with
 *                        mutex_new()
 * 
 * RETURNS:
 * 
 *              MUTEX_SUCCESS               - The mutex was successfully unlocked.
 * 
 *              MUTEX_INVALID_ARG           - 'm' was NULL
 * 
 *              MUTEX_NOT_OWNED             - Another thread has a lock
 *                                            on the specified mutex.
 * 
 *              MUTEX_FAILED                - An unspecified error occured and
 *                                            the mutex could not be unlocked.
 * 
 **/
int mutex_unlock( PMUTEX m);


#ifdef __cplusplus
}
#endif

#endif /* MUTEX_H */

