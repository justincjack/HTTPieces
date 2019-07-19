#include "mutex.h"


int mutex_retire( PMUTEX m ) {
    int r = 0;
    if (!m) return MUTEX_INVALID_ARG;
    
    if (!m->mutex_valid) return MUTEX_IS_INVALID;
    
    r = mutex_lock(m);
    if (r != MUTEX_SUCCESS && r != MUTEX_ALREADY_OWNED) {
        return r;
    }
    
    m->mutex_valid = 0;
    mutex_unlock(m);
    
    if (!pthread_mutex_destroy(&m->mutex)) {
        return MUTEX_SUCCESS;
    }
    return MUTEX_FAILED;
}

int mutex_free( PMUTEX m ) {
    int r = 0;
    if (!m) return MUTEX_INVALID_ARG;
    
    if (m->mutex_valid == 1) {
        r = mutex_retire(m);
        if (r!=MUTEX_SUCCESS) {
            return r;
        }
    }
    free(m);
    return MUTEX_SUCCESS;
}

PMUTEX mutex_new( int lock_now ) {
    pthread_mutexattr_t mta;
    PMUTEX mtx = (PMUTEX)malloc(sizeof(MUTEX));
    if (!mtx) return MUTEX_BAD_MUTEX;
    mtx->current_owner = 0;
    mtx->mutex_valid = 0;
    
    pthread_mutexattr_init(&mta);
    pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_DEFAULT);
    
    if (!pthread_mutex_init(&mtx->mutex, 0)) {
        if (lock_now) {
            if (!pthread_mutex_lock(&mtx->mutex)) {
                mtx->current_owner = pthread_self();
                mtx->mutex_valid = 1;
                return mtx;
            }
        }
        mtx->mutex_valid = 1;
        return mtx;
    }
    free(mtx);
    return MUTEX_BAD_MUTEX;
}

int mutex_lock( PMUTEX m ) {
    pthread_t this_thread = pthread_self();
    if (!m) return MUTEX_INVALID_ARG;
    if (!m->mutex_valid) {
        return MUTEX_IS_INVALID;
    }
    if (m->current_owner == this_thread) {
        m->lock_count++;
        return MUTEX_ALREADY_OWNED;
    }
    if (!pthread_mutex_lock(&m->mutex)) {
        m->lock_count = 0;
        m->current_owner = this_thread;
        return MUTEX_SUCCESS;
    }
    return MUTEX_FAILED;
}

int mutex_unlock( PMUTEX m ) {
    pthread_t this_thread = pthread_self();
    if (!m) return MUTEX_INVALID_ARG;
    if (m->current_owner != this_thread) {
        return MUTEX_NOT_OWNED;
    }
    
    /* If the current owner is trying to unlock it, and this is its last lock */
    if (m->current_owner == this_thread && m->lock_count == 0) {
        m->current_owner = 0;
    }
    
    if (m->lock_count > 0) {
        m->lock_count--;
        return MUTEX_SUCCESS;
    }
    
    /* Here, we know the owning thread is trying to unlock the mutex */
    
    /* Go ahead and clear the owner before the OS unlocks the 
     * mutex to avoid race conditions.
     */
    if (!pthread_mutex_unlock(&m->mutex)) {
        return MUTEX_SUCCESS;
    }
    /* We've fail to unlock the mutex, set its owner back */
    m->current_owner = this_thread;
    return MUTEX_FAILED;
}
