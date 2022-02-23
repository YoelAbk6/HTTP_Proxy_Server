#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "threadpool.h"

/**
 * Creates a thread pool and initialize all of its values
 * @param num_threads_in_pool - Number of threads in the pool
 * @return A pointer to the new thread pool struct on success, NULL on failure
 */
threadpool *create_threadpool(int num_threads_in_pool) {
    if (0 < num_threads_in_pool && num_threads_in_pool <= MAXT_IN_POOL) {
        threadpool *pool = malloc(sizeof(threadpool));
        if (pool) {
            int i;
            pool->num_threads = num_threads_in_pool;
            pool->qsize = 0;
            pool->threads = malloc(sizeof(pthread_t) * num_threads_in_pool);
            if (!pool->threads) {
                free(pool);
                return NULL;
            }
            pool->qhead = pool->qtail = NULL;
            if (pthread_mutex_init(&pool->qlock, NULL))
                return NULL;
            if (pthread_cond_init(&(pool->q_not_empty), NULL))
                return NULL;
            if (pthread_cond_init(&(pool->q_empty), NULL))
                return NULL;
            pool->shutdown = 0;
            pool->dont_accept = 0;
            for (i = 0; i < num_threads_in_pool; i++) {
                if (pthread_create(&(pool->threads[i]), NULL, do_work, (void *) pool)) {
                    free(pool->threads);
                    free(pool);
                    return NULL;
                }
            }
            return pool;
        }
    }
    return NULL;
}


/**
 * Adds a work_t to the tail of the queue within the thread pool
 * @param from_me The tread pool struct holding the queue head and tail
 * @param curr The current work that has to be add to the list
 */
void enqueue(threadpool *from_me, work_t *curr) {
    if (!from_me->qtail) {
        from_me->qtail = curr;
        from_me->qhead = curr;
    } else {
        from_me->qtail->next = curr;
        from_me->qtail = curr;
    }
    from_me->qsize++;
}

/**
 * The function creates and initialize a new work_t and enters it to the queue
 * @param from_me The thread pool struct holding the queue head and tail
 * @param dispatch_to_here The dispatch_fn function that will be performed later
 * @param arg The dispatch_to_here function argument
 */
void dispatch(threadpool *from_me, dispatch_fn dispatch_to_here, void *arg) {
    pthread_mutex_lock(&from_me->qlock);
    if (from_me->dont_accept) {//If the destroying has begun
        pthread_mutex_unlock(&from_me->qlock);
        return;
    }
    pthread_mutex_unlock(&from_me->qlock);
    work_t *curr = malloc(sizeof(work_t));
    if (!curr) {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }
    curr->routine = dispatch_to_here;
    curr->arg = arg;
    curr->next = NULL;
    pthread_mutex_lock(&from_me->qlock);
    enqueue(from_me, curr);
    pthread_cond_signal(&from_me->q_not_empty);
    pthread_mutex_unlock(&from_me->qlock);
}


/**
 * dequeue from the head of the list
 * @param tail - list tail
 * @param head  - list head
 * @return the list head
 */
work_t *dequeue(threadpool *pool){
    work_t *curr_work = pool->qhead;
    if(!curr_work){
        return NULL;
    }
    pool->qhead = pool->qhead->next;
    pool->qsize--;
    if(!pool->qsize)
        pool->qtail = NULL;
    return curr_work;
}

/* The work function of the thread, runs the first work when there's an available thread
 * @param p The thread pool struct
 * @return
 */
void* do_work(void* p){
    threadpool *pool = (threadpool*)p;
    work_t *curr_work;
    while(1){
        pthread_mutex_lock(&pool->qlock);
        if(pool->shutdown) {
            pthread_mutex_unlock(&pool->qlock);
            return NULL;
        }
        if(!pool->qsize)
            pthread_cond_wait(&pool->q_not_empty, &pool->qlock);
        if(pool->shutdown) {
            pthread_mutex_unlock(&pool->qlock);
            return NULL;
        }
        if(!(curr_work = dequeue(pool))) {
            pthread_mutex_unlock(&pool->qlock);
            continue;
        }
        if(!pool->qsize && pool->dont_accept){
            pthread_cond_signal(&pool->q_empty);
        }
        pthread_mutex_unlock(&pool->qlock);
        curr_work->routine(curr_work->arg);
        free(curr_work);
    }
}


void destroy_threadpool(threadpool* destroyme){
    pthread_mutex_lock(&destroyme->qlock);
    destroyme->dont_accept = 1;
    if(destroyme->qsize)
        pthread_cond_wait(&destroyme->q_empty, &destroyme->qlock);
    destroyme->shutdown = 1;
    pthread_cond_broadcast(&destroyme->q_not_empty);
    pthread_mutex_unlock(&destroyme->qlock);
    for(int i = 0; i < destroyme->num_threads; i++)
        pthread_join(destroyme->threads[i], NULL);
    pthread_mutex_destroy(&destroyme->qlock);
    pthread_cond_destroy(&destroyme->q_not_empty);
    pthread_cond_destroy(&destroyme->q_empty);
    free(destroyme->threads);
    free(destroyme);
}