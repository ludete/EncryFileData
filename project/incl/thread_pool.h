#ifndef __THREAD_POOL_H_
#define __THREAD_POOL_H_

typedef struct thread_pool_t threadpool_t;

typedef void *(*task_func)(void *);


#define myprint( x...) do {char bufMessagePut_Stdout_[1024];\
        sprintf(bufMessagePut_Stdout_, x);\
        fprintf(stdout, "%s [%d], [%s]\n", bufMessagePut_Stdout_,__LINE__, __FILE__ );\
    }while (0) 


/**
* @function threadpool_create
* @descCreates a threadpool_t object.
* @param min_thr_num  thread num
* @param max_thr_num  max thread size
* @param queue_max_size   size of the queue.
* @return a newly created thread pool or NULL
*/
threadpool_t *threadpool_create(int min_thr_num, int max_thr_num, int queue_max_size);


/**
* @function threadpool_add
* @desc add a new task in the queue of a thread pool
* @param pool     Thread pool to which add the task.
* @param function Pointer to the function that will perform the task.
* @param argument Argument to be passed to the function.
* @return 0 if all goes well,else -1
*/
int threadpool_add(threadpool_t *pool, task_func function, void *arg);


/**
* @function threadpool_destroy
* @desc Stops and destroys a thread pool.
* @param pool  Thread pool to destroy.
* @return 0 if destory success else -1
*/
int threadpool_destroy(threadpool_t *pool);


/**
* @desc get the thread num
* @pool pool threadpool
* @return all of the thread Num of The Pool
*/
int threadpool_all_threadnum(threadpool_t *pool);



/**
* desc get the busy thread num
* @param pool threadpool
* return # of the busy thread of the pool
*/
int threadpool_busy_threadnum(threadpool_t *pool);



#endif