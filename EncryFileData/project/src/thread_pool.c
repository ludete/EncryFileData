#include <stdlib.h> 
#include <pthread.h> 
#include <unistd.h> 
#include <assert.h> 
#include <stdio.h> 
#include <string.h> 
#include <signal.h> 
#include <errno.h> 
#include <stdbool.h>
#include <stdint.h>

#include "thread_pool.h"
#include "include_sub_function.h"


#define DEFAULT_TIME 10 				/*10s检测一次*/ 
#define MIN_WAIT_TASK_NUM 10			/*如果queue_size > MIN_WAIT_TASK_NUM 添加新的线程到线程池*/  
#define DEFAULT_THREAD_VARY 3 		 	/*每次创建和销毁线程的个数*/ 



/* 各子线程任务结构体 */ 
typedef struct {

	task_func func;			 		  /* 函数指针，回调函数 */	  
	void *arg;						  /* 上面函数的参数 */ 

} threadpool_task_t; 	

/* 描述线程池相关信息 */ 
struct thread_pool_t {
	pthread_mutex_t 	lock;			   		/* 用于锁住本结构体 */
	pthread_mutex_t 	thread_counter;	   		/* 记录忙状态线程个数的锁 -- busy_thr_num */
	pthread_cond_t 		queue_not_full; 	    /* 当任务队列满时，添加任务的线程阻塞，等待此条件变量 */
	pthread_cond_t 		queue_not_empty;	 	/* 任务队列里不为空时，通知等待任务的线程 */
	pthread_t 			*threads;				/* 存放线程池中每个线程的tid。数组 */
	pthread_t 			adjust_tid;				/* 存管理线程tid */
	threadpool_task_t   *task_queue;	   		/* 任务队列(数组首地址) */
	int 				min_thr_num; 			/* 线程池最小线程数 */
	int 				max_thr_num;			/* 线程池最大线程数 */
	int 				live_thr_num;			/* 当前存活线程个数 */
	int 				busy_thr_num;			/* 忙状态线程个数 */
	int 				wait_exit_thr_num; 		/* 要销毁的线程个数 */
	int 				queue_front;			/* task_queue队头下标 */
	int 				queue_rear;				/* task_queue队尾下标 */
	int 				queue_size;				/* task_queue队中实际任务数 */
	int 				queue_max_size;			/* task_queue队列可容纳任务数上限 */
	bool 				shutdown;				/* 标志位，线程池使用状态，true : 销毁线程池, false : 不销毁*/
};

/*线程池任务线程 执行方法
*@param : 该线程池句柄
*/
void *threadpool_thread(void *threadpool);

/*管理线程 执行方法
*@param : The threadPool point
*/
void *adjust_thread(void *threadpool);

/*查看线程是否存活,
*@param : tid  The thread ID
*/
bool is_thread_alive(pthread_t tid);			

/*释放线程池
*@param : The threadPool point
*/
int threadpool_free(threadpool_t *pool); 



threadpool_t *threadpool_create(int min_thr_num, int max_thr_num, int queue_max_size)
{
	int i = 0;
	threadpool_t *pool = NULL;			

	do{

		//1.init The thread_pool struct
		if((pool = (threadpool_t *)malloc(sizeof(threadpool_t))) == NULL)
		{
			myprint("Err : func malloc() pool : %p", pool);
			return pool;
		}

		pool->min_thr_num = min_thr_num;
		pool->max_thr_num = max_thr_num;
		pool->queue_max_size = queue_max_size;
		pool->busy_thr_num = 0;
		pool->live_thr_num = min_thr_num;
		pool->wait_exit_thr_num = 0;
		pool->queue_size = 0;
		pool->queue_front = 0;
		pool->queue_rear = 0;
		pool->shutdown = false;

		//2. The  Thread array 
		if((pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * max_thr_num)) == NULL)
		{
			myprint("Err : func malloc() pool->threads : %p", pool->threads);
			break;
		}
		memset(pool->threads, 0, sizeof(pthread_t)*min_thr_num);

		//3. The task queue array
		if((pool->task_queue = (threadpool_task_t *)malloc(sizeof(threadpool_task_t)*queue_max_size)) == NULL)
		{
			myprint("Err : func malloc() pool->task_queue : %p", pool->task_queue);
			break;
		}
		memset(pool->task_queue, 0, sizeof(threadpool_task_t)*queue_max_size );
	
	
		//4. init The pthread_mutex_t and pthread_cond
		if(pthread_mutex_init(&(pool->lock), NULL) != 0 || 
			pthread_mutex_init(&(pool->thread_counter), NULL) != 0 ||
			pthread_cond_init(&(pool->queue_not_empty), NULL) != 0 ||
			pthread_cond_init(&(pool->queue_not_full), NULL) != 0)
		{
			myprint("Err : func pthread_mutex_init() or func pthread_cond_init()");
			break;
		}

		for(i = 0; i < min_thr_num; i++)
			pthread_create(&(pool->threads[i]), NULL, threadpool_thread, (void *)pool);
		pthread_create(&pool->adjust_tid, NULL, adjust_thread, (void*)pool);

		return pool;
		
	}while(0);	
	
	if(pool) 		 threadpool_free(pool);


	return NULL;
}


int threadpool_add(threadpool_t *pool, task_func function, void *arg)
{
	pthread_mutex_lock(&(pool->lock));

	//1. 队列满, 调用wait 阻塞  (此处是否会阻塞)
	while((pool->queue_size == pool->queue_max_size) && (!pool->shutdown))
		pthread_cond_wait(&(pool->queue_not_full), &(pool->lock));

	if(pool->shutdown)			//线程池可用; (此处不太懂)
	{
		pthread_cond_broadcast(&(pool->queue_not_empty));
		pthread_mutex_unlock(&(pool->lock));
		return 0;
	}

	//2. 清空  工作线程 回调函数的 参数
	if(pool->task_queue[pool->queue_rear].arg != NULL)
		pool->task_queue[pool->queue_rear].arg = NULL;


	//3. 添加任务到队列
	pool->task_queue[pool->queue_rear].func = function;
	pool->task_queue[pool->queue_rear].arg = arg;
	pool->queue_rear = (pool->queue_rear + 1) % pool->queue_max_size;
	pool->queue_size++;

	//4. 添加完任务后, 唤醒线程池中等待处理任务的工作线程
	pthread_cond_broadcast(&(pool->queue_not_empty));
	pthread_mutex_unlock(&(pool->lock));

	return 0;
}


//线程池任务线程 执行方法; 
//该执行方法的特点: 1.同一时刻, 只有一条线程可以获取 任务队列中的任务(通过互斥锁); 2. 获取任务后, 立即释放该互斥锁(使其它线程可以去获取任务), 接下来执行获取的任务;
void *threadpool_thread(void * threadpool)
{
	threadpool_t *pool = (threadpool_t *)threadpool;
	threadpool_task_t task;
	pthread_detach(pthread_self());
	
	while(true)
	{
		pthread_mutex_lock(&(pool->lock));


		//1.当无任务时, 阻塞该条件变量, 有任务, 则跳过
		while((pool->queue_size == 0) && (!pool->shutdown))
		{
			pthread_cond_wait(&(pool->queue_not_empty), &(pool->lock));

			//2.清除指定数目的空闲线程, 
			if(pool->wait_exit_thr_num > 0)
			{
				pool->wait_exit_thr_num--;		//注意: 只有当符合下步条件时, 才会导致线程真正退出

				//线程池的存活线程个数 大于 最小值, 才可以结束当前线程
				if(pool->live_thr_num > pool->min_thr_num)
				{
					pool->live_thr_num--;
					pthread_mutex_unlock(&(pool->lock));
					pthread_exit(NULL);
				}
			}
		}

		//2. 指定了 true, 要关闭线程池的 每个线程, 自行退出处理 -- 销毁线程池
		if(pool->shutdown)
		{
			pthread_mutex_unlock(&(pool->lock));
			myprint("Thread 0x%x is exit", (unsigned int)pthread_self());					
			pthread_exit(NULL);
		}
		
		//3. 上述两种情况都不符合, 即有任务需要执行
		task.func = pool->task_queue[pool->queue_front].func;
		task.arg = pool->task_queue[pool->queue_front].arg;		
		pool->queue_size--;
		pool->queue_front = (pool->queue_front + 1)%pool->queue_max_size;

		//通知添加新任务进入队列
		pthread_cond_broadcast(&(pool->queue_not_full));
		pthread_mutex_unlock(&(pool->lock));		//任务取出后, 立即释放互斥锁,

		//执行任务
		pthread_mutex_lock(&(pool->thread_counter));
		pool->busy_thr_num++;
		pthread_mutex_unlock(&(pool->thread_counter));

//		myprint("Thread : 0x%x start working", (unsigned int)pthread_self());
		task.func(task.arg);		//执行回调任务
		
		pthread_mutex_lock(&(pool->thread_counter));
		pool->busy_thr_num--;
		pthread_mutex_unlock(&(pool->thread_counter));

		//下行代码为测试修改, 完了之后立即删除
		//pthread_exit(NULL);
	}


	pthread_exit(NULL);
}


//管理线程
void *adjust_thread(void * threadpool)
{
	int i = 0;
	threadpool_t  *pool = (threadpool_t*)threadpool;
	//pthread_detach(pthread_self());
	
	//线程池的工作 过程
	while(!pool->shutdown)
	{		
		
		sleep(DEFAULT_TIME);
		
		pthread_mutex_lock(&(pool->lock));
		int queue_size = pool->queue_size;
		int live_thr_num = pool->live_thr_num;
		pthread_mutex_unlock(&(pool->lock));
		
		pthread_mutex_lock(&(pool->thread_counter));
		int busy_thr_num = pool->busy_thr_num;
		pthread_mutex_unlock(&(pool->thread_counter));

		//创建新线程算法 : 任务数大于最小线程个数, 且存活的线程个数 小与最大线程数
		if(queue_size > MIN_WAIT_TASK_NUM && live_thr_num < pool->max_thr_num)
		{
			pthread_mutex_lock(&(pool->lock));
			int add = 0;

			//一次增加 DEFAULT_THREAD_VARY 个线程
			for(i = 0; i < pool->max_thr_num && pool->live_thr_num < pool->max_thr_num
				&& add < DEFAULT_THREAD_VARY; i++)
			{
				pthread_create(&(pool->threads[pool->live_thr_num]), NULL, threadpool_thread, (void*)pool);
				add++;
				pool->live_thr_num++;
			}		
			pthread_mutex_unlock(&(pool->lock));
		}

#if 1
	//注销本段代码, 是因为:测试阶段属于小任务量, 每次都走这个分支, 进行线程销毁子线程(默认每次销毁10个),测不出下面销毁方法的功能 
		//销毁多余空闲线程的算法 : 忙线程X2 小于 存活的线程数 且 存活的线程数 大于 最小线程数时
		if(busy_thr_num * 2 < live_thr_num && live_thr_num < pool->max_thr_num)
		{
			pthread_mutex_lock(&(pool->lock));
			pool->wait_exit_thr_num = DEFAULT_THREAD_VARY;
			pthread_mutex_unlock(&(pool->lock));		
			//通知一定数量的线程, 让其自行终止
			for(i = 0; i < DEFAULT_THREAD_VARY; i++)
			{			
				pthread_cond_signal(&(pool->queue_not_empty));
			}
		}
#endif			
	}
	
	printf("\n\n adjust_thread exit !!!! \n\n");
	pthread_exit(NULL);
	
	return NULL;

}


int threadpool_destroy(threadpool_t *pool)
{
	int i = 0, ret = 0;
	if(pool == NULL)		return -1;
		

	//1. 修改句柄, 进行线程销毁
	pool->shutdown = true;

	//2. 先销毁管理线程, 该线程没有被分离, 需要进行回收		
	pthread_join(pool->adjust_tid, NULL);

	//3. 通知所有任务线程, 进行销毁
	for(i = 0; i < pool->live_thr_num; i++)	
		pthread_cond_broadcast(&(pool->queue_not_empty));

	//4. 因为子线程分离, 所以销毁子线程时, 不需要进行回收;
	//for(i = 0; i < pool->live_thr_num; i++)
	//	pthread_join(pool->threads[i], NULL);		
	
	//5. 销毁句柄
	if((ret = threadpool_free(pool)) < 0)	
		myprint("Err : func threadpool_free() ");			
	

	return ret;
}


int threadpool_free(threadpool_t * pool)
{
	if(!pool)
	{
		myprint("Err : pool : %p ", pool);
		return -1;
	}

	if(pool->task_queue)
		free(pool->task_queue);

	if(pool->threads)
	{	
		free(pool->threads);
		pthread_mutex_destroy(&(pool->lock));
		pthread_mutex_destroy(&(pool->thread_counter));
		pthread_cond_destroy(&(pool->queue_not_full));
		pthread_cond_destroy(&(pool->queue_not_empty));
	}
	
	free(pool);
	pool = NULL;
	myprint("func threadpool_free() end ...");
	
	return 0;
}

int threadpool_busy_threadnum(threadpool_t * pool)
{
	int busy_thr_num = -1;
	pthread_mutex_lock(&(pool->lock));
	busy_thr_num = pool->busy_thr_num;
	pthread_mutex_unlock(&(pool->lock));
	
	return busy_thr_num;
}


int threadpool_all_threadnum(threadpool_t *pool)
{
	int all_thr_num = -1;
	pthread_mutex_lock(&(pool->lock));
	all_thr_num = pool->live_thr_num;
	pthread_mutex_unlock(&(pool->lock));
	
	return all_thr_num;

}

bool is_thread_alive(pthread_t tid)
{
	int kill_rc = pthread_kill(tid, 0);		//发0号信号，测试线程是否存活
	if(kill_rc == ESRCH)
		return false;
	return true;
}

