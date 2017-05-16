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


#define DEFAULT_TIME 10 				/*10s���һ��*/ 
#define MIN_WAIT_TASK_NUM 10			/*���queue_size > MIN_WAIT_TASK_NUM ����µ��̵߳��̳߳�*/  
#define DEFAULT_THREAD_VARY 3 		 	/*ÿ�δ����������̵߳ĸ���*/ 



/* �����߳�����ṹ�� */ 
typedef struct {

	task_func func;			 		  /* ����ָ�룬�ص����� */	  
	void *arg;						  /* ���溯���Ĳ��� */ 

} threadpool_task_t; 	

/* �����̳߳������Ϣ */ 
struct thread_pool_t {
	pthread_mutex_t 	lock;			   		/* ������ס���ṹ�� */
	pthread_mutex_t 	thread_counter;	   		/* ��¼æ״̬�̸߳������� -- busy_thr_num */
	pthread_cond_t 		queue_not_full; 	    /* �����������ʱ�����������߳��������ȴ����������� */
	pthread_cond_t 		queue_not_empty;	 	/* ��������ﲻΪ��ʱ��֪ͨ�ȴ�������߳� */
	pthread_t 			*threads;				/* ����̳߳���ÿ���̵߳�tid������ */
	pthread_t 			adjust_tid;				/* ������߳�tid */
	threadpool_task_t   *task_queue;	   		/* �������(�����׵�ַ) */
	int 				min_thr_num; 			/* �̳߳���С�߳��� */
	int 				max_thr_num;			/* �̳߳�����߳��� */
	int 				live_thr_num;			/* ��ǰ����̸߳��� */
	int 				busy_thr_num;			/* æ״̬�̸߳��� */
	int 				wait_exit_thr_num; 		/* Ҫ���ٵ��̸߳��� */
	int 				queue_front;			/* task_queue��ͷ�±� */
	int 				queue_rear;				/* task_queue��β�±� */
	int 				queue_size;				/* task_queue����ʵ�������� */
	int 				queue_max_size;			/* task_queue���п��������������� */
	bool 				shutdown;				/* ��־λ���̳߳�ʹ��״̬��true : �����̳߳�, false : ������*/
};

/*�̳߳������߳� ִ�з���
*@param : ���̳߳ؾ��
*/
void *threadpool_thread(void *threadpool);

/*�����߳� ִ�з���
*@param : The threadPool point
*/
void *adjust_thread(void *threadpool);

/*�鿴�߳��Ƿ���,
*@param : tid  The thread ID
*/
bool is_thread_alive(pthread_t tid);			

/*�ͷ��̳߳�
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

	//1. ������, ����wait ����  (�˴��Ƿ������)
	while((pool->queue_size == pool->queue_max_size) && (!pool->shutdown))
		pthread_cond_wait(&(pool->queue_not_full), &(pool->lock));

	if(pool->shutdown)			//�̳߳ؿ���; (�˴���̫��)
	{
		pthread_cond_broadcast(&(pool->queue_not_empty));
		pthread_mutex_unlock(&(pool->lock));
		return 0;
	}

	//2. ���  �����߳� �ص������� ����
	if(pool->task_queue[pool->queue_rear].arg != NULL)
		pool->task_queue[pool->queue_rear].arg = NULL;


	//3. ������񵽶���
	pool->task_queue[pool->queue_rear].func = function;
	pool->task_queue[pool->queue_rear].arg = arg;
	pool->queue_rear = (pool->queue_rear + 1) % pool->queue_max_size;
	pool->queue_size++;

	//4. ����������, �����̳߳��еȴ���������Ĺ����߳�
	pthread_cond_broadcast(&(pool->queue_not_empty));
	pthread_mutex_unlock(&(pool->lock));

	return 0;
}


//�̳߳������߳� ִ�з���; 
//��ִ�з������ص�: 1.ͬһʱ��, ֻ��һ���߳̿��Ի�ȡ ��������е�����(ͨ��������); 2. ��ȡ�����, �����ͷŸû�����(ʹ�����߳̿���ȥ��ȡ����), ������ִ�л�ȡ������;
void *threadpool_thread(void * threadpool)
{
	threadpool_t *pool = (threadpool_t *)threadpool;
	threadpool_task_t task;
	pthread_detach(pthread_self());
	
	while(true)
	{
		pthread_mutex_lock(&(pool->lock));


		//1.��������ʱ, ��������������, ������, ������
		while((pool->queue_size == 0) && (!pool->shutdown))
		{
			pthread_cond_wait(&(pool->queue_not_empty), &(pool->lock));

			//2.���ָ����Ŀ�Ŀ����߳�, 
			if(pool->wait_exit_thr_num > 0)
			{
				pool->wait_exit_thr_num--;		//ע��: ֻ�е������²�����ʱ, �Żᵼ���߳������˳�

				//�̳߳صĴ���̸߳��� ���� ��Сֵ, �ſ��Խ�����ǰ�߳�
				if(pool->live_thr_num > pool->min_thr_num)
				{
					pool->live_thr_num--;
					pthread_mutex_unlock(&(pool->lock));
					pthread_exit(NULL);
				}
			}
		}

		//2. ָ���� true, Ҫ�ر��̳߳ص� ÿ���߳�, �����˳����� -- �����̳߳�
		if(pool->shutdown)
		{
			pthread_mutex_unlock(&(pool->lock));
			myprint("Thread 0x%x is exit", (unsigned int)pthread_self());					
			pthread_exit(NULL);
		}
		
		//3. �������������������, ����������Ҫִ��
		task.func = pool->task_queue[pool->queue_front].func;
		task.arg = pool->task_queue[pool->queue_front].arg;		
		pool->queue_size--;
		pool->queue_front = (pool->queue_front + 1)%pool->queue_max_size;

		//֪ͨ���������������
		pthread_cond_broadcast(&(pool->queue_not_full));
		pthread_mutex_unlock(&(pool->lock));		//����ȡ����, �����ͷŻ�����,

		//ִ������
		pthread_mutex_lock(&(pool->thread_counter));
		pool->busy_thr_num++;
		pthread_mutex_unlock(&(pool->thread_counter));

		myprint("Thread : 0x%x start working", (unsigned int)pthread_self());
		task.func(task.arg);		//ִ�лص�����
		
		pthread_mutex_lock(&(pool->thread_counter));
		pool->busy_thr_num--;
		pthread_mutex_unlock(&(pool->thread_counter));

		//���д���Ϊ�����޸�, ����֮������ɾ��
		//pthread_exit(NULL);
	}


	pthread_exit(NULL);
}


//�����߳�
void *adjust_thread(void * threadpool)
{
	int i = 0;
	threadpool_t  *pool = (threadpool_t*)threadpool;
	//pthread_detach(pthread_self());
	
	//�̳߳صĹ��� ����
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

		//�������߳��㷨 : ������������С�̸߳���, �Ҵ����̸߳��� С������߳���
		if(queue_size > MIN_WAIT_TASK_NUM && live_thr_num < pool->max_thr_num)
		{
			pthread_mutex_lock(&(pool->lock));
			int add = 0;

			//һ������ DEFAULT_THREAD_VARY ���߳�
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
	//ע�����δ���, ����Ϊ:���Խ׶�����С������, ÿ�ζ��������֧, �����߳��������߳�(Ĭ��ÿ������10��),�ⲻ���������ٷ����Ĺ��� 
		//���ٶ�������̵߳��㷨 : æ�߳�X2 С�� �����߳��� �� �����߳��� ���� ��С�߳���ʱ
		if(busy_thr_num * 2 < live_thr_num && live_thr_num < pool->max_thr_num)
		{
			pthread_mutex_lock(&(pool->lock));
			pool->wait_exit_thr_num = DEFAULT_THREAD_VARY;
			pthread_mutex_unlock(&(pool->lock));		
			//֪ͨһ���������߳�, ����������ֹ
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
		

	//1. �޸ľ��, �����߳�����
	pool->shutdown = true;

	//2. �����ٹ����߳�, ���߳�û�б�����, ��Ҫ���л���		
	pthread_join(pool->adjust_tid, NULL);

	//3. ֪ͨ���������߳�, ��������
	for(i = 0; i < pool->live_thr_num; i++)	
		pthread_cond_broadcast(&(pool->queue_not_empty));

	//4. ��Ϊ���̷߳���, �����������߳�ʱ, ����Ҫ���л���;
	//for(i = 0; i < pool->live_thr_num; i++)
	//	pthread_join(pool->threads[i], NULL);		
	
	//5. ���پ��
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
	int kill_rc = pthread_kill(tid, 0);		//��0���źţ������߳��Ƿ���
	if(kill_rc == ESRCH)
		return false;
	return true;
}

