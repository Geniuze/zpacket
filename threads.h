#include <iostream>
using namespace std;

#include <list>
#include <vector>

void *threadhandle(void *arg);

typedef void*(*thread_handle)(void *);

class mtpool_work
{
public:
	mtpool_work(thread_handle wk, void *a):work(wk), arg(a){}
	mtpool_work():work(NULL), arg(NULL){}
	void run()
	{
		if (work) (*work)(arg);
	}
private:
	thread_handle work;
	void *arg;
};

class mthreads_pool
{
public:
	mthreads_pool(int cnt = 100):count(cnt), shutdown(false){}
	int mthreads_init()
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&cond, NULL);
		for (int i=0; i < count; ++i)
		{
			pthread_t tid;
			pthread_create(&tid, NULL, threadhandle, (void*)this);
			tids.push_back(tid);
		}
		return 0;
	}

	int mthreads_finit()
	{
		shutdown = true;

		pthread_mutex_lock(&mutex);
		pthread_cond_broadcast(&cond);
		pthread_mutex_unlock(&mutex);

		mthreads_join();

		while (tids.size())
		{
			tids.pop_front();
		}
	}
	void mthreads_join()
	{
		list<pthread_t>::iterator it = tids.end();
		for (it = tids.begin(); it != tids.end(); it++)
		{
			pthread_join(*it, NULL);
		}
	}

	void mthreads_wait()
	{
		pthread_mutex_lock(&mutex);
		while (!works.size() && !shutdown)
			pthread_cond_wait(&cond, &mutex);
		if (shutdown)
		{
			pthread_mutex_unlock(&mutex);
			pthread_exit(NULL);
		}
			
	}
	void mthreads_lock()
	{
		pthread_mutex_lock(&mutex);
	}
	void mthreads_unlock()
	{
		pthread_mutex_unlock(&mutex);
	}

	void mthreads_addwork(mtpool_work work)
	{
		pthread_mutex_lock(&mutex);
		
		works.push_back(work);

		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);
	}
	mtpool_work mthreads_getwork()
	{
		mtpool_work work = works.front();
		works.pop_front();
		return work;
	}

	size_t mthreads_workcount()
	{
		int count = 0;
		pthread_mutex_lock(&mutex);
		count = works.size();
		pthread_mutex_unlock(&mutex);

		return count;
	}
private:
	int count;
	list<mtpool_work> works;
	list<pthread_t> tids;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool shutdown;
};
