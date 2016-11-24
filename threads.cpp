#include <iostream>
using namespace std;

#include "threads.h"

void *threadhandle(void *arg)
{
	mtpool_work work;
	
	mthreads_pool *mp = (mthreads_pool *)arg;

	while(true)
	{
		mp->mthreads_wait();

		// TODO get work
		work = mp->mthreads_getwork();

		mp->mthreads_unlock();

		// TODO do work

		work.run();
	}
	
}
