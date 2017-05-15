
static void lock_callback(int mode, int type, char *file, int line)
{
    (void)file;
    (void)line;
    if(mode & CRYPTO_LOCK) 
    {
        pthread_mutex_lock(&(g_lockarray[type]));
    }
    else 
    {
        pthread_mutex_unlock(&(g_lockarray[type]));
    }
}

static unsigned long thread_id(void)
{
    unsigned long ret;

    ret=(unsigned long)pthread_self();
    return ret;
}

static void init_locks(void)
{
    int i;

    g_lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

    for(i=0; i<CRYPTO_num_locks(); i++) 
    {
        pthread_mutex_init(&(g_lockarray[i]), NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void kill_locks(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for(i=0; i<CRYPTO_num_locks(); i++)
    {
        pthread_mutex_destroy(&(g_lockarray[i]));
    }
    OPENSSL_free(g_lockarray);
}
