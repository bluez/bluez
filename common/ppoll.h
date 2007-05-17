#ifdef ppoll
#undef ppoll
#endif

#define ppoll compat_ppoll

static inline int compat_ppoll(struct pollfd *fds, nfds_t nfds,
		const struct timespec *timeout, const sigset_t *sigmask)
{
	return poll(fds, nfds, timeout ? timeout->tv_sec * 1000 : 500);
}
