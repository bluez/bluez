#ifdef ppoll
#undef ppoll
#endif

#define ppoll compat_ppoll

static inline int compat_ppoll(struct pollfd *fds, nfds_t nfds,
		const struct timespec *timeout, const sigset_t *sigmask)
{
	if (timeout == NULL)
		return poll(fds, nfds, -1);
	else if (timeout->tv_sec == 0)
		return poll(fds, nfds, 500);
	else
		return poll(fds, nfds, timeout->tv_sec * 1000);
}
