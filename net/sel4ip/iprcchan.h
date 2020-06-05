#ifndef _h_iprcchan_h
#define _h_iprcchan_h

struct iprcchan *iprcchan_open(int num, void (*cb_func)(void*, void*), void *cb_data);
void             iprcchan_close(struct iprcchan *);
void            *iprcchan_begin_call(struct iprcchan *);
int              iprcchan_do_call(struct iprcchan *);
void             iprcchan_end_call(struct iprcchan*);

#endif
