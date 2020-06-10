#ifndef _h_iprcchan_h
#define _h_iprcchan_h

typedef struct iprcchan iprcchan_t;

iprcchan_t *iprcchan_open(int num, void (*cb_func)(void *cb_data, void *buffer), void *cb_data);
void        iprcchan_close(iprcchan_t *);
void       *iprcchan_begin_call(iprcchan_t *);
int         iprcchan_do_call(iprcchan_t *);
void        iprcchan_end_call(iprcchan_t *);

#endif
