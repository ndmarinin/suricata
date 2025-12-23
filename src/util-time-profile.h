#ifndef __UTIL_TIME_PROFILE_H__
#define __UTIL_TIME_PROFILE_H__

#include <time.h>
#include <stdint.h>

static inline uint64_t GetTimeNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
}

#define PROFILE_START(var) \
    uint64_t var##_start = GetTimeNs()

#define PROFILE_END(var, acc) \
    acc += (GetTimeNs() - var##_start)

#endif
