#pragma once

#include <cstdio>
#include <cstdlib>

// Test checks must execute in Release builds as well as Debug builds.
#define CHECK(condition)                                                                        \
    do                                                                                          \
    {                                                                                           \
        if (!(condition))                                                                       \
        {                                                                                       \
            std::fprintf(stderr, "Check failed: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
            std::exit(EXIT_FAILURE);                                                            \
        }                                                                                       \
    } while (false)
