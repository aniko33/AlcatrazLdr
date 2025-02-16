#ifndef DEBUGGING_H
#define DEBUGGING_H

#define TEXT_RED(TEXT) "\033[91m" TEXT "\033[0m"
#define TEXT_CYAN(TEXT) "\033[96m" TEXT "\033[0m"

#ifdef DEBUG
#define DEBUG_ERROR(FMT, ...) printf("[" TEXT_RED("!") "] " FMT "\n", ##__VA_ARGS__)
#define DEBUG_INFO(FMT, ...) printf("[" TEXT_CYAN("i") "] " FMT "\n", ##__VA_ARGS__)
#define DEBUG_GETCHAR() printf("Press enter for close the program..."); getchar()
#else
#define DEBUG_ERROR(FMT, ...)
#define DEBUG_INFO(FMT, ...)
#define DEBUG_GETCHAR()
#endif

#endif

