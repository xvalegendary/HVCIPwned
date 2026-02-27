#include "exploit.h"
#include "common.h"

int main(int argc, char** argv)
{
    int ret;
    (void)argc;
    (void)argv;
    ret = exploit_run();
    printf("\npress enter to exit...");
    getchar();
    return ret;
}