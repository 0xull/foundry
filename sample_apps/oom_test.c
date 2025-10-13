#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MB (1024 * 1024)

int main()
{
    printf("Starting memory allocation...\n");
    // Allocate 10MB memory chunk in loop
    for (int i = 0; i <100; i++) {
        void *ptr = malloc(10 * MB);
        if (ptr == NULL) {
            printf("malloc failed at %d0 MB! This should not happen if OOM killer works.\n", i);
            return 1;
        }
        
        memset(ptr, 0, 10 * MB);
        printf("Allocated %d0 MB so far...\n", i + 1);
        sleep(1);
    }
    
    printf("Successfully allocated 1GB. The cgroup limit failed!\n");
    return 0;
}