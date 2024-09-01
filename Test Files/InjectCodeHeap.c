#include <stdio.h>
#include <windows.h>

int main() {
    HANDLE hHeap;
    LPVOID pMem1, pMem2;

    // Create a new heap with HeapCreate
    hHeap = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0, 0);
    if (hHeap == NULL) {
        printf("Error creating the heap\n");
        return 1;
    }

    // Allocate a block of memory in the created heap
    pMem1 = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 1024);
    if (pMem1 == NULL) {
        printf("Error allocating memory in the heap\n");
        HeapDestroy(hHeap);
        return 1;
    }

    // Code injected into the heap
    char code1[] = "#include <stdio.h>\n"
                   "int main() {\n"
                   "    printf(\"Hello World from the heap!\\n\");\n"
                   "    getchar();\n"
                   "    return 0;\n"
                   "}\n";

    // Write the code into the process heap
    SIZE_T bytesWritten;
    BOOL result = WriteProcessMemory(GetCurrentProcess(), pMem1, code1, sizeof(code1), &bytesWritten);
    if (!result) {
        printf("Error writing to the process memory\n");
        HeapFree(hHeap, 0, pMem1);
        HeapDestroy(hHeap);
        return 1;
    }

    printf("Code injected into the process heap at address: 0x%p\n", pMem1);

    // Allocate more memory in the same heap to fill the current segment
    // Multiple allocations are made to try to force the creation of a new segment
    for (int i = 0; i < 100; i++) {
        LPVOID tempMem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 1024); 
        if (tempMem == NULL) {
            printf("Error allocating intermediate memory in the heap\n");
            HeapFree(hHeap, 0, pMem1);
            HeapDestroy(hHeap);
            return 1;
        }
    }

    // Allocate another block of memory to force a new segment
    pMem2 = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 1024); 
    if (pMem2 == NULL) {
        printf("Error allocating the second block of memory in the heap\n");
        HeapFree(hHeap, 0, pMem1);
        HeapDestroy(hHeap);
        return 1;
    }

    // Second code injected into the heap
    char code2[] = "#include <stdio.h>\n"
                   "int main() {\n"
                   "    printf(\"I am undetectable\n\");\n"
                   "    getchar();\n"
                   "    return 0;\n"
                   "}\n";

    // Write the second code into the process heap
    result = WriteProcessMemory(GetCurrentProcess(), pMem2, code2, sizeof(code2), &bytesWritten);
    if (!result) {
        printf("Error writing the second injection to the process memory\n");
        HeapFree(hHeap, 0, pMem2);
        HeapFree(hHeap, 0, pMem1);
        HeapDestroy(hHeap);
        return 1;
    }

    printf("Second code injection into the process heap at address: 0x%p\n", pMem2);

    printf("Press Enter to exit...\n");
    getchar();

    // Free the allocated memory and destroy the heap
    HeapFree(hHeap, 0, pMem2);
    HeapFree(hHeap, 0, pMem1);
    HeapDestroy(hHeap);

    return 0;
}
