# Test Files

## Binary for Code Injection

### Overview

This directory contains a binary file designed for injecting code into the heap of a running process in a controlled environment. The purpose of this binary is to simulate an environment where code is injected into the memory heap, allowing for detailed analysis and understanding of heap structures and memory allocation behaviors.

### How It Works

The binary operates by executing the following steps:

1. **Heap Creation**: 
   - The binary begins by creating a new heap in the target process using Windows API functions. This heap will serve as the space where the code will be injected and managed.

2. **Memory Allocation**:
   - Once the heap is created, the binary allocates a block of memory within the heap. This block is where the first fragment of code will be injected.

3. **Code Injection**:
   - A predefined piece of code is injected into the allocated memory block. This code can be any payload that you wish to study, and it allows you to observe how the code interacts with the memory structures.

4. **Heap Expansion**:
   - The binary then allocates additional memory, forcing the creation of a new segment within the heap. This is done to simulate a more complex heap structure where multiple segments are involved.

5. **Secondary Code Injection**:
   - A second piece of code is injected into the newly allocated memory segment. This allows the analysis of how different segments within the heap handle injected code.

6. **Memory Dump Preparation**:
   - Before completing execution, the binary outputs the memory addresses where the code has been injected. It then waits for a user input to ensure that the process remains active while the memory dump is taken.

7. **Cleanup**:
   - After the memory dump is captured, the binary proceeds to free the allocated memory and destroy the heap, ensuring that no residual data is left in memory after execution.

### Purpose

The main objective of this binary is to create a controlled scenario for forensic analysis. By injecting known code into the heap, it provides a predictable environment for studying how heap memory is structured, how code is managed within it, and how tools like Volatility3 can be used to extract and analyze these memory segments.

### Usage

To use this binary for testing, simply execute it in your test environment and follow the prompts to create a memory dump for analysis. The memory dump can then be analyzed using the Volatility3 framework to extract and examine the injected code within the heap.

