# Heap Extraction Plugin for Volatility3

## Overview

This plugin is designed for use with the Volatility3 framework. It allows forensic analysts to extract heap fragments from process memory dumps in Windows systems. The plugin is particularly useful for identifying and extracting information that may be critical in forensic investigations, such as injected code, sensitive data, and other relevant process behaviors.


## Features

- Lists all heaps of a specific process in a Windows memory dump.
- Extracts specific heap fragments based on the analyst's interest.
- Handles encoded heap fragments by decoding them for analysis.
- Outputs extracted heap data into files for further examination.


## Installation

To install the plugin, follow these steps:

1. Clone or download this repository to your local machine.
2. Ensure that you have Volatility3 installed and properly configured. You can follow the official installation guide [here](https://github.com/volatilityfoundation/volatility3). NOTE: For this plugin to function correctly, the minimum required version of the Volatility3 framework is 2.0.0.
3. Copy the plugin file into the appropriate Volatility3 plugin directory:

    ```bash
    cp heap_extraction_plugin.py /path/to/volatility3/volatility3/plugins/windows/
    ```

4. The plugin is now ready to use with Volatility3.

## Usage

To use the plugin, run Volatility3 with the following command:

```bash
vol.py -f <memory_dump> windows.heaplist.HeapList [options]
 ```

## Options

- --pid: Specify the process ID (PID) to analyze. If not specified, the plugin will analyze all processes.
- --dump-all: Dump all heap fragments from the specified process or processes.
- --dump: Specify the address of the heap fragment to download.


## Example
To analyze the heaps of a specific process with PID 1234 and dump all heap fragments:

```bash
vol.py -f memory.dmp windows.heap_extraction -p 1234 --dump-all
```


