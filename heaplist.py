import logging
from typing import Callable, List, Generator, Iterable, Type, Optional

# This plugin for Volatility3 analyzes heaps of processes in a Windows system.
# It allows enumerating heaps and, optionally, extracting memory chunks from these heaps.
# The chunks can be filtered by address or extracted entirely.

from volatility3.framework import exceptions, interfaces, renderers, objects
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.framework.renderers import format_hints
from enum import IntFlag

# Setting up the logger
vollog = logging.getLogger(__name__)

# Flags for heap entries (_HEAP_ENTRY)
class ENTRY_FLAGS(IntFlag):
    BUSY = 0x01
    EXTRA = 0x02
    FILL = 0x04
    #VIRTUAL = 0x08
    LAST = 0x10
    FLAG1 = 0x20
    FLAG2 = 0x40
    FLAG3 = 0x80
    FLAGS = FLAG1 | FLAG2 | FLAG3

# Main plugin class that implements the functionality to analyze and extract
# information from heaps in selected processes.
class HeapList(interfaces.plugins.PluginInterface):
    """Prints the PIDs, NT Heap Address for Backend Layer, Segment Address and Chunk address, size and status"""

    _required_framework_version = (2, 0, 0)

    # Defines the requirements needed to run the plugin, including the kernel,
    # the pslist plugin, and optional parameters like PID and dump options.
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name="pid",
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.StringRequirement(
                name="dump",
                description="Virtual memory address of the process to start the dump.",
                optional=True,
                default=None,
            ),
            requirements.BooleanRequirement(
                name="dump-all",
                description="Extract all memory fragments from the heap",
                default=False,
                optional=True,
            ),
        ]

    # Generator that iterates over the selected processes and produces heap information.
    # If specified, it also extracts memory chunks and saves them to files.
    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        # Check if a specific dump address was provided
        dump_address = self.config.get('dump')
        dump_mode = dump_address is not None

        for proc in procs:
            pid = "Unknown"
            process_name = "Unknown"
            number_of_heaps = "Unknown"

            try:
                # Attempt to get the PEB of the process and then the associated heaps.
                pid = proc.UniqueProcessId
                process_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace')
                peb = proc.get_peb()
                number_of_heaps = peb.NumberOfHeaps
                HEAP_ENTRY = kernel.get_type("_HEAP_ENTRY")
                HEAP_SEGMENT = kernel.get_type("_HEAP_SEGMENT")
                HEAP = kernel.get_type("_HEAP")
                LIST_ENTRY = kernel.get_type("_LIST_ENTRY")
                granularity = HEAP_ENTRY.size
                process_heaps = peb.ProcessHeaps.dereference()
                symbol_table = proc._context.symbol_space[proc.get_symbol_table_name()]
                heap_type = symbol_table.get_type('pointer')
                heap_pointer_array = process_heaps.cast('array', count=number_of_heaps, subtype=heap_type)

                # Iterate over each heap in the process to analyze its segments and entries.
                for heap_index, heap_pointer in enumerate(heap_pointer_array):
                    process_heap = heap_pointer.dereference()
                    heap_final = process_heap.vol.offset
                    offset = heap_final
                    heap: objects.StructType = self.context.object(HEAP, peb.vol.layer_name, heap_final)
                    FlinkStart = heap.SegmentList.Flink
                    Flink = FlinkStart
                    FlinkFinal = heap.SegmentList.Blink
                    indexSegments = 1
                    
                    # Start traversing the segment list in the heap using the doubly linked list pattern.
                    while FlinkStart != FlinkFinal or indexSegments == 1:
                        offset = Flink - 24
                        segment: objects.StructType = self.context.object(HEAP_SEGMENT, heap.vol.layer_name, offset)
                        SegmentPrint = offset
                        
                        while True:
                            try:
                                file_output = "Disabled"
                                # Get the current heap entry and decode it (if encoded).
                                # Then attempt to read and decode the first 40 bytes of the chunk to extract printable data.
                                entry: objects.StructType = self.context.object(HEAP_ENTRY, heap.vol.layer_name, offset)
                                encoding = heap.EncodeFlagMask
                                if encoding == 1048576:
                                    size = (entry.Size ^ heap.Encoding.Size)
                                    AllSize = size * granularity
                                    Flags = (entry.Flags ^ heap.Encoding.Flags)
                                    cipher = 'Enabled'
                                else:
                                    size = (entry.Size)
                                    AllSize = size * granularity
                                    Flags = entry.Flags
                                    cipher = 'Disabled'
                                
                                # Skip this entry if the calculated size is 0x0
                                if AllSize == 0x0:
                                    offset += granularity  # or another appropriate value to move to the next entry
                                    continue  # Skip the current entry and move to the next

                                trans_layer = self.context.layers[entry.vol.layer_name]
                                data = trans_layer.read(entry.vol.offset + granularity, (size - 1) * granularity)
                                try:
                                    user_data = data[:40].decode('utf-8', errors='ignore')
                                    user_data = ''.join(c if c.isprintable() else '.' for c in user_data)
                                except UnicodeDecodeError:
                                    user_data = "Cannot decode"

                                # If dump-all is enabled, attempt to dump the chunk data to a file.
                                if self.config["dump-all"]:
                                    dump = hex(entry.vol.offset)
                                    file_output = f"{pid}.{process_name}.{dump}.dmp"
                                    file_name = file_output
                                    try:
                                        with open(file_name, 'wb') as file_handle:
                                            file_handle.write(data)
                                    except Exception as e:
                                        print(f"An error occurred when writing in the file: {e}")

                                # If a specific dump address is provided, dump only that chunk.                                
                                if dump_mode:
                                    dump = hex(entry.vol.offset)
                                    if dump == dump_address:
                                        file_output = f"{pid}.{process_name}.{dump}.dmp"
                                        file_name = file_output
                                        try:
                                            with open(file_name, 'wb') as file_handle:
                                                file_handle.write(data)
                                        except Exception as e:
                                            print(f"An error occurred while writing in the file: {e}")
                                        
                                        # Only show output for the specified dump address.
                                        yield (
                                            0,
                                            (
                                                pid,
                                                process_name,
                                                format_hints.Hex(heap_final),
                                                format_hints.Hex(SegmentPrint),
                                                format_hints.Hex(entry.vol.offset),
                                                cipher,
                                                format_hints.Hex(AllSize),
                                                flags_str,
                                                user_data,
                                                file_output,
                                            )
                                        )
                                        return  # Exit after handling the specific chunk
                                    
                                # Create a list of active flags for the current heap entry and convert them to a string.
                                flags_activos = []
                                for flag in ENTRY_FLAGS:
                                    if Flags & flag:
                                        flags_activos.append(flag.name)
                                flags_str = '[' + ' '.join(str(flag) for flag in flags_activos) + ']'

                                offset += AllSize

                                # Yield information about the current heap entry if not in dump mode.
                                if not dump_mode:
                                    yield (
                                        0,
                                        (
                                            pid,
                                            process_name,
                                            format_hints.Hex(heap_final),
                                            format_hints.Hex(SegmentPrint),
                                            format_hints.Hex(entry.vol.offset),
                                            cipher,
                                            format_hints.Hex(AllSize),
                                            flags_str,
                                            user_data,
                                            file_output,
                                        )
                                    )           

                            except exceptions.PagedInvalidAddressException:
                                break
                        
                        if FlinkStart == FlinkFinal:
                            break

                        List: objects.StructType = self.context.object(LIST_ENTRY, heap.vol.layer_name, Flink)
                        Flink = List.Flink
                        FlinkFinal = List.Blink
                        indexSegments += 1

            except exceptions.InvalidAddressException as excp:
                vollog.debug(f"Process {pid}: invalid address {excp.invalid_address} in layer {excp.layer_name}")
                continue
            except Exception as e:
                vollog.debug(f"Error obtaining information for process {pid}: {e}")
                continue
    
    # Main method executed when the plugin is run. It retrieves the process list
    # and constructs the TreeGrid with the heap information.
    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get("pid", None)])
        kernel = self.context.modules[self.config["kernel"]]
        processes = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        )
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process Name", str),
                ("Heap Address", format_hints.Hex),
                ("Segment Address", format_hints.Hex),
                ("Chunk Address", format_hints.Hex),
                ("Coded", str),
                ("Chunk Size", format_hints.Hex),
                ("Chunk Status", str),
                ("Payload", str),
                ("File Output", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
