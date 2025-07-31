// Windows PE sections use standard file alignment (typically 512 bytes)
// No special 16KB alignment needed like macOS code signing

/// Windows PE Binary manipulation for codesigning standalone executables
pub const PEFile = struct {
    allocator: Allocator,
    // Parsed headers stored in memory
    dos_header: DOSHeader,
    pe_header: PEHeader,
    optional_header: OptionalHeader64,
    section_headers: std.ArrayList(SectionHeader),
    // Raw section data
    sections_data: std.ArrayList([]u8),
    // PE structure offsets for reconstruction
    pe_header_offset: u32,

    const DOSHeader = extern struct {
        e_magic: u16, // Magic number
        e_cblp: u16, // Bytes on last page of file
        e_cp: u16, // Pages in file
        e_crlc: u16, // Relocations
        e_cparhdr: u16, // Size of header in paragraphs
        e_minalloc: u16, // Minimum extra paragraphs needed
        e_maxalloc: u16, // Maximum extra paragraphs needed
        e_ss: u16, // Initial relative SS value
        e_sp: u16, // Initial SP value
        e_csum: u16, // Checksum
        e_ip: u16, // Initial IP value
        e_cs: u16, // Initial relative CS value
        e_lfarlc: u16, // Address of relocation table
        e_ovno: u16, // Overlay number
        e_res: [4]u16, // Reserved words
        e_oemid: u16, // OEM identifier (for e_oeminfo)
        e_oeminfo: u16, // OEM information; e_oemid specific
        e_res2: [10]u16, // Reserved words
        e_lfanew: u32, // File address of new exe header

        pub fn parse(reader: anytype) !DOSHeader {
            var header: DOSHeader = undefined;
            header.e_magic = try reader.readInt(u16, .little);
            header.e_cblp = try reader.readInt(u16, .little);
            header.e_cp = try reader.readInt(u16, .little);
            header.e_crlc = try reader.readInt(u16, .little);
            header.e_cparhdr = try reader.readInt(u16, .little);
            header.e_minalloc = try reader.readInt(u16, .little);
            header.e_maxalloc = try reader.readInt(u16, .little);
            header.e_ss = try reader.readInt(u16, .little);
            header.e_sp = try reader.readInt(u16, .little);
            header.e_csum = try reader.readInt(u16, .little);
            header.e_ip = try reader.readInt(u16, .little);
            header.e_cs = try reader.readInt(u16, .little);
            header.e_lfarlc = try reader.readInt(u16, .little);
            header.e_ovno = try reader.readInt(u16, .little);
            for (&header.e_res) |*r| {
                r.* = try reader.readInt(u16, .little);
            }
            header.e_oemid = try reader.readInt(u16, .little);
            header.e_oeminfo = try reader.readInt(u16, .little);
            for (&header.e_res2) |*r| {
                r.* = try reader.readInt(u16, .little);
            }
            header.e_lfanew = try reader.readInt(u32, .little);
            return header;
        }

        pub fn write(self: DOSHeader, writer: anytype) !void {
            try writer.writeInt(u16, self.e_magic, .little);
            try writer.writeInt(u16, self.e_cblp, .little);
            try writer.writeInt(u16, self.e_cp, .little);
            try writer.writeInt(u16, self.e_crlc, .little);
            try writer.writeInt(u16, self.e_cparhdr, .little);
            try writer.writeInt(u16, self.e_minalloc, .little);
            try writer.writeInt(u16, self.e_maxalloc, .little);
            try writer.writeInt(u16, self.e_ss, .little);
            try writer.writeInt(u16, self.e_sp, .little);
            try writer.writeInt(u16, self.e_csum, .little);
            try writer.writeInt(u16, self.e_ip, .little);
            try writer.writeInt(u16, self.e_cs, .little);
            try writer.writeInt(u16, self.e_lfarlc, .little);
            try writer.writeInt(u16, self.e_ovno, .little);
            for (self.e_res) |r| {
                try writer.writeInt(u16, r, .little);
            }
            try writer.writeInt(u16, self.e_oemid, .little);
            try writer.writeInt(u16, self.e_oeminfo, .little);
            for (self.e_res2) |r| {
                try writer.writeInt(u16, r, .little);
            }
            try writer.writeInt(u32, self.e_lfanew, .little);
        }
    };

    const PEHeader = extern struct {
        signature: u32, // PE signature
        machine: u16, // Machine type
        number_of_sections: u16, // Number of sections
        time_date_stamp: u32, // Time/date stamp
        pointer_to_symbol_table: u32, // Pointer to symbol table
        number_of_symbols: u32, // Number of symbols
        size_of_optional_header: u16, // Size of optional header
        characteristics: u16, // Characteristics

        pub fn parse(reader: anytype) !PEHeader {
            return PEHeader{
                .signature = try reader.readInt(u32, .little),
                .machine = try reader.readInt(u16, .little),
                .number_of_sections = try reader.readInt(u16, .little),
                .time_date_stamp = try reader.readInt(u32, .little),
                .pointer_to_symbol_table = try reader.readInt(u32, .little),
                .number_of_symbols = try reader.readInt(u32, .little),
                .size_of_optional_header = try reader.readInt(u16, .little),
                .characteristics = try reader.readInt(u16, .little),
            };
        }

        pub fn write(self: PEHeader, writer: anytype) !void {
            try writer.writeInt(u32, self.signature, .little);
            try writer.writeInt(u16, self.machine, .little);
            try writer.writeInt(u16, self.number_of_sections, .little);
            try writer.writeInt(u32, self.time_date_stamp, .little);
            try writer.writeInt(u32, self.pointer_to_symbol_table, .little);
            try writer.writeInt(u32, self.number_of_symbols, .little);
            try writer.writeInt(u16, self.size_of_optional_header, .little);
            try writer.writeInt(u16, self.characteristics, .little);
        }
    };

    const OptionalHeader64 = extern struct {
        magic: u16, // Magic number
        major_linker_version: u8, // Major linker version
        minor_linker_version: u8, // Minor linker version
        size_of_code: u32, // Size of code
        size_of_initialized_data: u32, // Size of initialized data
        size_of_uninitialized_data: u32, // Size of uninitialized data
        address_of_entry_point: u32, // Address of entry point
        base_of_code: u32, // Base of code
        image_base: u64, // Image base
        section_alignment: u32, // Section alignment
        file_alignment: u32, // File alignment
        major_operating_system_version: u16, // Major OS version
        minor_operating_system_version: u16, // Minor OS version
        major_image_version: u16, // Major image version
        minor_image_version: u16, // Minor image version
        major_subsystem_version: u16, // Major subsystem version
        minor_subsystem_version: u16, // Minor subsystem version
        win32_version_value: u32, // Win32 version value
        size_of_image: u32, // Size of image
        size_of_headers: u32, // Size of headers
        checksum: u32, // Checksum
        subsystem: u16, // Subsystem
        dll_characteristics: u16, // DLL characteristics
        size_of_stack_reserve: u64, // Size of stack reserve
        size_of_stack_commit: u64, // Size of stack commit
        size_of_heap_reserve: u64, // Size of heap reserve
        size_of_heap_commit: u64, // Size of heap commit
        loader_flags: u32, // Loader flags
        number_of_rva_and_sizes: u32, // Number of RVA and sizes
        data_directories: [16]DataDirectory, // Data directories

        pub fn parse(reader: anytype) !OptionalHeader64 {
            var header: OptionalHeader64 = undefined;
            header.magic = try reader.readInt(u16, .little);
            header.major_linker_version = try reader.readByte();
            header.minor_linker_version = try reader.readByte();
            header.size_of_code = try reader.readInt(u32, .little);
            header.size_of_initialized_data = try reader.readInt(u32, .little);
            header.size_of_uninitialized_data = try reader.readInt(u32, .little);
            header.address_of_entry_point = try reader.readInt(u32, .little);
            header.base_of_code = try reader.readInt(u32, .little);
            header.image_base = try reader.readInt(u64, .little);
            header.section_alignment = try reader.readInt(u32, .little);
            header.file_alignment = try reader.readInt(u32, .little);
            header.major_operating_system_version = try reader.readInt(u16, .little);
            header.minor_operating_system_version = try reader.readInt(u16, .little);
            header.major_image_version = try reader.readInt(u16, .little);
            header.minor_image_version = try reader.readInt(u16, .little);
            header.major_subsystem_version = try reader.readInt(u16, .little);
            header.minor_subsystem_version = try reader.readInt(u16, .little);
            header.win32_version_value = try reader.readInt(u32, .little);
            header.size_of_image = try reader.readInt(u32, .little);
            header.size_of_headers = try reader.readInt(u32, .little);
            header.checksum = try reader.readInt(u32, .little);
            header.subsystem = try reader.readInt(u16, .little);
            header.dll_characteristics = try reader.readInt(u16, .little);
            header.size_of_stack_reserve = try reader.readInt(u64, .little);
            header.size_of_stack_commit = try reader.readInt(u64, .little);
            header.size_of_heap_reserve = try reader.readInt(u64, .little);
            header.size_of_heap_commit = try reader.readInt(u64, .little);
            header.loader_flags = try reader.readInt(u32, .little);
            header.number_of_rva_and_sizes = try reader.readInt(u32, .little);
            for (&header.data_directories) |*dir| {
                dir.* = try DataDirectory.parse(reader);
            }
            return header;
        }

        pub fn write(self: OptionalHeader64, writer: anytype) !void {
            try writer.writeInt(u16, self.magic, .little);
            try writer.writeByte(self.major_linker_version);
            try writer.writeByte(self.minor_linker_version);
            try writer.writeInt(u32, self.size_of_code, .little);
            try writer.writeInt(u32, self.size_of_initialized_data, .little);
            try writer.writeInt(u32, self.size_of_uninitialized_data, .little);
            try writer.writeInt(u32, self.address_of_entry_point, .little);
            try writer.writeInt(u32, self.base_of_code, .little);
            try writer.writeInt(u64, self.image_base, .little);
            try writer.writeInt(u32, self.section_alignment, .little);
            try writer.writeInt(u32, self.file_alignment, .little);
            try writer.writeInt(u16, self.major_operating_system_version, .little);
            try writer.writeInt(u16, self.minor_operating_system_version, .little);
            try writer.writeInt(u16, self.major_image_version, .little);
            try writer.writeInt(u16, self.minor_image_version, .little);
            try writer.writeInt(u16, self.major_subsystem_version, .little);
            try writer.writeInt(u16, self.minor_subsystem_version, .little);
            try writer.writeInt(u32, self.win32_version_value, .little);
            try writer.writeInt(u32, self.size_of_image, .little);
            try writer.writeInt(u32, self.size_of_headers, .little);
            try writer.writeInt(u32, self.checksum, .little);
            try writer.writeInt(u16, self.subsystem, .little);
            try writer.writeInt(u16, self.dll_characteristics, .little);
            try writer.writeInt(u64, self.size_of_stack_reserve, .little);
            try writer.writeInt(u64, self.size_of_stack_commit, .little);
            try writer.writeInt(u64, self.size_of_heap_reserve, .little);
            try writer.writeInt(u64, self.size_of_heap_commit, .little);
            try writer.writeInt(u32, self.loader_flags, .little);
            try writer.writeInt(u32, self.number_of_rva_and_sizes, .little);
            for (self.data_directories) |dir| {
                try dir.write(writer);
            }
        }
    };

    const DataDirectory = extern struct {
        virtual_address: u32,
        size: u32,

        pub fn parse(reader: anytype) !DataDirectory {
            return DataDirectory{
                .virtual_address = try reader.readInt(u32, .little),
                .size = try reader.readInt(u32, .little),
            };
        }

        pub fn write(self: DataDirectory, writer: anytype) !void {
            try writer.writeInt(u32, self.virtual_address, .little);
            try writer.writeInt(u32, self.size, .little);
        }
    };

    const SectionHeader = extern struct {
        name: [8]u8, // Section name
        virtual_size: u32, // Virtual size
        virtual_address: u32, // Virtual address
        size_of_raw_data: u32, // Size of raw data
        pointer_to_raw_data: u32, // Pointer to raw data
        pointer_to_relocations: u32, // Pointer to relocations
        pointer_to_line_numbers: u32, // Pointer to line numbers
        number_of_relocations: u16, // Number of relocations
        number_of_line_numbers: u16, // Number of line numbers
        characteristics: u32, // Characteristics

        pub fn parse(reader: anytype) !SectionHeader {
            var header: SectionHeader = undefined;
            _ = try reader.read(&header.name);
            header.virtual_size = try reader.readInt(u32, .little);
            header.virtual_address = try reader.readInt(u32, .little);
            header.size_of_raw_data = try reader.readInt(u32, .little);
            header.pointer_to_raw_data = try reader.readInt(u32, .little);
            header.pointer_to_relocations = try reader.readInt(u32, .little);
            header.pointer_to_line_numbers = try reader.readInt(u32, .little);
            header.number_of_relocations = try reader.readInt(u16, .little);
            header.number_of_line_numbers = try reader.readInt(u16, .little);
            header.characteristics = try reader.readInt(u32, .little);
            return header;
        }

        pub fn write(self: SectionHeader, writer: anytype) !void {
            try writer.writeAll(&self.name);
            try writer.writeInt(u32, self.virtual_size, .little);
            try writer.writeInt(u32, self.virtual_address, .little);
            try writer.writeInt(u32, self.size_of_raw_data, .little);
            try writer.writeInt(u32, self.pointer_to_raw_data, .little);
            try writer.writeInt(u32, self.pointer_to_relocations, .little);
            try writer.writeInt(u32, self.pointer_to_line_numbers, .little);
            try writer.writeInt(u16, self.number_of_relocations, .little);
            try writer.writeInt(u16, self.number_of_line_numbers, .little);
            try writer.writeInt(u32, self.characteristics, .little);
        }
    };

    const PE_SIGNATURE = 0x00004550; // "PE\0\0"
    const DOS_SIGNATURE = 0x5A4D; // "MZ"
    const OPTIONAL_HEADER_MAGIC_64 = 0x020B;

    // Section characteristics
    const IMAGE_SCN_CNT_CODE = 0x00000020;
    const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
    const IMAGE_SCN_MEM_READ = 0x40000000;
    const IMAGE_SCN_MEM_WRITE = 0x80000000;
    const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

    // Data directory indices
    const IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;

    pub fn parseFromFile(allocator: Allocator, file_path: []const u8) !*PEFile {
        const file_data = try std.fs.cwd().readFileAlloc(allocator, file_path, 500 * 1024 * 1024); // 500MB max
        defer allocator.free(file_data);
        
        var stream = std.io.fixedBufferStream(file_data);
        return parse(allocator, stream.reader());
    }

    pub fn parse(allocator: Allocator, reader: anytype) !*PEFile {
        const self = try allocator.create(PEFile);
        errdefer allocator.destroy(self);

        // Parse DOS header
        self.dos_header = try DOSHeader.parse(reader);
        if (self.dos_header.e_magic != DOS_SIGNATURE) {
            return error.InvalidDOSSignature;
        }

        // Validate e_lfanew offset (should be reasonable)
        if (self.dos_header.e_lfanew < @sizeOf(DOSHeader) or self.dos_header.e_lfanew > 0x1000) {
            return error.InvalidPEFile;
        }

        // Seek to PE header
        try reader.context.seekTo(self.dos_header.e_lfanew);
        self.pe_header_offset = self.dos_header.e_lfanew;

        // Parse PE header
        self.pe_header = try PEHeader.parse(reader);
        if (self.pe_header.signature != PE_SIGNATURE) {
            return error.InvalidPESignature;
        }

        // Parse optional header
        self.optional_header = try OptionalHeader64.parse(reader);
        if (self.optional_header.magic != OPTIONAL_HEADER_MAGIC_64) {
            return error.UnsupportedPEFormat;
        }

        // Skip any extra optional header data
        const optional_header_extra = self.pe_header.size_of_optional_header - @sizeOf(OptionalHeader64);
        if (optional_header_extra > 0) {
            try reader.skipBytes(optional_header_extra, .{});
        }

        // Parse section headers
        self.section_headers = std.ArrayList(SectionHeader).init(allocator);
        errdefer self.section_headers.deinit();
        try self.section_headers.ensureTotalCapacity(self.pe_header.number_of_sections);
        
        var i: u16 = 0;
        while (i < self.pe_header.number_of_sections) : (i += 1) {
            const section = try SectionHeader.parse(reader);
            try self.section_headers.append(section);
        }

        // Read section data
        self.sections_data = std.ArrayList([]u8).init(allocator);
        errdefer {
            for (self.sections_data.items) |data| {
                allocator.free(data);
            }
            self.sections_data.deinit();
        }

        for (self.section_headers.items) |section| {
            if (section.size_of_raw_data > 0) {
                const data = try allocator.alloc(u8, section.size_of_raw_data);
                errdefer allocator.free(data);
                
                try reader.context.seekTo(section.pointer_to_raw_data);
                try reader.readNoEof(data);
                
                try self.sections_data.append(data);
            } else {
                try self.sections_data.append(&.{});
            }
        }

        self.allocator = allocator;
        return self;
    }

    pub fn deinit(self: *PEFile) void {
        self.section_headers.deinit();
        for (self.sections_data.items) |data| {
            if (data.len > 0) {
                self.allocator.free(data);
            }
        }
        self.sections_data.deinit();
        self.allocator.destroy(self);
    }

    /// Validate the PE file structure
    pub fn validate(self: *const PEFile) !void {
        // Check DOS header
        if (self.dos_header.e_magic != DOS_SIGNATURE) {
            return error.InvalidDOSSignature;
        }

        // Check PE header
        if (self.pe_header.signature != PE_SIGNATURE) {
            return error.InvalidPESignature;
        }

        // Check optional header
        if (self.optional_header.magic != OPTIONAL_HEADER_MAGIC_64) {
            return error.UnsupportedPEFormat;
        }

        // Validate section headers
        for (self.section_headers.items, self.sections_data.items) |section, data| {
            if (section.size_of_raw_data != data.len) {
                return error.InvalidSectionData;
            }
        }
    }

    /// Rebuild PE file with modified resources
    /// This creates a new PE file with proper offset calculations
    pub fn rebuildWithResources(
        allocator: Allocator,
        input_path: []const u8,
        output_path: []const u8,
        resource_data: []const u8,
    ) !void {
        // Open input file
        const input_file = try std.fs.cwd().openFile(input_path, .{});
        defer input_file.close();

        // Parse PE headers from input
        var input_reader = input_file.reader();
        const pe = try PEFile.parse(allocator, input_reader);
        defer pe.deinit();

        // Create temporary output file
        const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{output_path});
        defer allocator.free(tmp_path);

        const output_file = try std.fs.cwd().createFile(tmp_path, .{});
        defer output_file.close();
        var writer = output_file.writer();

        // Check if .rsrc section already exists
        var rsrc_index: ?usize = null;
        for (pe.section_headers.items, 0..) |section, i| {
            const name = std.mem.sliceTo(&section.name, 0);
            if (strings.eql(name, ".rsrc")) {
                rsrc_index = i;
                break;
            }
        }

        // Calculate new section count
        const new_section_count = if (rsrc_index == null) pe.pe_header.number_of_sections + 1 else pe.pe_header.number_of_sections;

        // Calculate new SizeOfHeaders (must be aligned to FileAlignment)
        const headers_size = pe.pe_header_offset + @sizeOf(PEHeader) + pe.pe_header.size_of_optional_header + 
                           @as(u32, new_section_count) * @sizeOf(SectionHeader);
        const new_size_of_headers = alignSize(headers_size, pe.optional_header.file_alignment);

        // Write DOS header and stub
        try pe.dos_header.write(writer);
        
        // Write DOS stub (area between DOS header and PE header)
        const dos_stub_size = pe.pe_header_offset - @sizeOf(DOSHeader);
        if (dos_stub_size > 0) {
            try input_reader.context.seekTo(@sizeOf(DOSHeader));
            const dos_stub = try allocator.alloc(u8, dos_stub_size);
            defer allocator.free(dos_stub);
            try input_reader.readNoEof(dos_stub);
            try writer.writeAll(dos_stub);
        }

        // Update and write PE header
        var new_pe_header = pe.pe_header;
        new_pe_header.number_of_sections = @intCast(new_section_count);
        try new_pe_header.write(writer);

        // Update and write optional header (with placeholder for SizeOfImage)
        var new_optional_header = pe.optional_header;
        new_optional_header.size_of_headers = new_size_of_headers;
        const size_of_image_offset = output_file.getPos() catch unreachable;
        try new_optional_header.write(writer);

        // Skip any extra optional header data
        const optional_header_extra = pe.pe_header.size_of_optional_header - @sizeOf(OptionalHeader64);
        if (optional_header_extra > 0) {
            try writer.writeByteNTimes(0, optional_header_extra);
        }

        // Write existing section headers and prepare new .rsrc header if needed
        var new_rsrc_section: SectionHeader = undefined;
        var last_section_file_offset: u32 = new_size_of_headers;
        var last_section_virtual_addr: u32 = 0;

        for (pe.section_headers.items) |section| {
            try section.write(writer);
            
            const section_end = section.pointer_to_raw_data + section.size_of_raw_data;
            if (section_end > last_section_file_offset) {
                last_section_file_offset = section_end;
            }
            
            const virtual_end = section.virtual_address + alignSize(
                if (section.virtual_size > 0) section.virtual_size else section.size_of_raw_data,
                pe.optional_header.section_alignment
            );
            if (virtual_end > last_section_virtual_addr) {
                last_section_virtual_addr = virtual_end;
            }
        }

        // If adding new .rsrc section, write its header
        if (rsrc_index == null) {
            const aligned_resource_size = alignSize(@intCast(resource_data.len), pe.optional_header.file_alignment);
            
            new_rsrc_section = SectionHeader{
                .name = ".rsrc\x00\x00\x00".*,
                .virtual_size = @intCast(resource_data.len),
                .virtual_address = alignSize(last_section_virtual_addr, pe.optional_header.section_alignment),
                .size_of_raw_data = aligned_resource_size,
                .pointer_to_raw_data = alignSize(last_section_file_offset, pe.optional_header.file_alignment),
                .pointer_to_relocations = 0,
                .pointer_to_line_numbers = 0,
                .number_of_relocations = 0,
                .number_of_line_numbers = 0,
                .characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            };
            
            try new_rsrc_section.write(writer);
        }

        // Write padding up to first section
        const current_pos = try output_file.getPos();
        if (new_size_of_headers > current_pos) {
            try writer.writeByteNTimes(0, new_size_of_headers - current_pos);
        }

        // Copy section data from original file
        for (pe.section_headers.items, 0..) |section, i| {
            if (section.size_of_raw_data > 0) {
                // Seek to section position
                const write_pos = try output_file.getPos();
                if (section.pointer_to_raw_data > write_pos) {
                    try writer.writeByteNTimes(0, section.pointer_to_raw_data - write_pos);
                }

                if (rsrc_index != null and i == rsrc_index.?) {
                    // Replace resource section data
                    try writer.writeAll(resource_data);
                    // Pad to aligned size
                    const padding = section.size_of_raw_data - resource_data.len;
                    if (padding > 0) {
                        try writer.writeByteNTimes(0, padding);
                    }
                } else {
                    // Copy original section data
                    try input_reader.context.seekTo(section.pointer_to_raw_data);
                    var buffer: [4096]u8 = undefined;
                    var remaining = section.size_of_raw_data;
                    while (remaining > 0) {
                        const to_read = @min(remaining, buffer.len);
                        const read = try input_reader.read(buffer[0..to_read]);
                        try writer.writeAll(buffer[0..read]);
                        remaining -= @intCast(read);
                    }
                }
            }
        }

        // Write new .rsrc section data if adding
        if (rsrc_index == null) {
            const write_pos = try output_file.getPos();
            if (new_rsrc_section.pointer_to_raw_data > write_pos) {
                try writer.writeByteNTimes(0, new_rsrc_section.pointer_to_raw_data - write_pos);
            }
            try writer.writeAll(resource_data);
            // Pad to aligned size
            const padding = new_rsrc_section.size_of_raw_data - resource_data.len;
            if (padding > 0) {
                try writer.writeByteNTimes(0, padding);
            }
        }

        // Calculate final SizeOfImage
        var final_size_of_image = new_size_of_headers;
        for (pe.section_headers.items) |section| {
            const section_end = section.virtual_address + alignSize(
                if (section.virtual_size > 0) section.virtual_size else section.size_of_raw_data,
                pe.optional_header.section_alignment
            );
            if (section_end > final_size_of_image) {
                final_size_of_image = section_end;
            }
        }
        
        if (rsrc_index == null) {
            const rsrc_end = new_rsrc_section.virtual_address + 
                           alignSize(new_rsrc_section.virtual_size, pe.optional_header.section_alignment);
            if (rsrc_end > final_size_of_image) {
                final_size_of_image = rsrc_end;
            }
        }

        // Go back and patch SizeOfImage
        try output_file.seekTo(size_of_image_offset + 56); // Offset of size_of_image in OptionalHeader64
        try writer.writeInt(u32, final_size_of_image, .little);

        // Also update the resource data directory if we have resources
        if (resource_data.len > 0) {
            const rsrc_virtual_addr = if (rsrc_index) |idx|
                pe.section_headers.items[idx].virtual_address
            else
                new_rsrc_section.virtual_address;

            // Seek to data directory entry for resources
            const data_dir_offset = size_of_image_offset + 120 + // OptionalHeader fields before data_directories
                                  (IMAGE_DIRECTORY_ENTRY_RESOURCE * @sizeOf(DataDirectory));
            try output_file.seekTo(data_dir_offset);
            try writer.writeInt(u32, rsrc_virtual_addr, .little);
            try writer.writeInt(u32, @intCast(resource_data.len), .little);
        }

        // Close files and rename temp to final
        output_file.close();
        input_file.close();
        
        // Delete existing output file if it exists
        std.fs.cwd().deleteFile(output_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        
        try std.fs.cwd().rename(tmp_path, output_path);
    }
};

/// Align size to the nearest multiple of alignment
fn alignSize(size: u32, alignment: u32) u32 {
    if (alignment == 0) return size;
    // Check for overflow
    if (size > std.math.maxInt(u32) - alignment + 1) return std.math.maxInt(u32);
    return (size + alignment - 1) & ~(alignment - 1);
}

/// Utilities for PE file detection and validation
pub const utils = struct {
    pub fn isPE(reader: anytype) bool {
        const start_pos = reader.context.getPos() catch return false;
        defer reader.context.seekTo(start_pos) catch {};

        const dos_header = PEFile.DOSHeader.parse(reader) catch return false;
        if (dos_header.e_magic != PEFile.DOS_SIGNATURE) return false;

        reader.context.seekTo(dos_header.e_lfanew) catch return false;
        const pe_signature = reader.readInt(u32, .little) catch return false;
        
        return pe_signature == PEFile.PE_SIGNATURE;
    }
};

/// Windows-specific external interface for accessing embedded Bun data
/// This matches the macOS interface but for PE files
pub const BUN_COMPILED_SECTION_NAME = ".bun";

/// External C interface declarations - these are implemented in C++ bindings
/// The C++ code uses Windows PE APIs to directly access the .bun section
/// from the current process memory without loading the entire executable
extern "C" fn Bun__getStandaloneModuleGraphPELength() u32;
extern "C" fn Bun__getStandaloneModuleGraphPEData() ?[*]u8;

const std = @import("std");

const bun = @import("bun");
const strings = bun.strings;

const mem = std.mem;
const Allocator = mem.Allocator;