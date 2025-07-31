const std = @import("std");
const bun = @import("bun");
const strings = bun.strings;
const Allocator = std.mem.Allocator;

// Windows resource types
pub const ResourceType = enum(u16) {
    ICON = 3,
    GROUP_ICON = 14,
    VERSION = 16,
    _,
};

// Resource structures - properly aligned and using packed structs
pub const ResourceDirectoryTable = extern struct {
    characteristics: u32,
    timestamp: u32,
    major_version: u16,
    minor_version: u16,
    number_of_name_entries: u16,
    number_of_id_entries: u16,
};

pub const ResourceDirectoryEntry = extern struct {
    id_or_name: u32, // High bit set = name offset, else ID
    offset_to_data: u32, // High bit set = subdirectory, else data entry
};

pub const ResourceDataEntry = extern struct {
    data_rva: u32,
    size: u32,
    codepage: u32,
    reserved: u32,
};

// Version info structures
pub const VS_FIXEDFILEINFO = extern struct {
    signature: u32 = 0xFEEF04BD,
    struct_version: u32 = 0x00010000,
    file_version_ms: u32,
    file_version_ls: u32,
    product_version_ms: u32,
    product_version_ls: u32,
    file_flags_mask: u32 = 0x3F,
    file_flags: u32 = 0,
    file_os: u32 = 0x40004, // VOS_NT_WINDOWS32
    file_type: u32 = 0x1, // VFT_APP
    file_subtype: u32 = 0,
    file_date_ms: u32 = 0,
    file_date_ls: u32 = 0,
};

// Version info block header
pub const VersionInfoHeader = packed struct {
    length: u16,
    value_length: u16,
    type: u16, // 0 = binary, 1 = text
};

// Icon structures
pub const IconDirEntry = extern struct {
    width: u8,
    height: u8,
    color_count: u8,
    reserved: u8,
    planes: u16,
    bit_count: u16,
    bytes_in_res: u32,
    image_offset: u32,
};

pub const GroupIconDirEntry = extern struct {
    width: u8,
    height: u8,
    color_count: u8,
    reserved: u8,
    planes: u16,
    bit_count: u16,
    bytes_in_res: u32,
    id: u16,
};

// Resource tree node
const ResourceNode = struct {
    id_or_name: union(enum) {
        id: u16,
        name: []const u16,
    },
    children: ?*ResourceDirectory = null,
    data: ?ResourceData = null,
};

const ResourceDirectory = struct {
    entries: std.ArrayList(ResourceNode),
};

const ResourceData = struct {
    rva: u32,
    data: []const u8,
};

// Version info builder using structured approach
pub const VersionInfoBuilder = struct {
    allocator: Allocator,
    version: WindowsVersion,
    strings: std.StringArrayHashMap([]const u8),

    pub fn init(allocator: Allocator, version: WindowsVersion) VersionInfoBuilder {
        return .{
            .allocator = allocator,
            .version = version,
            .strings = std.StringArrayHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *VersionInfoBuilder) void {
        self.strings.deinit();
    }

    pub fn addString(self: *VersionInfoBuilder, key: []const u8, value: []const u8) !void {
        try self.strings.put(key, value);
    }

    pub fn build(self: *VersionInfoBuilder) ![]u8 {
        // Calculate sizes
        const fixed_info_size = @sizeOf(VS_FIXEDFILEINFO);
        var total_size: usize = @sizeOf(VersionInfoHeader) + 30 + // VS_VERSIONINFO header + key
            align4(fixed_info_size); // Fixed info
        
        // Calculate string table size
        if (self.strings.count() > 0) {
            total_size += @sizeOf(VersionInfoHeader) + 30; // StringFileInfo header
            total_size += @sizeOf(VersionInfoHeader) + 18; // StringTable header
            
            var iter = self.strings.iterator();
            while (iter.next()) |entry| {
                const key_utf16_len = try std.unicode.utf8CountUtf16CodeUnits(entry.key_ptr.*);
                const value_utf16_len = try std.unicode.utf8CountUtf16CodeUnits(entry.value_ptr.*);
                total_size += @sizeOf(VersionInfoHeader) + 
                    align4((key_utf16_len + 1) * 2) + 
                    align4((value_utf16_len + 1) * 2);
            }
        }

        // Allocate buffer
        const buffer = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(buffer);
        
        var offset: usize = 0;

        // Write VS_VERSIONINFO header
        const version_info_start = offset;
        const version_header = VersionInfoHeader{
            .length = @intCast(total_size),
            .value_length = fixed_info_size,
            .type = 0, // Binary
        };
        @memcpy(buffer[offset..][0..@sizeOf(VersionInfoHeader)], std.mem.asBytes(&version_header));
        offset += @sizeOf(VersionInfoHeader);

        // Write "VS_VERSION_INFO" key
        const version_key = [_]u16{ 'V', 'S', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N', 'I', 'N', 'F', 'O', 0 };
        @memcpy(buffer[offset..][0..version_key.len * 2], std.mem.sliceAsBytes(&version_key));
        offset += version_key.len * 2;

        // Align to DWORD
        offset = align4(offset);

        // Write VS_FIXEDFILEINFO
        const fixed_info = VS_FIXEDFILEINFO{
            .file_version_ms = (@as(u32, self.version.major) << 16) | self.version.minor,
            .file_version_ls = (@as(u32, self.version.patch) << 16) | self.version.build,
            .product_version_ms = (@as(u32, self.version.major) << 16) | self.version.minor,
            .product_version_ls = (@as(u32, self.version.patch) << 16) | self.version.build,
        };
        @memcpy(buffer[offset..][0..@sizeOf(VS_FIXEDFILEINFO)], std.mem.asBytes(&fixed_info));
        offset += @sizeOf(VS_FIXEDFILEINFO);

        // Align to DWORD
        offset = align4(offset);

        // Write StringFileInfo if we have strings
        if (self.strings.count() > 0) {
            const string_file_info_start = offset;
            
            // StringFileInfo header
            offset += @sizeOf(VersionInfoHeader); // Skip header, will fill later
            const string_file_key = [_]u16{ 'S', 't', 'r', 'i', 'n', 'g', 'F', 'i', 'l', 'e', 'I', 'n', 'f', 'o', 0 };
            @memcpy(buffer[offset..][0..string_file_key.len * 2], std.mem.sliceAsBytes(&string_file_key));
            offset += string_file_key.len * 2;
            offset = align4(offset);

            // StringTable header
            const string_table_start = offset;
            offset += @sizeOf(VersionInfoHeader); // Skip header, will fill later
            const lang_charset = [_]u16{ '0', '4', '0', '9', '0', '4', 'E', '4', 0 }; // US English, Unicode
            @memcpy(buffer[offset..][0..lang_charset.len * 2], std.mem.sliceAsBytes(&lang_charset));
            offset += lang_charset.len * 2;
            offset = align4(offset);

            // Write string entries
            var iter = self.strings.iterator();
            while (iter.next()) |entry| {
                const string_start = offset;
                offset += @sizeOf(VersionInfoHeader); // Skip header

                // Write key
                const key_utf16 = try self.allocator.allocSentinel(u16, try std.unicode.utf8CountUtf16CodeUnits(entry.key_ptr.*), 0);
                defer self.allocator.free(key_utf16);
                _ = try std.unicode.utf8ToUtf16Le(key_utf16, entry.key_ptr.*);
                @memcpy(buffer[offset..][0..key_utf16.len * 2], std.mem.sliceAsBytes(key_utf16[0..key_utf16.len]));
                offset += (key_utf16.len + 1) * 2;
                offset = align4(offset);

                // Write value
                const value_utf16 = try self.allocator.allocSentinel(u16, try std.unicode.utf8CountUtf16CodeUnits(entry.value_ptr.*), 0);
                defer self.allocator.free(value_utf16);
                _ = try std.unicode.utf8ToUtf16Le(value_utf16, entry.value_ptr.*);
                @memcpy(buffer[offset..][0..value_utf16.len * 2], std.mem.sliceAsBytes(value_utf16[0..value_utf16.len]));
                offset += (value_utf16.len + 1) * 2;
                offset = align4(offset);

                // Update string entry header
                const string_header = VersionInfoHeader{
                    .length = @intCast(offset - string_start),
                    .value_length = @intCast(value_utf16.len + 1),
                    .type = 1, // Text
                };
                @memcpy(buffer[string_start..][0..@sizeOf(VersionInfoHeader)], std.mem.asBytes(&string_header));
            }

            // Update StringTable header
            const string_table_header = VersionInfoHeader{
                .length = @intCast(offset - string_table_start),
                .value_length = 0,
                .type = 1,
            };
            @memcpy(buffer[string_table_start..][0..@sizeOf(VersionInfoHeader)], std.mem.asBytes(&string_table_header));

            // Update StringFileInfo header
            const string_file_info_header = VersionInfoHeader{
                .length = @intCast(offset - string_file_info_start),
                .value_length = 0,
                .type = 1,
            };
            @memcpy(buffer[string_file_info_start..][0..@sizeOf(VersionInfoHeader)], std.mem.asBytes(&string_file_info_header));
        }

        return buffer[0..offset];
    }

    fn align4(n: usize) usize {
        return (n + 3) & ~@as(usize, 3);
    }
};

// Resource section builder using structured approach
pub const ResourceSectionBuilder = struct {
    allocator: Allocator,
    root: ResourceDirectory,
    data_blocks: std.ArrayList([]const u8),
    string_pool: std.ArrayList([]const u16),

    pub fn init(allocator: Allocator) ResourceSectionBuilder {
        return .{
            .allocator = allocator,
            .root = ResourceDirectory{ .entries = std.ArrayList(ResourceNode).init(allocator) },
            .data_blocks = std.ArrayList([]const u8).init(allocator),
            .string_pool = std.ArrayList([]const u16).init(allocator),
        };
    }

    pub fn deinit(self: *ResourceSectionBuilder) void {
        self.root.entries.deinit();
        self.data_blocks.deinit();
        self.string_pool.deinit();
    }

    pub fn addResource(self: *ResourceSectionBuilder, type_id: u16, name_id: u16, lang_id: u16, data: []const u8) !void {
        // Find or create type directory
        var type_node: ?*ResourceNode = null;
        for (self.root.entries.items) |*entry| {
            if (entry.id_or_name == .id and entry.id_or_name.id == type_id) {
                type_node = entry;
                break;
            }
        }
        
        if (type_node == null) {
            try self.root.entries.append(.{
                .id_or_name = .{ .id = type_id },
                .children = try self.allocator.create(ResourceDirectory),
            });
            type_node = &self.root.entries.items[self.root.entries.items.len - 1];
            type_node.?.children.?.* = ResourceDirectory{ .entries = std.ArrayList(ResourceNode).init(self.allocator) };
        }

        // Find or create name directory
        var name_node: ?*ResourceNode = null;
        for (type_node.?.children.?.entries.items) |*entry| {
            if (entry.id_or_name == .id and entry.id_or_name.id == name_id) {
                name_node = entry;
                break;
            }
        }

        if (name_node == null) {
            try type_node.?.children.?.entries.append(.{
                .id_or_name = .{ .id = name_id },
                .children = try self.allocator.create(ResourceDirectory),
            });
            name_node = &type_node.?.children.?.entries.items[type_node.?.children.?.entries.items.len - 1];
            name_node.?.children.?.* = ResourceDirectory{ .entries = std.ArrayList(ResourceNode).init(self.allocator) };
        }

        // Add language entry
        const data_copy = try self.allocator.dupe(u8, data);
        try self.data_blocks.append(data_copy);
        
        try name_node.?.children.?.entries.append(.{
            .id_or_name = .{ .id = lang_id },
            .data = ResourceData{
                .rva = 0, // Will be set during build
                .data = data_copy,
            },
        });
    }

    pub fn build(self: *ResourceSectionBuilder, base_rva: u32) ![]u8 {
        // Calculate total size needed
        var total_size: usize = 0;
        var dir_count: usize = 0;
        var entry_count: usize = 0;
        var data_entry_count: usize = 0;
        
        self.countNodes(&self.root, &dir_count, &entry_count, &data_entry_count);
        
        const dir_size = dir_count * @sizeOf(ResourceDirectoryTable);
        const entries_size = entry_count * @sizeOf(ResourceDirectoryEntry);
        const data_entries_size = data_entry_count * @sizeOf(ResourceDataEntry);
        
        var data_size: usize = 0;
        for (self.data_blocks.items) |data| {
            data_size += align8(data.len);
        }

        total_size = dir_size + entries_size + data_entries_size + data_size;
        
        // Allocate buffer
        const buffer = try self.allocator.alloc(u8, total_size);
        errdefer self.allocator.free(buffer);
        
        var offset: usize = 0;
        var data_offset: usize = dir_size + entries_size + data_entries_size;
        
        // Write directories recursively
        _ = try self.writeDirectory(&self.root, buffer, &offset, base_rva, data_offset + base_rva);
        
        return buffer;
    }

    fn countNodes(self: *ResourceSectionBuilder, dir: *const ResourceDirectory, dir_count: *usize, entry_count: *usize, data_entry_count: *usize) void {
        _ = self;
        dir_count.* += 1;
        entry_count.* += dir.entries.items.len;
        
        for (dir.entries.items) |*entry| {
            if (entry.children) |child_dir| {
                self.countNodes(child_dir, dir_count, entry_count, data_entry_count);
            } else if (entry.data != null) {
                data_entry_count.* += 1;
            }
        }
    }

    fn writeDirectory(self: *ResourceSectionBuilder, dir: *const ResourceDirectory, buffer: []u8, offset: *usize, base_rva: u32, data_rva: u32) !u32 {
        _ = self;
        _ = base_rva;
        const dir_offset = offset.*;
        
        // Count name and ID entries
        var name_count: u16 = 0;
        var id_count: u16 = 0;
        for (dir.entries.items) |entry| {
            switch (entry.id_or_name) {
                .name => name_count += 1,
                .id => id_count += 1,
            }
        }
        
        // Write directory table
        const dir_table = ResourceDirectoryTable{
            .characteristics = 0,
            .timestamp = 0,
            .major_version = 0,
            .minor_version = 0,
            .number_of_name_entries = name_count,
            .number_of_id_entries = id_count,
        };
        @memcpy(buffer[offset.*..][0..@sizeOf(ResourceDirectoryTable)], std.mem.asBytes(&dir_table));
        offset.* += @sizeOf(ResourceDirectoryTable);
        
        // Write entries
        for (dir.entries.items) |entry| {
            const id_or_name: u32 = switch (entry.id_or_name) {
                .id => |id| id,
                .name => |name| 0x80000000 | @as(u32, @intCast(name.len)), // TODO: string table offset
            };
            
            var offset_to_data: u32 = 0;
            if (entry.children) |child_dir| {
                const child_offset = try self.writeDirectory(child_dir, buffer, offset, base_rva, data_rva);
                offset_to_data = 0x80000000 | child_offset;
            } else if (entry.data) |data| {
                // Write data entry
                const data_entry = ResourceDataEntry{
                    .data_rva = data_rva,
                    .size = @intCast(data.data.len),
                    .codepage = 0,
                    .reserved = 0,
                };
                // TODO: write data entry at correct offset
                _ = data_entry;
            }
            
            const dir_entry = ResourceDirectoryEntry{
                .id_or_name = id_or_name,
                .offset_to_data = offset_to_data,
            };
            @memcpy(buffer[offset.*..][0..@sizeOf(ResourceDirectoryEntry)], std.mem.asBytes(&dir_entry));
            offset.* += @sizeOf(ResourceDirectoryEntry);
        }
        
        return @intCast(dir_offset);
    }

    fn align8(n: usize) usize {
        return (n + 7) & ~@as(usize, 7);
    }
};

pub const WindowsVersion = struct {
    major: u16,
    minor: u16,
    patch: u16,
    build: u16,
};

pub fn parseWindowsVersion(str: []const u8) !WindowsVersion {
    var parts_iter = std.mem.tokenizeScalar(u8, str, '.');
    const major_str = parts_iter.next() orelse return error.InvalidFormat;
    const minor_str = parts_iter.next() orelse return error.InvalidFormat;
    const patch_str = parts_iter.next() orelse return error.InvalidFormat;
    const build_str = parts_iter.next() orelse return error.InvalidFormat;

    if (parts_iter.next() != null) return error.InvalidFormat;

    return WindowsVersion{
        .major = std.fmt.parseInt(u16, major_str, 10) catch return error.InvalidFormat,
        .minor = std.fmt.parseInt(u16, minor_str, 10) catch return error.InvalidFormat,
        .patch = std.fmt.parseInt(u16, patch_str, 10) catch return error.InvalidFormat,
        .build = std.fmt.parseInt(u16, build_str, 10) catch return error.InvalidFormat,
    };
}