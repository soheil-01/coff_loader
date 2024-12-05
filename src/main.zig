const std = @import("std");
const CoffLoader = @import("coff_loader");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return error.MissingFilePath;
    if (args.len < 3) return error.MissingEntryPoint;

    const file_path = args[1];
    const entry_point = args[2];

    var coff_loader = try CoffLoader.init(allocator, file_path);
    defer coff_loader.deinit();

    try coff_loader.load(entry_point);
}
