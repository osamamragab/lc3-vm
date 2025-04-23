const std = @import("std");
const builtin = @import("builtin");
const lc3 = @import("lc3.zig");
const term = @import("term.zig");

fn handleSigInt(_: i32) callconv(.C) void {
    std.process.exit(0);
}

pub fn main() !void {
    if (std.os.argv.len < 2) {
        @panic("lc3 <image_file>...\n");
    }

    const stderr = std.io.getStdErr().writer();

    var vm = lc3.LC3.init(lc3.PC_START);
    for (std.os.argv[1..]) |arg| {
        vm.readImage(std.mem.span(arg)) catch |err| {
            try stderr.print("{!}\n", .{err});
            @panic("failed to load image");
        };
    }

    const state = try term.disableInputBuffering();
    defer term.setTerm(state);

    try vm.run();
}
