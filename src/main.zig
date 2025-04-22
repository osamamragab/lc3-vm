const std = @import("std");
const lc3 = @import("lc3.zig");

extern fn input_buffering_disable() void;
extern fn input_buffering_reset() void;

pub fn main() !void {
    if (std.os.argv.len < 2) {
        @panic("lc3 <image_file>...\n");
    }

    var vm = lc3.LC3.init(lc3.PC_START);
    for (std.os.argv[1..]) |arg| {
        vm.readImage(std.mem.span(arg)) catch |err| {
            try std.io.getStdErr().writer().print("{any}", .{err});
            @panic("failed to load image");
        };
    }

    _ = input_buffering_disable();
    defer input_buffering_reset();

    try vm.loop();
}
