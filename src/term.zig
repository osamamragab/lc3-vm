const std = @import("std");
const linux = std.os.linux;

pub fn disableInputBuffering() !linux.termios {
    const in = std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_only }) catch unreachable;
    var tio = linux.termios{
        .iflag = .{},
        .oflag = .{},
        .cflag = .{},
        .lflag = .{},
        .cc = std.mem.zeroes([32]u8),
        .line = 0,
        .ispeed = linux.speed_t.B38400,
        .ospeed = linux.speed_t.B38400,
    };

    _ = linux.tcgetattr(in.handle, &tio);
    const tio_def = tio;

    tio.lflag.ECHO = false;
    tio.lflag.ICANON = false;

    _ = linux.tcsetattr(in.handle, linux.TCSA.NOW, &tio);
    return tio_def;
}

pub fn setTerm(tio: linux.termios) void {
    const in = std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_only }) catch unreachable;
    _ = linux.tcsetattr(in.handle, linux.TCSA.NOW, &tio);
}
