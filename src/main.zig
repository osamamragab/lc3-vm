const std = @import("std");
const io = std.io;
const fs = std.fs;
const os = std.os;
const mem = std.mem;
const linux = os.linux;

var stdout_writer = io.bufferedWriter(io.getStdOut().writer());
const stdout = stdout_writer.writer();
const stdin = io.getStdIn().reader();

const PC_START = 0x0;

var memory: [1 << 16]u16 = undefined;

const Register = enum {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    PC,
    COND,
};

var registers: [@typeInfo(Register).@"enum".fields.len]u16 = undefined;

const Opcode = enum {
    BR,
    ADD,
    LD,
    ST,
    JSR,
    AND,
    LDR,
    STR,
    RTI,
    NOT,
    LDI,
    STI,
    JMP,
    RES,
    LEA,
    TRAP,
};

const ConditionFlag = enum(u8) {
    POS = 1 << 0,
    ZRO = 1 << 1,
    NEG = 1 << 2,
};

const Trap = enum(u16) {
    GETC = 0x20,
    OUT = 0x21,
    PUTS = 0x22,
    IN = 0x23,
    PUTSP = 0x24,
    HALT = 0x25,
};

const MemoryMappedRegister = enum(u16) {
    KBSR = 0xFE00,
    KBDR = 0xFE02,
};

fn memWrite(addr: u16, val: u16) void {
    memory[addr] = val;
}

fn memRead(addr: u16) !u16 {
    if (addr == @intFromEnum(MemoryMappedRegister.KBSR)) {
        if (checkInputKey()) {
            memory[@intFromEnum(MemoryMappedRegister.KBSR)] = 1 << 15;
            memory[@intFromEnum(MemoryMappedRegister.KBDR)] = try stdin.readInt(u16, .big);
        } else {
            memory[@intFromEnum(MemoryMappedRegister.KBSR)] = 0;
        }
    }
    return memory[addr];
}

fn readImage(filename: []const u8) !void {
    var file = try fs.cwd().openFile(filename, .{ .mode = .read_only });
    defer file.close();
    const file_reader = file.reader();
    var buffered_reader = io.bufferedReader(file_reader);
    var reader = buffered_reader.reader();

    const org = try reader.readInt(u16, .big);
    if (org >= memory.len) {
        return error.EOF;
    }

    const max_read: usize = memory.len - @as(usize, org);
    const file_size = (try file.stat()).size;
    const read_size = @min(max_read, @divFloor(file_size - @sizeOf(u16), @sizeOf(u16)));

    for (0..read_size) |i| {
        var v: u16 = undefined;
        const rsize = try reader.read(@as([*]u8, @ptrCast(&v))[0..@sizeOf(u16)]);
        if (rsize != @sizeOf(u16)) {
            return error.EOF;
        }
        memory[org + i] = swap16(v);
    }
}

fn swap16(n: u16) u16 {
    return (n << 8) | (n >> 8);
}

fn signExtend(n: u16, bc: u4) u16 {
    if ((n >> (bc - 1)) & 1 != 0) {
        return n | (@as(u16, 0xffff) << bc);
    }
    return n;
}

fn updateFlags(r: u16) void {
    const flag = if (registers[r] == 0)
        ConditionFlag.ZRO
    else if (registers[r] >> 15 != 0)
        ConditionFlag.NEG
    else
        ConditionFlag.POS;
    registers[@intFromEnum(Register.COND)] = @intFromEnum(flag);
}

const FdSet = std.StaticBitSet(1 << 10);

comptime {
    std.debug.assert(@sizeOf(FdSet) == (1 << 10) / 8);
}

fn checkInputKey() bool {
    var readfds = FdSet.initEmpty();
    readfds.setValue(linux.STDIN_FILENO, true);

    var timeout: linux.timeval = .{ .sec = 0, .usec = 0 };

    return linux.syscall6(
        .pselect6,
        1,
        @intFromPtr(&readfds),
        0,
        0,
        @intFromPtr(&timeout),
        0,
    ) != 0;
}

pub fn main() !void {
    var tio: linux.termios = undefined;
    _ = linux.tcgetattr(linux.STDIN_FILENO, &tio);
    var new_tio = tio;
    new_tio.lflag = .{ .ICANON = true, .ECHO = true };
    _ = linux.tcgetattr(linux.STDIN_FILENO, &tio);
    defer _ = linux.tcsetattr(linux.STDIN_FILENO, .NOW, &tio);

    if (os.argv.len < 2) {
        @panic("lc3 <image_file>...\n");
    }

    registers[@intFromEnum(Register.PC)] = PC_START;
    registers[@intFromEnum(Register.COND)] = @intFromEnum(ConditionFlag.ZRO);

    for (os.argv[1..]) |arg| {
        readImage(mem.span(arg)) catch @panic("failed to load image");
    }

    loop: while (true) {
        const instr = try memRead(registers[@intFromEnum(Register.PC)]);
        registers[@intFromEnum(Register.PC)] += 1;
        const op = instr >> 12;
        switch (@as(Opcode, @enumFromInt(op))) {
            .BR => {
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const cond_flag = (instr >> 9) & 0x7;
                if (cond_flag & registers[@intFromEnum(Register.COND)] != 0) {
                    registers[@intFromEnum(Register.PC)] = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                }
            },
            .JMP => {
                const r1 = (instr >> 6) & 0x7;
                registers[@intFromEnum(Register.PC)] = registers[r1];
            },
            .JSR => {
                registers[@intFromEnum(Register.R7)] = registers[@intFromEnum(Register.PC)];
                const long_flag = (instr >> 11) & 0x1;
                if (long_flag != 0) {
                    const pc_offset = signExtend(instr & 0x7ff, 11);
                    registers[@intFromEnum(Register.PC)] = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                } else {
                    const r1 = (instr >> 6) & 0x7;
                    registers[@intFromEnum(Register.PC)] = registers[r1];
                }
            },
            .LD => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                registers[r0] = try memRead(addr);
                updateFlags(r0);
            },
            .LDI => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                registers[r0] = try memRead(try memRead(addr));
                updateFlags(r0);
            },
            .LDR => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3f, 6);
                const addr = @addWithOverflow(registers[r1], offset)[0];
                registers[r0] = try memRead(addr);
                updateFlags(r0);
            },
            .LEA => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                registers[r0] = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                updateFlags(r0);
            },
            .ST => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                memWrite(addr, registers[r0]);
            },
            .STI => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset)[0];
                memWrite(try memRead(addr), registers[r0]);
            },
            .STR => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3f, 6);
                const addr = @addWithOverflow(registers[r1], offset)[0];
                memWrite(addr, registers[r0]);
            },
            .NOT => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                registers[r0] = ~registers[r1];
                updateFlags(r0);
            },
            .AND => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const val = if ((instr >> 5) & 0x1 != 0) signExtend(instr & 0x1f, 5) else registers[instr & 0x7];
                registers[r0] = registers[r1] & val;
                updateFlags(r0);
            },
            .ADD => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const val = if ((instr >> 5) & 0x1 != 0) signExtend(instr & 0x1f, 5) else registers[instr & 0x7];
                registers[r0] = @addWithOverflow(registers[r1], val)[0];
                updateFlags(r0);
            },
            .TRAP => {
                registers[@intFromEnum(Register.R7)] = registers[@intFromEnum(Register.PC)];
                switch (@as(Trap, @enumFromInt(instr & 0xFF))) {
                    .GETC => {
                        registers[@intFromEnum(Register.R0)] = @as(u16, try stdin.readByte());
                        updateFlags(@intFromEnum(Register.R0));
                    },
                    .IN => {
                        try stdout.writeAll("Input character: ");
                        const c = try stdin.readByte();
                        try stdout.writeByte(c);
                        try stdout_writer.flush();
                        registers[@intFromEnum(Register.R0)] = @as(u16, c);
                        updateFlags(@intFromEnum(Register.R0));
                    },
                    .OUT => {
                        try stdout.writeByte(@truncate(registers[@intFromEnum(Register.R0)]));
                        try stdout_writer.flush();
                    },
                    .PUTS => {
                        var addr = registers[@intFromEnum(Register.R0)];
                        var char = try memRead(addr);
                        while (char != 0) {
                            try stdout.writeByte(@truncate(char >> 8));
                            try stdout.writeByte(@truncate(char & 0xff));
                            addr = @addWithOverflow(addr, 1)[0];
                            char = try memRead(addr);
                        }
                        try stdout_writer.flush();
                    },
                    .PUTSP => {
                        var i = registers[@intFromEnum(Register.R0)];
                        var c = memory[i];
                        while (c != 0) {
                            try stdout.writeByte(@truncate(c & 0xff));
                            const c8 = @as(u8, @truncate(c >> 8));
                            if (c8 != 0) {
                                try stdout.writeByte(c8);
                            }
                            i += 1;
                            c = memory[i];
                        }
                        try stdout_writer.flush();
                    },
                    .HALT => {
                        try stdout.writeAll("HALT\n");
                        try stdout_writer.flush();
                        break :loop;
                    },
                }
            },
            .RES, .RTI => @panic("unimplemented"),
        }
    }
}
