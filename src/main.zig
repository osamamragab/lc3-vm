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

fn memRead(addr: u16) u16 {
    if (addr == @intFromEnum(MemoryMappedRegister.KBSR)) {
        if (checkInputKey()) {
            memory[@intFromEnum(MemoryMappedRegister.KBSR)] = 1 << 15;
            memory[@intFromEnum(MemoryMappedRegister.KBDR)] = @as(u16, @intCast(stdin.readByte() catch 0));
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

    const org = try reader.readInt(u16, .little);
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
    var x = n;
    if ((x >> (bc - 1)) & 1 != 0) {
        x |= @as(u16, 0xffff) << bc;
    }
    return x;
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

    var timeout: linux.timeval = .{
        .sec = 0,
        .usec = 0,
    };

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

    var running = true;
    while (running) {
        const instr = memRead(registers[@intFromEnum(Register.PC)]);
        registers[@intFromEnum(Register.PC)] += 1;
        const op = instr >> 12;
        switch (@as(Opcode, @enumFromInt(op))) {
            Opcode.BR => {
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const cond_flag = (instr >> 9) & 0x7;
                if (cond_flag & registers[@intFromEnum(Register.COND)] != 0) {
                    registers[@intFromEnum(Register.PC)], _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                }
            },
            Opcode.JMP => {
                const r1 = (instr >> 6) & 0x7;
                registers[@intFromEnum(Register.PC)] = registers[r1];
            },
            Opcode.JSR => {
                registers[@intFromEnum(Register.R7)] = registers[@intFromEnum(Register.PC)];
                const long_flag = (instr >> 11) & 0x1;
                if (long_flag != 0) {
                    const pc_offset = signExtend(instr & 0x7ff, 11);
                    const val, _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                    registers[@intFromEnum(Register.PC)] = val;
                } else {
                    const r1 = (instr >> 6) & 0x7;
                    registers[@intFromEnum(Register.PC)] = registers[r1];
                }
            },
            Opcode.LD => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr, _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                registers[r0] = memRead(addr);
                updateFlags(r0);
            },
            Opcode.LDI => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr, _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                registers[r0] = memRead(memRead(addr));
                updateFlags(r0);
            },
            Opcode.LDR => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3f, 6);
                const addr, _ = @addWithOverflow(registers[r1], offset);
                registers[r0] = memRead(addr);
                updateFlags(r0);
            },
            Opcode.LEA => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                registers[r0], _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                updateFlags(r0);
            },
            Opcode.ST => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr, _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                memWrite(addr, registers[r0]);
            },
            Opcode.STI => {
                const r0 = (instr >> 9) & 0x7;
                const pc_offset = signExtend(instr & 0x1ff, 9);
                const addr, _ = @addWithOverflow(registers[@intFromEnum(Register.PC)], pc_offset);
                memWrite(memRead(addr), registers[r0]);
            },
            Opcode.STR => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const offset = signExtend(instr & 0x3f, 6);
                const addr, _ = @addWithOverflow(registers[r1], offset);
                memWrite(addr, registers[r0]);
            },
            Opcode.NOT => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                registers[r0] = ~registers[r1];
                updateFlags(r0);
            },
            Opcode.AND => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const val = if ((instr >> 5) & 0x1 != 0) signExtend(instr & 0x1f, 5) else registers[instr & 0x7];
                registers[r0] = registers[r1] & val;
                updateFlags(r0);
            },
            Opcode.ADD => {
                const r0 = (instr >> 9) & 0x7;
                const r1 = (instr >> 6) & 0x7;
                const val = if ((instr >> 5) & 0x1 != 0) signExtend(instr & 0x1f, 5) else registers[instr & 0x7];
                registers[r0], _ = @addWithOverflow(registers[r1], val);
                updateFlags(r0);
            },
            Opcode.TRAP => {
                registers[@intFromEnum(Register.R7)] = registers[@intFromEnum(Register.PC)];
                switch (@as(Trap, @enumFromInt(instr & 0xFF))) {
                    Trap.GETC => {
                        registers[@intFromEnum(Register.R0)] = @as(u16, try stdin.readByte());
                        updateFlags(@intFromEnum(Register.R0));
                    },
                    Trap.IN => {
                        try stdout.print("Input character: ", .{});
                        const c = try stdin.readByte();
                        try stdout.writeByte(c);
                        try stdout_writer.flush();
                        registers[@intFromEnum(Register.R0)] = @as(u16, c);
                        updateFlags(registers[@intFromEnum(Register.R0)]);
                    },
                    Trap.OUT => {
                        try stdout.writeByte(@as(u8, @intCast(registers[@intFromEnum(Register.R0)])));
                        try stdout_writer.flush();
                    },
                    Trap.PUTS => {
                        var i = registers[@intFromEnum(Register.R0)];
                        var c = memory[i];
                        while (c != 0) {
                            try stdout.writeByte(@truncate(c >> 8));
                            try stdout.writeByte(@truncate(c & 0xff));
                            i += 1;
                            c = memory[i];
                        }
                        try stdout_writer.flush();
                    },
                    Trap.PUTSP => {
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
                    Trap.HALT => {
                        try stdout.print("HALT\n", .{});
                        try stdout_writer.flush();
                        running = false;
                    },
                }
            },
            Opcode.RES, Opcode.RTI => @panic("unimplemented"),
        }
    }
}
