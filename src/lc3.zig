const std = @import("std");

extern fn check_key() bool;

var stdout_writer = std.io.bufferedWriter(std.io.getStdOut().writer());
const stdout = stdout_writer.writer();
const stdin = std.io.getStdIn().reader();

pub const PC_START = 0x3000;

pub const Register = enum(u8) {
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

    pub fn len() usize {
        return @typeInfo(Register).@"enum".fields.len;
    }

    pub fn val(self: Register) u16 {
        return @intFromEnum(self);
    }
};

const R_R0 = Register.R0.val();
const R_R1 = Register.R1.val();
const R_R2 = Register.R2.val();
const R_R3 = Register.R3.val();
const R_R4 = Register.R4.val();
const R_R5 = Register.R5.val();
const R_R6 = Register.R6.val();
const R_R7 = Register.R7.val();
const R_PC = Register.PC.val();
const R_COND = Register.COND.val();

pub const Opcode = enum(u8) {
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

    pub fn fromInstruction(instr: u16) Opcode {
        return @as(Opcode, @enumFromInt(instr >> 12));
    }

    pub fn val(self: Opcode) u16 {
        return @intFromEnum(self);
    }
};

pub const ConditionFlag = enum(u8) {
    POS = 1 << 0,
    ZRO = 1 << 1,
    NEG = 1 << 2,

    pub fn val(self: ConditionFlag) u16 {
        return @intFromEnum(self);
    }
};

pub const Trap = enum(u16) {
    GETC = 0x20,
    OUT = 0x21,
    PUTS = 0x22,
    IN = 0x23,
    PUTSP = 0x24,
    HALT = 0x25,

    pub fn fromInstruction(instr: u16) Trap {
        return @as(Trap, @enumFromInt(instr & 0xFF));
    }

    pub fn val(self: Trap) u16 {
        return @intFromEnum(self);
    }
};

pub const MemoryMappedRegister = enum(u16) {
    KBSR = 0xFE00,
    KBDR = 0xFE02,

    pub fn val(self: MemoryMappedRegister) u16 {
        return @intFromEnum(self);
    }
};

const MMR_KBSR = MemoryMappedRegister.KBSR.val();
const MMR_KBDR = MemoryMappedRegister.KBDR.val();

pub const LC3 = struct {
    memory: [1 << 16]u16 = undefined,
    registers: [Register.len()]u16 = undefined,

    pub fn init(pc_start: u16) LC3 {
        var vm = LC3{};
        vm.registers[R_PC] = pc_start;
        vm.registers[R_COND] = ConditionFlag.ZRO.val();
        return vm;
    }

    fn signExtend(n: u16, comptime bc: u4) u16 {
        if ((n >> (bc - 1)) & 1 != 0) {
            return n | (@as(u16, 0xFFFF) << bc);
        }
        return n;
    }

    fn updateFlags(self: *LC3, r: u16) void {
        const flag = if (self.registers[r] == 0)
            ConditionFlag.ZRO
        else if (self.registers[r] >> 15 != 0)
            ConditionFlag.NEG
        else
            ConditionFlag.POS;
        self.registers[R_COND] = flag.val();
    }

    fn memWrite(self: *LC3, addr: u16, val: u16) void {
        self.memory[addr] = val;
    }

    fn memRead(self: *LC3, addr: u16) !u16 {
        if (addr == MMR_KBSR) {
            if (check_key()) {
                self.memory[MMR_KBSR] = 1 << 15;
                self.memory[MMR_KBDR] = @intCast(try stdin.readInt(u8, .big));
            } else {
                self.memory[MMR_KBSR] = 0;
            }
        }
        return self.memory[addr];
    }

    pub fn readImage(self: *LC3, filename: []const u8) !void {
        var file = try std.fs.cwd().openFile(filename, .{ .mode = .read_only });
        defer file.close();

        const file_size = try file.getEndPos();
        if (file_size < @sizeOf(u16)) {
            return error.FileTooSmall;
        }

        const reader = file.reader();

        const org = try reader.readInt(u16, .big);
        if (org >= self.memory.len) {
            return error.InvalidOrigin;
        }

        const read_size = @divFloor(file_size - @sizeOf(u16), @sizeOf(u16));
        if (org + read_size > self.memory.len) {
            return error.FileTooLarge;
        }

        for (0..read_size) |i| {
            self.memory[org + i] = try reader.readInt(u16, .big);
        }
    }

    pub fn loop(self: *LC3) !void {
        loop: while (true) {
            const instr = try self.memRead(self.registers[R_PC]);
            self.registers[R_PC] = @addWithOverflow(self.registers[R_PC], 1)[0];
            switch (Opcode.fromInstruction(instr)) {
                .BR => {
                    const pc_offset = signExtend(instr & 0x1FF, 9);
                    const cond_flag = (instr >> 9) & 0x7;
                    if (cond_flag & self.registers[R_COND] != 0) {
                        self.registers[R_PC] = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    }
                },
                .JMP => {
                    const r1 = (instr >> 6) & 0x7;
                    self.registers[R_PC] = self.registers[r1];
                },
                .JSR => {
                    self.registers[R_R7] = self.registers[R_PC];
                    const long_flag = (instr >> 11) & 0x1;
                    if (long_flag != 0) {
                        const pc_offset = signExtend(instr & 0x7FF, 11);
                        self.registers[R_PC] = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    } else {
                        const r1 = (instr >> 6) & 0x7;
                        self.registers[R_PC] = self.registers[r1];
                    }
                },
                .LD => {
                    const r0 = (instr >> 9) & 0x7;
                    const pc_offset = signExtend(instr & 0x1FF, 9);
                    const addr = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    self.registers[r0] = try self.memRead(addr);
                    self.updateFlags(r0);
                },
                .LDI => {
                    const r0 = (instr >> 9) & 0x7;
                    const pc_offset = signExtend(instr & 0x1FF, 9);
                    const addr = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    self.registers[r0] = try self.memRead(try self.memRead(addr));
                    self.updateFlags(r0);
                },
                .LDR => {
                    const r0 = (instr >> 9) & 0x7;
                    const r1 = (instr >> 6) & 0x7;
                    const offset = signExtend(instr & 0x3F, 6);
                    const addr = @addWithOverflow(self.registers[r1], offset)[0];
                    self.registers[r0] = try self.memRead(addr);
                    self.updateFlags(r0);
                },
                .LEA => {
                    const r0 = (instr >> 9) & 0x7;
                    const pc_offset = signExtend(instr & 0x1FF, 9);
                    self.registers[r0] = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    self.updateFlags(r0);
                },
                .ST => {
                    const r0 = (instr >> 9) & 0x7;
                    const pc_offset = signExtend(instr & 0x1FF, 9);
                    const addr = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    self.memWrite(addr, self.registers[r0]);
                },
                .STI => {
                    const r0 = (instr >> 9) & 0x7;
                    const pc_offset = signExtend(instr & 0x1FF, 9);
                    const addr = @addWithOverflow(self.registers[R_PC], pc_offset)[0];
                    self.memWrite(try self.memRead(addr), self.registers[r0]);
                },
                .STR => {
                    const r0 = (instr >> 9) & 0x7;
                    const r1 = (instr >> 6) & 0x7;
                    const offset = signExtend(instr & 0x3F, 6);
                    const addr = @addWithOverflow(self.registers[r1], offset)[0];
                    self.memWrite(addr, self.registers[r0]);
                },
                .NOT => {
                    const r0 = (instr >> 9) & 0x7;
                    const r1 = (instr >> 6) & 0x7;
                    self.registers[r0] = ~self.registers[r1];
                    self.updateFlags(r0);
                },
                .AND => {
                    const r0 = (instr >> 9) & 0x7;
                    const r1 = (instr >> 6) & 0x7;
                    const val = if ((instr >> 5) & 0x1 != 0) signExtend(instr & 0x1F, 5) else self.registers[instr & 0x7];
                    self.registers[r0] = self.registers[r1] & val;
                    self.updateFlags(r0);
                },
                .ADD => {
                    const r0 = (instr >> 9) & 0x7;
                    const r1 = (instr >> 6) & 0x7;
                    const val = if ((instr >> 5) & 0x1 != 0) signExtend(instr & 0x1F, 5) else self.registers[instr & 0x7];
                    self.registers[r0] = @addWithOverflow(self.registers[r1], val)[0];
                    self.updateFlags(r0);
                },
                .TRAP => {
                    self.registers[R_R7] = self.registers[R_PC];
                    switch (Trap.fromInstruction(instr)) {
                        .GETC => {
                            self.registers[R_R0] = @as(u16, try stdin.readByte());
                            self.updateFlags(R_R0);
                        },
                        .IN => {
                            try stdout.writeAll("Input character: ");
                            const c = try stdin.readByte();
                            try stdout.writeByte(c);
                            try stdout_writer.flush();
                            self.registers[R_R0] = @as(u16, c);
                            self.updateFlags(R_R0);
                        },
                        .OUT => {
                            try stdout.writeByte(@truncate(self.registers[R_R0]));
                            try stdout_writer.flush();
                        },
                        .PUTS => {
                            var addr = self.registers[R_R0];
                            var char = try self.memRead(addr);
                            while (char != 0) {
                                try stdout.writeByte(@truncate(char >> 8));
                                try stdout.writeByte(@truncate(char & 0xFF));
                                addr = @addWithOverflow(addr, 1)[0];
                                char = try self.memRead(addr);
                            }
                            try stdout_writer.flush();
                        },
                        .PUTSP => {
                            var i = self.registers[R_R0];
                            var c = self.memory[i];
                            while (c != 0) {
                                try stdout.writeByte(@truncate(c & 0xFF));
                                const c8 = @as(u8, @truncate(c >> 8));
                                if (c8 != 0) {
                                    try stdout.writeByte(c8);
                                }
                                i += 1;
                                c = self.memory[i];
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
};
