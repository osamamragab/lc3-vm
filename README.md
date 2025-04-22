# lc3-vm

> Little Computer 3 Virtual Machine

An LC-3 virtual machine implementation written in Zig.

### Running

Simply build the project and run the output binary with the desired image file.
Some example images are in the `objs` directory.

```sh
zig build
./zig-out/bin/lc3 <image_file>
```


### Resources

- [Write your Own Virtual Machine](https://www.jmeiners.com/lc3-vm/)
- [Specification](https://www.jmeiners.com/lc3-vm/supplies/lc3-isa.pdf)
