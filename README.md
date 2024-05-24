# check-cfi

A simple tool to check if a binary is compiled with Clang's control flow integrity enabled, i.e if the binary was compiled with the `-fsanitize=cfi` option. 

The tool iterates all indirect calls, i.e. `call %rax` and checks that sanitization of the call target is applied before the call. 


## Building 

- Install [Rust](https://www.rust-lang.org/tools/install)
- Build with `cargo build --release`
- The executable will be available at `/target/release/check-cfi`

## Examples

- Some example C/C++ programs are provided in `examples`. 
- Build the examples with `cd examples && make`

