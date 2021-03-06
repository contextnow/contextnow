# ConTExT-now

## Installation

### Prerequiesits

On a Debian-based system, you need to install the following packages:

  * linux-headers
  * build-essential
  * clang

### Kernel Module

In order to build the kernel module, run the following command in the `module` directory:

    $ make

To load the module, run as root:

    # insmod pteditor.ko

To unload the module after usage, run as root:

    # rmmod pteditor

## Example

In order to test ConTExT-now, build the provided example in the `example` directory:

    $ make

The Makefile will build two executables: `example` and `example_secured`, both implementing a Spectre V1 attack.
While the `example` file is unprotected, `example_secured` utilizes the ConTExT-now protection to protect its `data` area with the `nospec` attribute.

To run the example, just execute it:

    $ ./example

The expected output is
```
[*] Flush+Reload Threshold: 180
[ ]  SECRET 

[>] Done
```

If you run `example_secured`, the value `SECRET` cannot be recovered.

