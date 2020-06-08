# Registry Callbacks

## Introduction

This was my first attempt writing kernel code and communicating with the kernel, trying to hide it from BattlEye.

The communication method lets you manual map the driver because it registers the callback in a legit module.

Old code, badly written, should only be used for reference.

## Credits

[yousif](https://github.com/haram) - showing the `jmp ecx` trick