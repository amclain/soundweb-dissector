# BSS Soundweb London Protocol Wireshark Dissector

## Screenshot
![BSS Soundweb London Protocol Wireshark Dissector Screenshot](screenshot.png)

## Installation

Navigate to `C:\Program Files\Wireshark` on Windows, or `~/.wireshark` on Linux.

Copy `soundweb-dissector.lua` to this directory.

Add the following code to the end of `init.lua` in this directory:

``` lua
dofile("soundweb-dissector.lua")
```

## Issues, Bugs, Feature Requests

Any bugs and feature requests should be reported on the GitHub issue tracker:

https://github.com/amclain/soundweb-dissector/issues


**Pull requests are preferred via GitHub.**

Mercurial users can use [Hg-Git](http://hg-git.github.io/) to interact with
GitHub repositories.
