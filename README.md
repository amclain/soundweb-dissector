# BSS Soundweb London Protocol Wireshark Dissector

## Screenshot
![BSS Soundweb London Protocol Wireshark Dissector Screenshot](screenshot.png)


## Installation

This plugin was tested with Wireshark `1.12.1`.

Copy `soundweb-dissector.lua` to `%APPDATA%\Wireshark\plugins` on Windows, or
`~/.wireshark/plugins` on Linux. For development, clone this repository to the
plugins directory. See the Wireshark [Configuration Files and Folders](https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html)
documentation for more information.


### Coloring Rules

Adding the following [coloring rule](https://www.wireshark.org/docs/wsug_html_chunked/ChCustColorizationSection.html)
to Wireshark will highlight Soundweb packets with errors.

`View -> Coloring Rules... -> New`

    Name: Soundweb Error
    String: soundweb.error==true
    Foreground Color: #FFFFFF
    Background Color: #A40000


## Issues, Bugs, Feature Requests

Any bugs and feature requests should be reported on the GitHub issue tracker:

https://github.com/amclain/soundweb-dissector/issues


**Pull requests are preferred via GitHub.**

Mercurial users can use [Hg-Git](http://hg-git.github.io/) to interact with
GitHub repositories.
