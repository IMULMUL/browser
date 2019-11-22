## blaze fox

`blazefox` is from [Blaze CTF 2018](https://ctftime.org/task/6000). I read [doare-team's blog](https://doar-e.github.io/blog/2018/11/19/introduction-to-spidermonkey-exploitation/).

-   [my personal write-up(Chinese)](https://redogwu.github.io/)
-   blazefox
    -   exp-tools
        -   Written by [saelo](https://twitter.com/5aelo). It is in order to represent 64-bit integers (that we cannot represent today with JavaScript native integers) and have utility functions to convert a double to an Int64 or vice-versa. 
    -   js-asserts
        -   Ugly version. Exploit code for debug js shell. The code is toooooo ugly. But it can work.
        -   js-code
            -   [exp.js](js-assert\js-code\exp.js)
                -   exploit code.
            -   [mem_lay.js](js-assert\js-code\mem_lay.js)
                -   To dump the memory layout.
            -   [sg.js](js-assert\js-code\sg.js)
                -   To observe the shape and group of a object.
    -   js-release
        -   Ugly version. Exploit code for release js shell. The code is toooooo ugly. But it can work.
        -   js-code
            -   [poc.js](js-release\js-code\poc.js)
                -   exploit code. But it is archived with hardcoded offsets.
            -   [exp.js](js-release\js-code\exp.js)
                -   exploit code. Use pe_leak.js's function to find the offset dynamicly.
            -   [pe_leak.js](js-release\js-code\pe_leak.js)
                -   Some `PE` function like that we could to find `IAT` table... It is ugly, but it can work. Avoid with hardware offset.