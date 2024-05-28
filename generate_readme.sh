#!/bin/bash

sed -n '/^\/\*!/,/\*\//p' src/rc5.rs > README.md
sed -i '1d;$d' README.md
