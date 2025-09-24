# Poke Plugin

## Prerequisites

Debian 13 Trixie:
```
sudo apt install libpoke-dev qt6-base-dev libxkb-dev qt5-qmake ninja-build
```

## Build

First copy `api_REVISION.txt` from the binaryninja installation directory.
Next run `add_dependencies` to install the binary ninja API.
Then run:
```
mkdir build
cd build
cmake -G Ninja ..
ninja
```
