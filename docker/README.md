## Build and run the binwalk container

```
docker build --file binwalk.docker --tag binwalk .
docker run --rm --mount type=bind,src=$PWD/,dst=/workspace binwalk --extract --matryoshka file.bin
```

## Build and run Unblob

```
docker pull ghcr.io/onekey-sec/unblob:latest
docker run --rm --user $UID:$GID --volume $PWD/:/data/output --volume $PWD/:/data/input ghcr.io/onekey-sec/unblob:latest /data/input/file.bin
```
