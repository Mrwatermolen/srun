# srun

SRun authentication login

## Usage

`username`, `password` and `host` are used to login

```bash
srun --username 123456 --password 7890 --host host
```

Use `--help` to get more information

---

`config.json` file is used to login

```bash
srun --config <path to config.json>
```

### Config file

Json format

Required fields:
- `username` the username of the account. `string`
- `password` the password of the account. `string`
- `host` the host of the server. `string`
- `port` the port of the server. `int`

Optional fields:
- `protocol` the protocol of the server. Type is `string` ("http" or "https") (default: "http")
- `ip` the client ip address. Type is `string` (default: "") (emptying this field to automatically obtain the ip address)
- `ac_id`. Type is `int` (default: 1)
- `os` the operating system of the client. Type is `string` (default: "Linux")
- `os_name` the name of the operating system. Type is `string` (default: "Linux")

Example:

```json
{
  "username": "123456",
  "password": "7890",
  "host": "host",
  "port": 443,
  "protocol": "https"
}
```

## Build

### Dependencies

- [ASIO](https://think-async.com/Asio/) (without boost)
- [Nlohmann JSON](https://github.com/nlohmann/json)
- Optional: [OpenSSL](https://www.openssl.org/)  (for https)

### Build with CMake

```bash
cmake -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build
```

the executable will be in `build/bin` directory

### Support for HTTPS

This feature is disabled by default.

If you need to support https, you need to install OpenSSL on your system. Then use the following command to enable support for https.

```cmake
cmake -DSRUN_SSL_ENABLED=ON -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build
``` 

## Acknowledgements

- [srun](https://github.com/zu1k/srun)
- [校园网登陆逆向 writeUP](https://ucaskernel.com/d/840-writeup)
