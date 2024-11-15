# srun

SRun authentication login

## Usage

Basic usage:

run with options

```bash
srun_cli --action <action> <some options>
```

or run with config file

```bash
srun_cli --action <action> --config <path to config.json>
```

### Action

* Login

  run with `--action 0` to login.

  `username`, `password` and `host` are required fields.

  ```bash
  srun_cli --action 0 --username 123456 --password 7890 --host host
  ```

  or run witch config file

  ```bash
  srun_cli --action 0 --config <path to config.json>
  ```

* Logout

  run with `--action 1` to logout.

  `host` is required field.

  ```bash
  srun_cli --action 1 --host host
  ```

* Info
  
    run with `--action 2` to get user information.
  
    `host` is required field.
  
    ```bash
    srun_cli --action 2 --host host
    ```

Use `--help` to get more information

### Config file

Json format

Required fields:
- `host` the host of the server. `string`

Optional fields:
- `username` the username of the account. `string`. required when action is login
- `password` the password of the account. `string`. required when action is login
- `port` the port of the server. `int`
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

### Build options

`SRUN_SSL_ENABLED` - enable support for https (default: OFF)

`SRUN_ENABLED_INSTALL_LIB` - enable install lib (default: OFF)

`SRUN_ENABLED_INSTALL_BIN` - enable install bin (default: ON)

## Acknowledgements

- [srun](https://github.com/zu1k/srun)
- [校园网登陆逆向 writeUP](https://ucaskernel.com/d/840-writeup)
