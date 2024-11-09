# srun

SRun authentication login

## Build

prerequisites:
- C++20
- [OpenSSL](https://www.openssl.org/)
- [ASIO](https://think-async.com/Asio/)
- [Nlohmann JSON](https://github.com/nlohmann/json)

```bash
cmake -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build
```

executable will be in `build/bin/srun`

## Usage

create a `config.json` file in the working directory with the following content
  
```json
{
  "protocol": "https",
  "host": "host",
  "port": 443,
  "username": "123456",
  "password": "7890"
}
```

optional fields:
- `ip` the ip address of the host. Type is `string` (default: "")
- `ac_id`. Type is `int` (default: 1)


run the executable

```bash
./srun
```
## Acknowledgements

- [srun](https://github.com/zu1k/srun)
- [校园网登陆逆向 writeUP](https://ucaskernel.com/d/840-writeup)
