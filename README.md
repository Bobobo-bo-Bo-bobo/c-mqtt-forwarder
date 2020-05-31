
**_Note:_** Because I'm running my own servers for several years, main development is done at at https://git.ypbind.de/cgit/c-mqtt-forwarder/

----

# Preface
`c-mqtt-forwarder` connects to a list of input MQTT brokers on a defined topic and forward all messages to all output brokers
in a fan-in-fan-out fashion.

## Requirements
### Runtime requirements
Running `c-mqtt-forwarder` requires:
   * [libmosquitto](https://mosquitto.org/)
   * [CJSON](https://github.com/DaveGamble/cJSON)
   * libuuid

### Build requirements
Building `c-mqtt-forwarder` requires *development* packages of:
   * [libmosquitto](https://mosquitto.org/)
   * [CJSON ](https://github.com/DaveGamble/cJSON)
   * libuuid
   * [utlist](https://troydhanson.github.io/uthash/)

## Configuration file
The input brokers are defined in the `in` list, the output brokers are defined in the `out` list.
Broker configuration is a dict of:

| *Key* | *Type* | *Default* | *Description* | *Comment* |
|:------|:-------|:----------|:--------------|:----------|
| `ca_file` | string | - | Path to CA file containing the public key of the CA for the server certificate | Must be set to enable TLS |
| `host` | string | - | Name or address of the MQTT broker | **_mandatory_** |
| `insecure_ssl` | boolean | false | Don't verify server certificate | - |
| `keepalive` | integer | 15 | Number of seconds after which the broker should send a PING | - |
| `password` | string | - | Password to use for user/password authentication | - |
| `port` | integer | 1883 | Port of the MQTT broker | - |
| `qos` | integer | 0 | MQTT QoS for messages | - |
| `reconnect_delay` | integer | 5 | If connection to broker fails or was disconnected, number of seconds to wait until reconnecting to broker |
| `ssl_auth_public` | string | - | File containing the public key for authentication using SSL client certificates | - |
| `ssl_auth_private` | string | - | File containing the public key for authentication using SSL client certificates | Private key must be unencrypted |
| `timeout` | integer | 60 | MQTT connection timeout in seconds | - |
| `topic` | string | - | MQTT topic | **_mandatory_** |
| `user` | string | - | User to use for user/password authentication | - |

### Example
```json
{
  "in": [
    {
      "host": "mqtt-in-1.example.com",
      "port": 8883,
      "topic": "#",
      "insecure_ssl": false,
      "ca_file": "/etc/ssl/certs/ca-certificates.crt",
      "user": "mqtt-in-1-user",
      "password": "It's so fluffy I'm gonna DIE!",
      "qos": 0,
      "timeout": 60,
      "keepalive": 5,
      "reconnect_delay": 10
    },
    {
      "host": "mqtt-in-2.example.net",
      "port": 1883,
      "topic": "input/topic/no/+/data",
      "insecure_ssl": false,
      "ca_file": "/etc/ssl/certs/ca-certificates.crt",
      "ssl_auth_public": "/path/to/client/public.pem",
      "ssl_auth_private": "/path/to/client/private.key",
      "qos": 2,
      "timeout": 180
    }
  ],
  "out": [
    {
      "host": "mqtt-out-1.example.com",
      "port": 8883,
      "topic": "output/topic/1",
      "insecure_ssl": false,
      "ca_file": "/etc/ssl/certs/ca-certificates.crt",
      "user": "mqtt-out-1-user",
      "password": "SO FLUFFY!",
      "qos": 0,
      "timeout": 60,
      "keepalive": 5
    },
    {
      "host": "mqtt-out-2.example.net",
      "port": 1883,
      "topic": "secondary/output/topic/2",
      "insecure_ssl": false,
      "ca_file": "/etc/ssl/certs/ca-certificates.crt",
      "ssl_auth_public": "/path/to/client/public.pem",
      "ssl_auth_private": "/path/to/client/private.key",
      "qos": 1,
      "timeout": 180
    },
    {
      "host": "mqtt-out-3.example.com",
      "port": 1884,
      "topic": "path/to/topic",
      "insecure_ssl": true,
      "ca_file": "/etc/ssl/certs/ca-certificates.crt",
      "user": "mqtt-out-user",
      "password": "Assemble the minions!",
      "qos": 0,
      "timeout": 60,
      "keepalive": 5
    },
    {
      "host": "mqtt-out-4.example.net",
      "port": 2885,
      "topic": "topic/on/out/4",
      "insecure_ssl": false,
      "ca_file": "/etc/ssl/certs/ca-certificates.crt",
      "ssl_auth_public": "/path/to/client/public.pem",
      "ssl_auth_private": "/path/to/client/private.key",
      "qos": 1,
    }
  ]
}
```

## Command line options

| *Option* | *Description* | *Default* |
|:---------|:--------------|:----------|
| `-c <cfg>` | Read configuration from `<cfg>` | `/etc/mqtt-forwarder/config.json` |
| `--config=<cfg>` | Read configuration from `<cfg>` | `/etc/mqtt-forwarder/config.json` |
| `-h` | Show help text | - |
| `--help` | Show help text | - |
| `-q` | Quiet operation | All log messages except error and fatal messages are suppressed |
| `--quiet` | Quiet operation | All log messages except error and fatal messages are suppressed |
| `-v` | Verbose operation | Log informational, warning, error and fatal messages |
| `--verbose` | Verbose operation | Log informational, warning, error and fatal messages |

# License
## c-mqtt-forwarder
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## log.c (https://github.com/rxi/log.c)
Copyright (c) 2017 rxi

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## libyuarel (https://github.com/jacketizer/libyuarel)
The MIT License (MIT)

Copyright (C) 2016 Jack Engqvist Johansson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

