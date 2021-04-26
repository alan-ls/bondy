# Bondy
#### The Distributed WAMP Router and API Gateway

Bondy is an open source, distributed, scaleable and robust networking platform for microservices and IoT applications written in Erlang. It implements the open Web Application Messaging Protocol (WAMP) offering both Publish and Subscribe (PubSub) and routed Remote Procedure Calls (RPC) comunication patterns.

Bondy is Apache2 licensed.

|:warning: **Notice for Contributors**|
|:---|
|Active development is done at Bondy's Gitlab repository (https://gitlab.com/leapsight/bondy). <br><br>If you are reading this file at Bondy's Github repository, notice this is a mirror that is unidirectionally synced to Gitlab's i.e. _no commits or PRs done in Github will be synced to the main Gitlab repository_.|

## Documentation

For our work-in-progress documentation go to [http://docs.getbondy.io](http://docs.getbondy.io).

## Quick Start

### Requirements

* [Erlang](https://www.erlang.org/) 23.3.1 or later
* [Rebar3](https://rebar3.readme.io/)
* [Libsodium](https://github.com/jedisct1/libsodium)


### Run a first node

We will start a node named `bondy1@127.0.0.1` which uses the following variables from the config file (`config/test/node_1_vars.config`).

|Transport|Description|Port|
|---|---|---|
|HTTP|REST API GATEWAY|18080|
|HTTP|REST API GATEWAY|18083|
|HTTP|REST Admin API|18081|
|HTTPS|REST Admin API|18084|
|Websockets|WAMP|18080|
|TCP|WAMP Raw Socket|18082|
|TLS|WAMP Raw Socket|18085|


```bash
make node1
```

#### Create a Realm

WAMP is a session-based protocol. Each session belongs to a Realm.

```curl
curl -X "POST" "http://localhost:18081/realms/" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -H 'Accept: application/json; charset=utf-8' \
     -d $'{
  "uri": "com.myrealm",
  "description": "My First Realm"
}'
```

#### Disable Security

We will disable security to avoid setting up credentials at this moment.

```curl
curl -X "DELETE" "http://localhost:18081/realms/com.myrealm/security_enabled" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -H 'Accept: application/json; charset=utf-8'
```

#### Run a second node

We start a second node named `bondy2@127.0.0.1` which uses the following variables from the config file (`config/test/node_2_vars.config`).

|Transport|Description|Port|
|:---|:---|:---|
|HTTP|REST API GATEWAY|18180|
|HTTP|REST API GATEWAY|18183|
|HTTP|REST Admin API|18181|
|HTTPS|REST Admin API|18184|
|Websockets|WAMP|18180|
|TCP|WAMP Raw Socket|18182|
|TLS|WAMP Raw Socket|18185|

```bash
make node2
```

#### Connect the two nodes

In `bondy1@127.0.0.1` erlang's shell type:

```erlang
(bondy2@127.0.0.1)1> bondy_peer_service:join('bondy2@127.0.0.1').
```

All new state changes will be propagated in real-time through gossip.
One minute after joining the cluster, the Active Anti-entropy service will trigger an exchange after which the Realm we have created in `bondy1@127.0.0.1` will have been replicated to `bondy2@127.0.0.1`.

## Resources

* [http://docs.getbondy.io](http://docs.getbondy.io).
* [WAMP Specification](wamp-proto.org)
* #bondy on slack (coming soon!)
* [Follow us on twitter @leapsight](https://twitter.com/leapsight)
* Recorded webinars
     * [Implementing a polyglot microservices architecture](https://www.youtube.com/watch?v=XxJ1IS8mo84)<br>Date: 10 July 2019

---

Copyright (c) 2016-2021 Leapsight. All rights reserved.