%% =============================================================================
%% juno_app - 
%%
%% Copyright (c) 2016-2017 Ngineo Limited t/a Leapsight. All rights reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%    http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%% =============================================================================
-module(juno_app).
-behaviour(application).
-include("juno.hrl").
-include_lib("wamp/include/wamp.hrl").

-define(JUNO_REALM, #{
    <<"description">> => <<"The Juno administrative realm.">>,
    <<"authmethods">> => [?WAMPCRA_AUTH, ?TICKET_AUTH]
}).


-export([start/2]).
-export([stop/1]).

start(_Type, _Args) ->
    case juno_sup:start_link() of
        {ok, Pid} ->
            ok = juno_router:start_pool(),
            ok = juno_stats:start_pool(),
            ok = juno_stats:create_metrics(),
            ok = maybe_init_juno_realm(),
            ok = maybe_start_router_services(),
            qdate:register_parser(iso8601, date_parser()),
            {ok, Pid};
        Other  ->
            Other
    end.


stop(_State) ->
    ok.



%% =============================================================================
%% PRIVATE
%% =============================================================================


%% @private
maybe_init_juno_realm() ->
    %% TODO Check what happens when we join the cluster and juno realm was
    %% already defined in my peers...we should not use LWW here.
    _ = juno_realm:get(?JUNO_REALM_URI, ?JUNO_REALM),
    ok.


%% @private
maybe_start_router_services() ->
    case juno_config:is_router() of
        true ->
            ok = start_tcp_handlers(),
            % {ok, _} = juno_rest_admin_api:start_admin_http(),
            juno_rest_api_gateway:start_listeners();
        false ->
            ok
    end.


%% @private
-spec start_tcp_handlers() -> ok.
start_tcp_handlers() ->
    ServiceName = juno_wamp_tcp_listener,
    PoolSize = juno_config:tcp_acceptors_pool_size(),
    Port = juno_config:tcp_port(),
    MaxConnections = juno_config:tcp_max_connections(),
    {ok, _} = ranch:start_listener(
        ServiceName,
        PoolSize,
        ranch_tcp,
        [{port, Port}],
        juno_wamp_raw_handler, []),
    ranch:set_max_connections(ServiceName, MaxConnections),
    ok.

%% A custom qdate parser for the ISO8601 dates where timezone == Z.
date_parser() ->
    fun
        (RawDate) when length(RawDate) == 20 ->
            try 
                re:run(RawDate,"^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})Z",[{capture,all_but_first,list}]) 
            of
                nomatch -> undefined;
                {match, [Y,M,D,H,I,S]} ->
                    Date = {list_to_integer(Y), list_to_integer(M), list_to_integer(D)},
                    Time = {list_to_integer(H), list_to_integer(I), list_to_integer(S)},
                    case calendar:valid_date(Date) of
                        true -> 
                            {{Date, Time}, "UTC"};
                        false -> 
                            undefined
                    end
            catch 
                _:_ -> 
                    undefined
            end;
        (_) -> 
            undefined
    end.