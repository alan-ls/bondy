%% =============================================================================
%%  bondy_connection.erl -
%%
%%  Copyright (c) 2016-2021 Leapsight. All rights reserved.
%%
%%  Licensed under the Apache License, Version 2.0 (the "License");
%%  you may not use this file except in compliance with the License.
%%  You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%%  Unless required by applicable law or agreed to in writing, software
%%  distributed under the License is distributed on an "AS IS" BASIS,
%%  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%  See the License for the specific language governing permissions and
%%  limitations under the License.
%% =============================================================================

%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-module(bondy_connection).
-include_lib("wamp/include/wamp.hrl").
-include_lib("bondy.hrl").

-define(OPTS_VALIDATOR, #{
    transport => #{
        required => false,
        datatype => {in, [ranch_tcp, ranch_ssl]}
    },
    socket => #{
        required => false
    },
    encoding => #{
        required => false,
        datatype => {in, ?WAMP_ENCODINGS}
    },
    max_length => #{
        required => false,
        datatype => pos_integer
    },
    peername => #{
        required => true,
        validator => fun bondy_data_validators:peername/1
    },
    real_peername => #{
        required => false,
        validator => fun bondy_data_validators:peername/1
    }
}).

-record(bondy_connection, {
    pid                     ::  pid(),
    node                    ::  atom(),
    handler                 ::  module(),
    %% Protocol opts
    encoding                ::  maybe(encoding()),
    max_length              ::  maybe(non_neg_integer()),
    %% Transport/Socket
    transport               ::  maybe(ranch_transport()),
    socket                  ::  maybe(socket()),
    peername                ::  maybe(peername()),
    real_peername           ::  maybe(peername())
}).


-opaque t()                 ::  #bondy_connection{}.
-type ranch_transport()     ::  ranch_tcp | ranch_ssl.
-type opts()                ::  #{
    transport               =>  ranch_transport(),
    socket                  =>  socket(),
    encoding                =>  encoding(),
    max_length              =>  non_neg_integer(),
    peername                =>  peername(),
    real_peername           =>  peername()
}.
-type send_error_reason()   ::  busy
                                | badarg
                                | noproc
                                | nosocket
                                | message_too_big
                                | timeout
                                | unsupported_encoding.

-export_type([t/0]).
-export_type([opts/0]).
-export_type([socket/0]).
-export_type([transport/0]).

-export([async_send/2]).
-export([async_send/3]).
-export([encoding/1]).
-export([handler/1]).
-export([ip_address/1]).
-export([is_type/1]).
-export([max_length/1]).
-export([new/3]).
-export([node/1]).
-export([peername/1]).
-export([peername_bin/1]).
-export([pid/1]).
-export([real_ip_address/1]).
-export([real_peername/1]).
-export([real_peername_bin/1]).
-export([send/2]).
-export([send/3]).
-export([socket/1]).
-export([transport/1]).

%% =============================================================================
%% API
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc Returns a new local connection information object.
%% @end
%% -----------------------------------------------------------------------------
-spec new(Handler :: module(), Owner :: pid(), Opts :: map()) ->
    t() | no_return().

new(Handler, Pid, Opts0) when is_atom(Handler) andalso is_pid(Pid) ->
    Opts = maps_utils:validate(Opts0, ?OPTS_VALIDATOR),
    Node = bondy_peer_service:mynode(),
    Node =:= erlang:node(Pid) orelse error(badarg),

    T = #bondy_connection{
        handler = Handler,
        pid = Pid,
        node = Node
    },
    set_opts(Opts, T).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec is_type(any()) -> boolean().

is_type(#bondy_connection{}) -> true;
is_type(_) -> false.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec handler(t()) -> module().

handler(#bondy_connection{handler = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec pid(t()) -> pid().

pid(#bondy_connection{pid = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec node(t()) -> atom().

node(#bondy_connection{node = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec transport(t()) -> maybe(ranch_transport()).

transport(#bondy_connection{transport = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec socket(t()) -> maybe(socket()).

socket(#bondy_connection{socket = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec encoding(t()) -> maybe(encoding()).

encoding(#bondy_connection{encoding = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec max_length(t()) -> maybe(non_neg_integer()).

max_length(#bondy_connection{max_length = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec peername(t()) -> maybe(peername()).

peername(#bondy_connection{peername = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec peername_bin(t()) -> maybe(binary()).

peername_bin(#bondy_connection{peername = undefined}) ->
    undefined;

peername_bin(#bondy_connection{peername = Val}) ->
    inet_utils:peername_to_binary(Val).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec ip_address(t()) -> maybe(inet:ip_address()).

ip_address(#bondy_connection{peername = undefined}) ->
    undefined;

ip_address(#bondy_connection{peername = {Val, _}}) ->
    Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec real_peername(t()) -> maybe(peername()).

real_peername(#bondy_connection{real_peername = Val}) ->
    Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec real_peername_bin(t()) -> maybe(binary()).

real_peername_bin(#bondy_connection{real_peername = undefined}) ->
    undefined;

real_peername_bin(#bondy_connection{real_peername = Val}) ->
    inet_utils:peername_to_binary(Val).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec real_ip_address(t()) -> maybe(inet:ip_address()).

real_ip_address(#bondy_connection{real_peername = undefined}) ->
    undefined;

real_ip_address(#bondy_connection{real_peername = {Val, _}}) ->
    Val.


%% -----------------------------------------------------------------------------
%% @doc Sends the message to the handler process (connection owner).
%% @end
%% -----------------------------------------------------------------------------
-spec send(Conn :: t(), Msg :: wamp_message()) ->
    ok | {error, send_error_reason()}.

send(Conn, Msg) ->
    send(Conn, Msg, ?SEND_TIMEOUT).


%% -----------------------------------------------------------------------------
%% @doc Sends the message to the handler process (connection owner).
%% @end
%% -----------------------------------------------------------------------------
-spec send(Conn :: t(), Msg :: wamp_message(), Timeout :: integer()) ->
    ok | {error, send_error_reason()}.

send(#bondy_connection{pid = Pid}, Msg, _) when Pid =:= self() ->
    wamp_message:is_message(Msg) orelse error(invalid_wamp_message),

    Pid ! {?BONDY_PEER_REQUEST, Pid, make_ref(), Msg},
    %% This is a sync message, we resolve this sequentially
    %% so we will not get an ack i.e. the ack is implicit
    ok;

send(#bondy_connection{pid = Pid}, Msg, Timeout) when is_pid(Pid) ->
    wamp_message:is_message(Msg) orelse error(invalid_wamp_message),

    Ref = monitor(process, Pid),

    %% The following comment no longer applies, as the process is local.
    %% However, we keep it as it still is the right thing to do.
    %% ---------------------------------------------------------
    %% If the monitor/2 call failed to set up a connection to a
    %% remote node, we don't want the '!' operator to attempt
    %% to set up the connection again. (If the monitor/2 call
    %% failed due to an expired timeout, '!' too would probably
    %% have to wait for the timeout to expire.) Therefore,
    %% use erlang:send/3 with the 'noconnect' option so that it
    %% will fail immediately if there is no connection to the
    %% remote node.
    %% ---------------------------------------------------------
    erlang:send(
        Pid,
        {?BONDY_PEER_REQUEST, self(), Ref, Msg},
        [noconnect]
    ),

    receive
        {'DOWN', Ref, process, Pid, _Reason} ->
            %% The handler no longer exists
            {error, noproc};

        {?BONDY_PEER_ACK, Ref} ->
            %% The handler received the message and acked it using bondy:ack/2
            true = demonitor(Ref, [flush]),
            ok
    after
        Timeout ->
            true = demonitor(Ref, [flush]),
            {error, timeout}
    end.


%% -----------------------------------------------------------------------------
%% @doc Sends the message to the connection socket directly i.e. bypassing the
%% connection handler process.
%% @end
%% -----------------------------------------------------------------------------
-spec async_send(Conn :: t(), Msg :: wamp_message()) ->
    ok | {error, send_error_reason()}.

async_send(Conn, Msg) ->
    async_send(Conn, Msg, ?SEND_TIMEOUT).


%% -----------------------------------------------------------------------------
%% @doc Sends the message to the connection socket directly i.e. bypassing the
%% connection handler process.
%% @end
%% -----------------------------------------------------------------------------
-spec async_send(
    Conn :: t(), Msg :: wamp_message(), Timeout :: non_neg_integer()) ->
    ok | {error, send_error_reason()}.

async_send(#bondy_connection{socket = undefined}, _, _) ->
    %% This connection does not provide access to the socker e.g. Websockets
    %% are implemented using Cowboy.
    {error, nosocket};

async_send(#bondy_connection{} = Conn, Msg, Opts) ->
    wamp_message:is_message(Msg) orelse error(invalid_wamp_message),

    Handler = Conn#bondy_connection.handler,

    try
        Data = Handler:to_frame(
            wamp_encoding:encode(Msg, Conn#bondy_connection.encoding),
            #{max_length => Conn#bondy_connection.max_length}
        ),

        %% Send can fail with {error, busy | badarg | message_too_big}
        Handler:send(
            Conn#bondy_connection.transport,
            Conn#bondy_connection.socket,
            Data,
            Opts
        )

    catch
        error:{unsupported_encoding, _} ->
            {error, unsupported_encoding};
        error:message_too_big ->
            {error, message_too_big}
    end.





%% =============================================================================
%% PRIVATE
%% =============================================================================


set_opts(Opts, Conn0) ->
    Conn = set_socket(Opts, Conn0),
    Conn#bondy_connection{
        encoding = maps:get(encoding, Opts, undefined),
        max_length = maps:get(max_length, Opts, undefined),
        peername = maps:get(peername, Opts, undefined),
        real_peername = maps:get(real_peername, Opts, undefined)
    }.


set_socket(#{socket := Socket, transport := Mod}, Conn) ->
    Conn#bondy_connection{
        socket = Socket,
        transport = Mod
    };

set_socket(#{socket := _}, _) ->
    error({missing_option, transport});

set_socket(#{transport := _}, _) ->
    error({missing_option, socket}).

