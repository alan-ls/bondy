%% =============================================================================
%%  bondy_wamp_tcp_connection_handler.erl -
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
%% A ranch handler for the wamp protocol over either tcp or tls transports.
%% @end
%% -----------------------------------------------------------------------------
-module(bondy_wamp_tcp_connection_handler).
-behaviour(gen_server).
-behaviour(ranch_protocol).
-behaviour(bondy_connection_handler).
-include("bondy.hrl").
-include_lib("wamp/include/wamp.hrl").


-define(TIMEOUT, ?PING_TIMEOUT * 2).
-define(PING_TIMEOUT, 10000). % 10 secs
%% 2^24 bytes, according to
%% https://wamp-proto.org/_static/gen/wamp_latest_ietf.html#handshake
-define(MAX_FRAME_LEN, 16777216).

-record(state, {
    %% Immutable state
    transport               ::  module(),  %% ranch_tcp | ranch_ssl
    socket                  ::  socket(),
    peername                ::  peername(),
    real_peername           ::  maybe(peername()),
    log_meta = #{}          ::  map(),
    encoding                ::  atom(),
    max_length              ::  pos_integer(),
    start_time              ::  integer(),
    %% Mutable state
    active_n = once         ::  once | -32768..32767,
    hibernate = false       ::  boolean(),
    ping_sent = false       ::  {true, binary(), reference()} | false,
    ping_attempts = 0       ::  non_neg_integer(),
    ping_max_attempts = 2   ::  non_neg_integer(),
    shutdown_reason         ::  maybe(term()),
    session                 ::  maybe(bondy_session:t()),
    buffer = <<>>           ::  binary()
}).
-type state() :: #state{}.


-export([start_link/4]).
-export([to_frame/2]).
-export([send/3]).
-export([send/4]).

-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).




%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
start_link(Ref, Socket, Transport, Opts) ->
    {ok, proc_lib:spawn_link(?MODULE, init, [{Ref, Socket, Transport, Opts}])}.



%% =============================================================================
%% BONDY_CONNECTION_HANDLER CALLBACKS
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc Send data directly to a socket.
%% @end
%% -----------------------------------------------------------------------------
-spec to_frame(Data :: iodata(), Opts :: map()) ->
    iodata() | no_return().

to_frame(Data, Opts) ->
    try
        MaxLen = maps:get(max_length, Opts, ?MAX_FRAME_LEN),
        maybe_too_big(?RAW_FRAME(Data), MaxLen)
    catch
        throw:Reason ->
            error(Reason)
    end.


%% -----------------------------------------------------------------------------
%% @doc Send data directly to a socket.
%% @end
%% -----------------------------------------------------------------------------
%% -----------------------------------------------------------------------------
-spec send(
    Transport :: bondy_connection:ranch_transport(),
    Socket :: socket(),
    Data :: iodata()) ->
    ok | {error, busy | badarg | message_too_big}.


send(Transport, Socket, Data) ->
    send(Transport, Socket, Data, []).


%% -----------------------------------------------------------------------------
%% @doc Send data directly to a socket.
%% The following is lifted from
%% https://github.com/erlang/otp/blob/master/erts/preloaded/src/prim_inet.erl
%%
%% We do this to avoid the selective receive in send/3 as it can take a while
%% when the inbox has many messages.
%% TODO not sure how this will work with the new Socket API.
%% @end
%% -----------------------------------------------------------------------------
-spec send(
    Transport :: bondy_connection:ranch_transport(),
    Socket :: socket(),
    Data :: iodata(),
    Opts :: [nosuspend | force]) ->
    ok | {error, busy | badarg | notsup}.

send(Transport, Socket, Data, Opts)
when (Transport == ranch_tcp orelse Transport == ranch_ssl)
andalso is_port(Socket) ->
    %% Sends data to a port. Same as Port ! {PortOwner, {command, Data}} except
    %% for the error behavior and being synchronous (see below). Any process
    %% can send data to a port with port_command/2, not only the port owner
    %% (the connected process).

    %% If the port is busy, the calling process is suspended until the port is
    %% not busy any more, unless the option nosuspend is passed.
    try erlang:port_command(Socket, Data, Opts) of
        false ->
            %% Port busy and nosuspend option passed
            %% The calling process is not suspended,
            %% the port command was aborted
            {error, busy};
        true ->
            %% Here is where the original code does a selective receive
            %% to find the message {inet_reply, Socket, State} as we do not to
            %% the receive here, we will get it through gen_server's
            %% handle_info callback
            ok
    catch
        error:badarg ->
            {error, badarg};
	    error:Reason ->
	        {error, Reason}
    end;

send(Transport, Socket, Data, _Opts) ->
    Transport:send(Socket, Data).



%% =============================================================================
%% GEN SERVER CALLBACKS
%% =============================================================================



init({Ref, Socket, RanchTransport, _Opts0}) ->
    try

        {ok, Socket, Info} = ranch_handshake(Ref, RanchTransport),

        Peername = peername(Socket),
        RealPeername = real_peername(Info),

        State0 = #state{
            start_time = erlang:monotonic_time(second),
            transport = RanchTransport,
            socket = Socket,
            peername = Peername,
            real_peername = RealPeername
        },
        State1 = State0#state{log_meta = log_meta(State0)},

        ok = socket_opened(State1),

        gen_server:enter_loop(?MODULE, [], State1, ?TIMEOUT)

    catch
        throw:Reason ->
            {stop, Reason}
    end.


handle_call(Msg, From, State) ->
    _ = lager:info("Received unknown call; message=~p, from=~p", [Msg, From]),
    {noreply, State, ?TIMEOUT}.


handle_cast(Msg, State) ->
    _ = lager:info("Received unknown cast; message=~p", [Msg]),
    {noreply, State, ?TIMEOUT}.


handle_info({inet_reply, _, ok}, State) ->
    %% see send/4 below
    {noreply, State, ?TIMEOUT};

handle_info({inet_reply, _, Status}, State) ->
    %% see send/4 below
    {stop, {send_failed, Status}, State};

handle_info(
    {tcp, Socket, <<?RAW_MAGIC:8, MaxLen:4, Encoding:4, _:16>>},
    #state{socket = Socket, session = undefined} = St0) ->
    case handle_handshake(MaxLen, Encoding, St0) of
        {ok, St1} ->
            case maybe_active_once(St1) of
                ok ->
                    {noreply, St1, ?TIMEOUT};
                {error, Reason} ->
                    {stop, Reason, St1}
            end;
        {stop, Reason, St1} ->
            {stop, Reason, St1}
    end;

handle_info(
    {tcp, Socket, Data},
    #state{socket = Socket, session = undefined} = St) ->
    %% RFC: After a _Client_ has connected to a _Router_, the _Router_ will
    %% first receive the 4 octets handshake request from the _Client_.
    %% If the _first octet_ differs from "0x7F", it is not a WAMP-over-
    %% RawSocket request. Unless the _Router_ also supports other
    %% transports on the connecting port (such as WebSocket), the
    %% _Router_ MUST *fail the connection*.
    _ = lager:error(
        "Received data before WAMP protocol handshake, reason=invalid_handshake, transport=~p, peername=~p, encoding=~p, data=~p",
        [St#state.transport, St#state.peername, St#state.encoding, Data]
    ),
    {stop, invalid_handshake, St};

handle_info({tcp, Socket, Data}, #state{socket = Socket} = St0) ->
    %% We append the newly received data to the existing buffer
    Buffer = St0#state.buffer,
    St1 = St0#state{buffer = <<>>},

    case handle_data(<<Buffer/binary, Data/binary>>, St1) of
        {ok, St2} ->
            case maybe_active_once(St1) of
                ok ->
                    {noreply, St2, ?TIMEOUT};
                {error, Reason} ->
                    {stop, Reason, St2}
            end;
        {stop, Reason, St2} ->
            {stop, Reason, St2}
    end;

handle_info({tcp_passive, Socket}, #state{socket = Socket} = St) ->
    %% We are using {active, N} and we consumed N messages from the socket
    ok = reset_inet_opts(St),
    {noreply, St, ?TIMEOUT};

handle_info({tcp_closed, _Socket}, State) ->
    {stop, normal, State};

handle_info({tcp_error, _, _} = Reason, State) ->
    {stop, Reason, State};

handle_info({?BONDY_PEER_REQUEST, Pid, M}, St) when Pid =:= self() ->
    %% Here we receive a message from the bondy_router in those cases
    %% in which the router is embodied by our process i.e. the sync part
    %% of a routing process e.g. wamp calls, so we do not ack
    %% TODO check if we still need this now that bondy:ack seems to handle this
    %% case
    handle_outbound(M, St);

handle_info({?BONDY_PEER_REQUEST, Pid, Ref, M}, St) ->
    %% Here we receive the messages that either the router or another peer
    %% have sent to us using bondy:send/2,3 which requires us to ack
    ok = bondy:ack(Pid, Ref),
    %% We send the message to the peer
    handle_outbound(M, St);


handle_info(timeout, #state{ping_sent = false} = State0) ->
    _ = log(debug, "Connection timeout, sending first ping;", [], State0),
    {ok, State1} = send_ping(State0),
    %% Here we do not return a timeout value as send_ping set an ah-hoc timet
    {noreply, State1};

handle_info(
    ping_timeout,
    #state{ping_sent = Val, ping_attempts = N, ping_max_attempts = N} = State) when Val =/= false ->
    _ = log(
        error, "Connection closing; reason=ping_timeout, attempts=~p,", [N],
        State
    ),
    {stop, ping_timeout, State#state{ping_sent = false}};

handle_info(ping_timeout, #state{ping_sent = {_, Bin, _}} = State) ->
    %% We try again until we reach ping_max_attempts
    _ = log(debug, "Ping timeout, sending another ping;", [], State),
    %% We reuse the same payload, in case the client responds the previous one
    {ok, State1} = send_ping(Bin, State),
    %% Here we do not return a timeout value as send_ping set an ah-hoc timer
    {noreply, State1};

handle_info({stop, Reason}, State) ->
    {stop, Reason, State};

handle_info(Info, State) ->
    _ = lager:error("Received unknown info; message='~p'", [Info]),
    {noreply, State}.



terminate(Reason, #state{transport = T, socket = S} = State)
when T =/= undefined andalso S =/= undefined ->
    ok = close_socket(Reason, State),
    terminate(Reason, State#state{transport = undefined, socket = undefined});

terminate(Reason, #state{session = P} = State) when P =/= undefined ->
    ok = bondy_wamp_fsm:terminate(P),
    terminate(Reason, State#state{session = undefined});

terminate(_, _) ->
    ok.


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.



%% =============================================================================
%% PRIVATE
%% =============================================================================



-spec ranch_handshake(atom(), module()) ->
    {ok, Socket :: port(), Info :: map()}.

ranch_handshake(Ref, RanchTransport) ->
    %% We must call ranch:accept_ack/1 before doing any socket operation.
    %% This will ensure the connection process is the owner of the socket.
    %% It expects the listener’s name as argument.
    % ok = ranch:accept_ack(Ref),

    Info = case bondy_config:get([Ref, proxy_protocol], false) of
        true ->
            {ok, ProxyInfo} = maybe_throw(ranch:recv_proxy_header(Ref, 1000)),
            ProxyInfo;
        false ->
            #{}
    end,

    Opts = bondy_config:get([Ref, socket_opts], []),

    SocketOpts = [{active, once}, {packet, 0} | Opts],

    {ok, Socket} = ranch:handshake(Ref, SocketOpts),
    ok = maybe_throw(RanchTransport:setopts(Socket, SocketOpts)),

    {ok, Socket, Info}.


%% @private
maybe_throw({error, Reason}) ->
    throw(Reason);

maybe_throw(Term) ->
    Term.



%% @private
-spec handle_data(Data :: binary(), State :: state()) ->
    {ok, state()} | {stop, raw_error(), state()}.

handle_data(
    <<0:5, _:3, Len:24, _Data/binary>>,
    #state{max_length = MaxLen} = St) when Len > MaxLen ->
    %% RFC: During the connection, Router MUST NOT send messages to the Client
    %% longer than the LENGTH requested by the Client, and the Client MUST NOT
    %% send messages larger than the maximum requested by the Router in it's
    %% handshake reply.
    %% If a message received during a connection exceeds the limit requested,
    %% a Peer MUST fail the connection.
    _ = log(
        error,
        "Client committed a WAMP protocol violation; "
        "reason=message_too_big, max_message_length=~p,",
        [Len],
        St
    ),
    {stop, message_too_big, St};

handle_data(<<0:5, 0:3, Len:24, Data/binary>>, St)
when byte_size(Data) >= Len ->
    %% We received a WAMP message
    %% Len is the number of octets after serialization
    <<Mssg:Len/binary, Rest/binary>> = Data,
    case bondy_wamp_fsm:handle_inbound(Mssg, St#state.session) of
        {ok, PSt} ->
            handle_data(Rest, St#state{session = PSt});
        {reply, L, PSt} ->
            St1 = St#state{session = PSt},
            ok = send(L, St1),
            handle_data(Rest, St1);
        {stop, PSt} ->
            {stop, normal, St#state{session = PSt}};
        {stop, L, PSt} ->
            St1 = St#state{session = PSt},
            ok = send(L, St1),
            {stop, normal, St1};
        {stop, normal, L, PSt} ->
            St1 = St#state{session = PSt},
            ok = send(L, St1),
            {stop, normal, St1};
        {stop, Reason, L, PSt} ->
            St1 = St#state{
                session = PSt,
                shutdown_reason = Reason
            },
            ok = send(L, St1),
            {stop, shutdown, St1}
    end;

handle_data(<<0:5, 1:3, Len:24, Data/binary>>, St) ->
    %% We received a PING, send a PONG
    <<Payload:Len/binary, Rest/binary>> = Data,
    ok = send(<<0:5, 2:3, Len:24, Payload/binary>>, St),
    handle_data(Rest, St);

handle_data(<<0:5, 2:3, Len:24, Data/binary>>, St) ->
    %% We received a PONG
    _ = log(debug, "Received pong;", [], St),
    <<Payload:Len/binary, Rest/binary>> = Data,
    case St#state.ping_sent of
        {true, Payload, TimerRef} ->
            %% We reset the state
            ok = erlang:cancel_timer(TimerRef, [{info, false}]),
            handle_data(Rest, St#state{ping_sent = false, ping_attempts = 0});
        {true, Bin, TimerRef} ->
            ok = erlang:cancel_timer(TimerRef, [{info, false}]),
            _ = log(
                error,
                "Invalid pong message from peer; "
                "reason=invalid_ping_response, received=~p, expected=~p,",
                [Bin, Payload], St
            ),
            {stop, invalid_ping_response, St};
        false ->
            _ = log(error, "Unrequested pong message from peer;", [], St),
            %% Should we stop instead?
            handle_data(Rest, St)
    end;

handle_data(<<0:5, R:3, Len:24, Data/binary>>, St) when R > 2 ->
    %% The three bits (R) encode the type of the transport message,
    %% values 3 to 7 are reserved
    <<Mssg:Len, Rest/binary>> = Data,
    ok = send(error_number(use_of_reserved_bits), St),
    _ = log(
        error,
        "Client committed a WAMP protocol violation, message dropped; reason=~p, value=~p, message=~p,",
        [use_of_reserved_bits, R, Mssg],
        St
    ),
    %% Should we stop instead?
    handle_data(Rest, St);

handle_data(<<>>, St) ->
    %% We finished consuming data
    {ok, St};

handle_data(Data, St) ->
    %% We have a partial message i.e. byte_size(Data) < Len
    %% we store is as buffer
    {ok, St#state{buffer = Data}}.


-spec handle_outbound(any(), state()) ->
    {noreply, state(), timeout()}
    | {stop, normal, state()}.

handle_outbound(M, St0) ->
    case bondy_wamp_fsm:handle_outbound(M, St0#state.session) of
        {ok, Bin, PSt} ->
            St1 = St0#state{session = PSt},
            case send(Bin, St1) of
                ok ->
                    {noreply, St1, ?TIMEOUT};
                {error, message_too_big} ->
                    _ = log(
                        warning,
                        "Message dropped as it exceeds the maximum message length;",
                        [],
                        St1
                    ),
                    {noreply, St1, ?TIMEOUT};
                {error, Reason} ->
                    {stop, Reason, St1}
            end;

        {stop, PSt} ->
            {stop, normal, St0#state{session = PSt}};

        {stop, Bin, PSt} ->
            St1 = St0#state{session = PSt},
            case send(Bin, St1) of
                ok ->
                    {stop, normal, St1};
                {error, Reason} ->
                    {stop, Reason, St1}
            end;

        {stop, Bin, PSt, Time} when is_integer(Time), Time > 0 ->
            %% We send ourselves a message to stop after Time
            St1 = St0#state{session = PSt},
            erlang:send_after(Time, self(), {stop, normal}),

            case send(Bin, St1) of
                ok ->
                    {noreply, St1};
                {error, Reason} ->
                    {stop, Reason, St1}
            end
    end.


%% @private
handle_handshake(Len, Enc, St) ->
    try
        init_wamp(Len, Enc, St)
    catch
        throw:Reason ->
            ok = send(error_number(Reason), St),
            _ = lager:error("WAMP protocol error, reason=~p", [Reason]),
            {stop, Reason, St}
    end.


%% @private
init_wamp(Len, Enc, St0) ->
    MaxLen = validate_max_len(Len),
    Encoding = validate_encoding(Enc),

    St1 = St0#state{
        encoding = Encoding,
        max_length = MaxLen
    },

    Proto = {raw, binary, Encoding},

    Conn = bondy_connection:new(?MODULE, self(), #{
        transport =>  St1#state.transport,
        socket => St1#state.socket,
        encoding => St1#state.encoding,
        max_length => St1#state.max_length,
        peername => St1#state.peername,
        real_peername => St1#state.peername
    }),


    case bondy_wamp_fsm:init(Proto, Conn) of
        {ok, CBState} ->
            St2 = St1#state{
                session = CBState
            },

            ok = send(
                <<?RAW_MAGIC, Len:4, Enc:4, 0:8, 0:8>>, St2
            ),

            _ = log(info, "Established connection with peer;", [], St2),
            {ok, St2};
        {error, Reason} ->
            {stop, Reason, St1}
    end.

%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% The possible values for "LENGTH" are:
%%
%% 0: 2**9 octets
%% 1: 2**10 octets ...
%% 15: 2**24 octets
%%
%% This means a _Client_ can choose the maximum message length between *512*
%% and *16M* octets.
%% @end
%% -----------------------------------------------------------------------------
validate_max_len(N) when N >= 0, N =< 15 ->
    trunc(math:pow(2, 9 + N));

validate_max_len(_) ->
    %% TODO define correct error return
    throw(maximum_message_length_unacceptable).


%% @private
maybe_too_big(Frame, MaxLen) ->
    byte_size(Frame) =< min(MaxLen, ?MAX_FRAME_LEN)
    orelse throw(message_too_big),
    Frame.





%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% 0: illegal
%% 1: JSON
%% 2: MessagePack
%% 3 - 15: reserved for future serializers
%% @end
%% -----------------------------------------------------------------------------
validate_encoding(1) ->
    json;

validate_encoding(2) ->
    msgpack;

validate_encoding(N) ->
    case lists:keyfind(N, 2, bondy_config:get(wamp_serializers, [])) of
        {erl, N} ->
            erl;
        {bert, N} ->
            bert;
        undefined ->
            %% TODO define correct error return
            throw(serializer_unsupported)
    end.


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% 0: illegal (must not be used)
%% 1: serializer unsupported
%% 2: maximum message length unacceptable
%% 3: use of reserved bits (unsupported feature)
%% 4: maximum connection count reached
%% 5 - 15: reserved for future errors
%% @end
%% -----------------------------------------------------------------------------
error_number(serializer_unsupported) ->?RAW_ERROR(1);
error_number(maximum_message_length_unacceptable) ->?RAW_ERROR(2);
error_number(use_of_reserved_bits) ->?RAW_ERROR(3);
error_number(maximum_connection_count_reached) ->?RAW_ERROR(4).

%% error_reason(1) -> serializer_unsupported;
%% error_reason(2) -> maximum_message_length_unacceptable;
%% error_reason(3) -> use_of_reserved_bits;
%% error_reason(4) -> maximum_connection_count_reached.


%% @private
log_meta(State) ->
    PeernameBin = inet_utils:peername_to_binary(State#state.peername),
    RealPeernameBin = case State#state.real_peername of
        undefined ->
            undefined;
        Value ->
            inet_utils:peername_to_binary(Value)
    end,

    #{
        frame_type => binary,
        peername => PeernameBin,
        protocol => wamp,
        protocol_transport => raw,
        real_peername => RealPeernameBin,
        socket => State#state.socket,
        transport => State#state.transport
    }.


%% @private
log(Level, Format, Args, #state{session = undefined})
when is_binary(Format) orelse is_list(Format), is_list(Args) ->
    lager:log(Level, self(), Format, Args);

log(Level, Prefix, Head, St)
when is_binary(Prefix) orelse is_list(Prefix), is_list(Head) ->
    Format = iolist_to_binary([
        Prefix,
        <<
            " realm=~s, session_id=~p, peername=~s, real_peername=~s, agent=~p"
            ", protocol=wamp, transport=raw, frame_type=~p, encoding=~p"
            ", message_max_length=~p, socket=~p"
        >>
    ]),
    SessionId = bondy_session:id(St#state.session),
    Agent = bondy_session:agent(St#state.session),
    #{
        peername := Peername,
        real_peername := RealPeername,
        frame_type := FrameType
    } = St#state.log_meta,

    Tail = [
        RealmUri,
        SessionId,
        Peername,
        RealPeername,
        Agent,
        FrameType,
        St#state.encoding,
        St#state.max_length,
        St#state.socket
    ],
    lager:log(Level, self(), Format, lists:append(Head, Tail)).

%% @private
socket_opened(St) ->
    Event = {socket_open, wamp, raw, St#state.peername},
    bondy_event_manager:notify(Event).


%% @private
close_socket(Reason, St) ->
    Socket = St#state.socket,
    catch (St#state.transport):close(Socket),

    Seconds = erlang:monotonic_time(second) - St#state.start_time,

    %% We report socket stats
    ok = bondy_event_manager:notify(
        {socket_closed, wamp, raw, St#state.peername, Seconds}
    ),

    IncrSockerErrorCnt = fun() ->
        %% We increase the socker error counter
        bondy_event_manager:notify(
            {socket_error, wamp, raw, St#state.peername}
        )
    end,

    {Format, LogReason} = case Reason of
        normal ->
            {<<"Connection closed by peer; reason=~p,">>, Reason};

        shutdown ->
            {<<"Connection closed by router; reason=~p,">>, Reason};

        {tcp_error, Socket, Reason} ->
            %% We increase the socker error counter
            ok = IncrSockerErrorCnt(),
            {<<"Connection closing due to tcp_error; reason=~p">>, Reason};

        _ ->
            %% We increase the socker error counter
            ok = IncrSockerErrorCnt(),
            {<<"Connection closed due to system error; reason=~p,">>, Reason}
    end,

    _ = log(error, Format, [LogReason], St),
    ok.



%% @private
active_n(#state{active_n = N}) ->
    %% TODO make this dynamic based on adaptive algorithm that takes into
    %% account:
    %% - overall node load
    %% - this socket traffic i.e. slow traffic => once, high traffic => N
    N.


%% @private
maybe_active_once(#state{active_n = once} = State) ->
    Transport = State#state.transport,
    Socket = State#state.socket,
    Transport:setopts(Socket, [{active, once}]);

maybe_active_once(#state{active_n = N} = State) ->
    Transport = State#state.transport,
    Socket = State#state.socket,
    Transport:setopts(Socket, [{active, N}]).


%% @private
reset_inet_opts(#state{} = State) ->
    Transport = State#state.transport,
    Socket = State#state.socket,
    N = active_n(State),
    Transport:setopts(Socket, [{active, N}]).


%% @private
-spec send(binary() | iolist(), state()) -> ok | {error, any()}.

send(L, #state{} = St) when is_list(L) ->
    lists:foreach(fun(Bin) -> send(Bin, St) end, L);

send(Bin, #state{} = St) ->
    try
        %% TODO do not send immeditely, buffer until we get closer to MSS (1460
        %% bytes)
        %% A maximum transmission unit (MTU) is the largest packet or frame
        %% size in bytes that can be sent in a packet- or frame-based network
        %% e.g. TCP.
        %% TCP uses the MTU to determine the maximum size of each packet in any
        %% transmission. MTU is usually associated with the Ethernet protocol,
        %% where a 1500-byte packet is the largest allowed in it (and hence
        %% over most of the internet).
        %% Larger packets will use IPv4 fragmentation, which divides the
        %% datagram into pieces. Each piece is small enough to pass over the
        %% single link that it is being fragmented for, using the MTU parameter
        %% configured for that interface.
        %% The best way to avoid fragmentation is to adjust the maximum segment
        %% size or TCP MSS so the segment will adjust its size before reaching
        %% the data link layer.
        %% The total value of the IP and the TCP header is 40 bytes and
        %% mandatory for each packet, which leaves us 1460 bytes for our data.
        send(
            St#state.transport,
            St#state.socket,
            maybe_too_big(?RAW_FRAME(Bin), St#state.max_length),
            []
        )
    catch
        throw:Reason ->
            {error, Reason}
    end.


%% @private
send_ping(#state{} = St) ->
    send_ping(integer_to_binary(erlang:system_time(microsecond)), St).


%% -----------------------------------------------------------------------------
%% @private
%% @doc Sends a ping message with a reference() as a payload to the client and
%% sent ourselves a ping_timeout message in the future.
%% @end
%% -----------------------------------------------------------------------------
send_ping(Bin, #state{} = St0) ->
    %% Crash if we cannot send ping
    ok = send(
        St0#state.transport,
        St0#state.socket,
        <<0:5, 1:3, (byte_size(Bin)):24, Bin/binary>>
    ),
    Timeout = bondy_config:get(ping_timeout, ?PING_TIMEOUT),
    TimerRef = erlang:send_after(Timeout, self(), ping_timeout),
    St1 = St0#state{
        ping_sent = {true, Bin, TimerRef},
        ping_attempts = St0#state.ping_attempts + 1
    },
    {ok, St1}.


%% @private
peername(Socket) ->
    case inet:peername(Socket) of
        {ok, {_, _} = Peername} ->
            Peername;
        {ok, NonIPAddr} ->

            _ = lager:error(
                "Unexpected peername when establishing connection,"
                " received a non IP address of '~p'; reason=invalid_socket,"
                " protocol=wamp, transport=raw",
                [NonIPAddr]
            ),
            throw(invalid_socket);

        {error, Reason} ->
            _ = lager:error(
                "Invalid peername when establishing connection,"
                " reason=~p, description=~p, protocol=wamp, transport=raw",
                [Reason, inet:format_error(Reason)]
            ),
            throw(invalid_socket)
    end.


%% @private
real_peername(#{src_address := RealIP, src_port := RealPort}) ->
    {RealIP, RealPort};

real_peername(_) ->
    undefined.

