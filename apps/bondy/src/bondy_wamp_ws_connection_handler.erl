%% =============================================================================
%%  bondy_wamp_ws_connection_handler.erl -
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
%% @doc A Cowboy WS handler.
%%
%% Each WAMP message is transmitted as a separate WebSocket message
%% (not WebSocket frame)
%%
%% The WAMP protocol MUST BE negotiated during the WebSocket opening
%% handshake between Peers using the WebSocket subprotocol negotiation
%% mechanism.
%%
%% WAMP uses the following WebSocket subprotocol identifiers for
%% unbatched modes:
%%
%% *  "wamp.2.json"
%% *  "wamp.2.msgpack"
%%
%% With "wamp.2.json", _all_ WebSocket messages MUST BE of type *text*
%% (UTF8 encoded) and use the JSON message serialization.
%%
%% With "wamp.2.msgpack", _all_ WebSocket messages MUST BE of type
%% *binary* and use the MsgPack message serialization.
%%
%% To avoid incompatibilities merely due to naming conflicts with
%% WebSocket subprotocol identifiers, implementers SHOULD register
%% identifiers for additional serialization formats with the official
%% WebSocket subprotocol registry.
%% @end
%% -----------------------------------------------------------------------------
-module(bondy_wamp_ws_connection_handler).
-include("http_api.hrl").
-include("bondy.hrl").
-include_lib("wamp/include/wamp.hrl").

%% Cowboy will automatically close the Websocket connection when no data
%% arrives on the socket after ?IDLE_TIMEOUT
-define(IDLE_TIMEOUT, 60000*10).
-define(SUBPROTO_HEADER, <<"sec-websocket-protocol">>).


-record(state, {
    frame_type              ::  bondy_wamp_protocol:frame_type(),
    protocol_state          ::  bondy_wamp_protocol:state() | undefined,
    auth_token              ::  map(),
    hibernate = false       ::  boolean(),
    ping_enabled            ::  boolean(),
    ping_interval           ::  timeout(),
    ping_interval_ref       ::  reference() | undefined,
    ping_max_attempts       ::  integer(),
    ping_attempts = 0       ::  integer()
}).

-type state()               ::  #state{}.



-export([init/2]).
-export([websocket_init/1]).
-export([websocket_handle/2]).
-export([websocket_info/2]).
-export([terminate/3]).



%% =============================================================================
%% COWBOY HANDLER CALLBACKS
%% =============================================================================

-spec init(cowboy_req:req(), state()) ->
    {ok | module(), cowboy_req:req(), state()}
    | {module(), cowboy_req:req(), state(), hibernate}
    | {module(), cowboy_req:req(), state(), timeout()}
    | {module(), cowboy_req:req(), state(), timeout(), hibernate}.

init(Req0, _) ->
    %% From [Cowboy's Users Guide](http://ninenines.eu/docs/en/cowboy/1.0/guide/ws_handlers/)
    %% If the sec-websocket-protocol header was sent with the request for
    %% establishing a Websocket connection, then the Websocket handler must
    %% select one of these subprotocol and send it back to the client,
    %% otherwise the client might decide to close the connection, assuming no
    %% correct subprotocol was found.
    ClientIP = bondy_http_utils:client_ip(Req0),
    Subprotocols = cowboy_req:parse_header(?SUBPROTO_HEADER, Req0),


    try

        {ok, Subproto, BinProto} = select_subprotocol(Subprotocols),

        %% If we have a token we pass it to the WAMP protocol state so that
        %% we can verify it and immediately authenticate the client using
        %% the token stored information.
        AuthToken = maybe_token(Req0),
        State1 = #state{auth_token = AuthToken},

        do_init(Subproto, BinProto, Req0, State1)

    catch
        throw:invalid_scheme ->
            %% Returning ok will cause the handler
            %% to stop in websocket_handle
            Req1 = cowboy_req:reply(?HTTP_BAD_REQUEST, Req0),
            {ok, Req1, undefined};

        throw:missing_subprotocol ->
            _ = lager:info(
                "Closing WS connection. Missing value for header '~s'; " "client_ip=~s",
                [?SUBPROTO_HEADER, ClientIP]
            ),
            %% Returning ok will cause the handler
            %% to stop in websocket_handle
            Req1 = cowboy_req:reply(?HTTP_BAD_REQUEST, Req0),
            {ok, Req1, undefined};

        throw:invalid_subprotocol ->
            %% At the moment we only support WAMP, not plain WS
            _ = lager:info(
                "Closing WS connection. Initialised without a valid value for http header '~s'; value=~p, client_ip=~s",
                [?SUBPROTO_HEADER, Subprotocols, ClientIP]
            ),
            %% Returning ok will cause the handler
            %% to stop in websocket_handle
            Req1 = cowboy_req:reply(?HTTP_BAD_REQUEST, Req0),
            {ok, Req1, undefined};

        throw:_Reason ->
            %% Returning ok will cause the handler
            %% to stop in websocket_handle
            Req1 = cowboy_req:reply(?HTTP_BAD_REQUEST, Req0),
            {ok, Req1, undefined}
    end.



%% =============================================================================
%% COWBOY_WEBSOCKET CALLBACKS
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% Initialises the WS connection.
%% @end
%% -----------------------------------------------------------------------------
websocket_init(#state{protocol_state = undefined} = St) ->
    %% This will close the WS connection
    Frame = {
        close,
        1002,
        <<"Missing value for header 'sec-websocket-protocol'.">>
    },
    {reply, Frame, St};

websocket_init(St) ->
    _ = log(info, "Established connection with peer;", [], St),
    {ok, reset_ping_interval(St)}.


%% -----------------------------------------------------------------------------
%% @doc
%% Handles frames sent by client
%% @end
%% -----------------------------------------------------------------------------
websocket_handle(Data, #state{protocol_state = undefined} = St) ->
    %% At the moment we only support WAMP, so we stop immediately.
    %% TODO This should be handled by the websocket_init callback above,
    %% review and eliminate.
    _ = lager:error(
        "Connection closing; reason=unsupported_message, message=~p", [Data]
    ),
    {stop, St};

websocket_handle(ping, St) ->
    %% Cowboy already replies to pings for us, we do nothing
    {ok, St};

websocket_handle({ping, _}, St) ->
    %% Cowboy already replies to pings for us, we do nothing
    {ok, St};

websocket_handle({pong, <<"bondy">>}, St0) ->
    %% We've got an answer to a Bondy-initiated ping.
    {ok, reset_ping_attempts(St0)};


websocket_handle({T, Data}, #state{frame_type = T} = St0) ->
    case bondy_wamp_protocol:handle_inbound(Data, St0#state.protocol_state) of
        {ok, PSt} ->
            {ok, St0#state{protocol_state = PSt}};
        {reply, L, PSt} ->
            reply(T, L, St0#state{protocol_state = PSt});
        {stop, PSt} ->
            {stop, St0#state{protocol_state = PSt}};
        {stop, L, PSt} ->
            self() ! {stop, normal},
            reply(T, L, St0#state{protocol_state = PSt});
        {stop, Reason, L, PSt} ->
            self() ! {stop, Reason},
            reply(T, L, St0#state{protocol_state = PSt})
    end;

websocket_handle(Data, St) ->
    %% We ignore this message and carry on listening
    _ = log(debug, "Received unsupported message; message=~p", [Data], St),
    {ok, St}.


%% -----------------------------------------------------------------------------
%% @doc
%% Handles internal erlang messages and WAMP messages BONDY wants to send to the
%% client. See {@link bondy:send/2}.
%% @end
%% -----------------------------------------------------------------------------
websocket_info({?BONDY_PEER_REQUEST, Pid, M}, St) when Pid =:= self() ->
    handle_outbound(St#state.frame_type, M, St);

websocket_info({?BONDY_PEER_REQUEST, Pid, Ref, M}, St) ->
    %% Here we receive the messages that either the router or another peer
    %% sent to us using bondy:send/2,3
    ok = bondy:ack(Pid, Ref),
    handle_outbound(St#state.frame_type, M, St);

websocket_info(
    {timeout, Ref, ping_interval}, #state{ping_interval_ref = Ref} = St) ->
    send_ping(St);

websocket_info({timeout, _Ref, Msg}, St) ->
    _ = log(debug, "Received unknown timeout; message=~p", [Msg], St),
    {ok, St};

websocket_info({stop, shutdown = Reason}, St) ->
    _ = log(info, "Connection closing; reason=~p", [Reason], St),
    {stop, St};

websocket_info({stop, Reason}, St) ->
    _ = log(info, "Connection closing; reason=~p", [Reason], St),
    {stop, St};

websocket_info(_, St0) ->
    %% Any other unwanted erlang messages
    {ok, St0}.


%% -----------------------------------------------------------------------------
%% @doc
%% Termination
%% @end
%% -----------------------------------------------------------------------------
%% From : http://ninenines.eu/docs/en/cowboy/2.0/guide/handlers/
%% Note that while this function may be called in a Websocket handler, it is
%% generally not useful to do any clean up as the process terminates
%% immediately after calling this callback when using Websocket.
terminate(normal, _Req, St) ->
    do_terminate(St);

terminate(stop, _Req, St) ->
    do_terminate(St);

terminate(timeout, _Req, St) ->
    Timeout = bondy_config:get([wamp_websocket, idle_timeout]),
    _ = log(error,
        "Connection closing; reason=idle_timeout, idle_timeout=~p,",
        [Timeout],
        St
    ),
    do_terminate(St);

terminate(remote, _Req, St) ->
    %% The remote endpoint closed the connection without giving any further
    %% details.
    _ = log(info, "Connection closed by peer; reason=~p,", [unknown], St),
    do_terminate(St);

terminate({remote, Code, Payload}, _Req, St) ->
    _ = log(
        info,
        "Connection closed by peer; reason=remote, code=~p, payload=~p",
        [Code, Payload],
        St
    ),
    do_terminate(St);

terminate({error, closed = Reason}, _Req, St) ->
    %% The socket has been closed brutally without a close frame being received
    %% first.
    _ = log(error, "Connection closed brutally; reason=~p,", [Reason], St),
    do_terminate(St);

terminate({error, badencoding = Reason}, _Req, St) ->
    %% A text frame was sent by the client with invalid encoding. All text
    %% frames must be valid UTF-8.
    _ = log(error, "Connection closed; reason=~p,", [Reason], St),
    do_terminate(St);

terminate({error, badframe = Reason}, _Req, St) ->
    %% A protocol error has been detected.
    _ = log(error, "Connection closed; reason=~p,", [Reason], St),
    do_terminate(St);

terminate({error, Reason}, _Req, St) ->
    _ = log(error, "Connection closed; reason=~p,", [Reason], St),
    do_terminate(St);

terminate({crash, Class, Reason}, _Req, St) ->
    %% A crash occurred in the handler.
    _ = log(error,
        "Process crashed, error=~p, reason=~p",
        [Class, Reason], St
    ),
    do_terminate(St);

terminate(Other, _Req, St) ->
        _ = log(error,
        "Process crashed, reason=~p",
        [Other], St
    ),
    do_terminate(St).



%% =============================================================================
%% PRIVATE:
%% =============================================================================



%% @private
handle_outbound(T, M, St) ->
    case bondy_wamp_protocol:handle_outbound(M, St#state.protocol_state) of
        {ok, Bin, PSt} ->
            {reply, frame(T, Bin), St#state{protocol_state = PSt}};
        {stop, PSt} ->
            {stop, St#state{protocol_state = PSt}};
        {stop, Bin, PSt} ->
            self() ! {stop, normal},
            reply(T, [Bin], St#state{protocol_state = PSt});
        {stop, Bin, PSt, Time} when is_integer(Time), Time > 0 ->
            erlang:send_after(
                Time, self(), {stop, normal}),
            reply(T, [Bin], St#state{protocol_state = PSt})
    end.


%% @private
maybe_token(Req) ->
    case cowboy_req:parse_header(<<"authorization">>, Req) of
        undefined -> undefined;
        {bearer, Token} -> Token;
        _ -> throw(invalid_scheme)
    end.


%% @private
do_init({ws, FrameType, _Enc} = Subproto, BinProto, Req0, State) ->
    Peer = cowboy_req:peer(Req0),
    AuthToken = State#state.auth_token,
    ProtocolOpts = #{auth_token => AuthToken},
    AllOpts = maps_utils:from_property_list(bondy_config:get(wamp_websocket)),
    {PingOpts, Opts} = maps:take(ping, AllOpts),

    case bondy_wamp_protocol:init(Subproto, Peer, ProtocolOpts) of
        {ok, CBState} ->
            St = #state{
                frame_type = FrameType,
                protocol_state = CBState,
                ping_enabled = maps:get(enabled, PingOpts),
                ping_interval = maps:get(interval, PingOpts),
                ping_max_attempts = maps:get(max_attempts, PingOpts)
            },
            Req1 = cowboy_req:set_resp_header(?SUBPROTO_HEADER, BinProto, Req0),
            {cowboy_websocket, Req1, St, Opts};
        {error, _Reason} ->
            %% Returning ok will cause the handler to
            %% stop in websocket_handle
            Req1 = cowboy_req:reply(?HTTP_BAD_REQUEST, Req0),
            {ok, Req1, undefined}
    end.


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% The order is undefined
%% @end
%% -----------------------------------------------------------------------------
-spec select_subprotocol(list(binary()) | undefined) ->
    {ok, bondy_wamp_protocol:subprotocol(), binary()}
    | no_return().

select_subprotocol(undefined) ->
    throw(missing_subprotocol);

select_subprotocol(L) when is_list(L) ->
    try
        Fun = fun(X) ->
            case bondy_wamp_protocol:validate_subprotocol(X) of
                {ok, SP} ->
                    throw({break, SP, X});
                {error, invalid_subprotocol} ->
                    ok
            end
        end,
        ok = lists:foreach(Fun, L),
        throw(invalid_subprotocol)
    catch
        throw:{break, SP, X} ->
            {ok, SP, X}
    end.


%% @private
do_terminate(undefined) ->
    ok;

do_terminate(St) ->
    ok = cancel_timer(St#state.ping_interval_ref),
    bondy_wamp_protocol:terminate(St#state.protocol_state).



%% @private
reply(FrameType, Frames, #state{hibernate = true} = St) ->
    {reply, frame(FrameType, Frames), St, hibernate};

reply(FrameType, Frames, #state{hibernate = false} = St) ->
    {reply, frame(FrameType, Frames), St}.


%% @private
frame(Type, L) when is_list(L) ->
    [frame(Type, E) || E <- L];

frame(Type, E) when Type == text orelse Type == binary ->
    {Type, E}.


%% @private


log(Level, Prefix, Head, #state{} = St)
when is_binary(Prefix) orelse is_list(Prefix), is_list(Head) ->
    Format = iolist_to_binary([
        Prefix,
        <<
            " session_id=~p, peername=~s, agent=~p"
            ", protocol=wamp, transport=websocket, frame_type=~p, encoding=~p"
        >>
    ]),

    Ctxt = bondy_wamp_protocol:context(St#state.protocol_state),

    Tail = [
        bondy_wamp_protocol:session_id(St#state.protocol_state),
        bondy_context:peername(Ctxt),
        bondy_wamp_protocol:agent(St#state.protocol_state),
        St#state.frame_type,
        bondy_context:encoding(Ctxt)
    ],
    lager:log(Level, self(), Format, lists:append(Head, Tail));

log(Level, Prefix, Head, _) ->
    lager:log(Level, self(), Prefix, Head).





%% =============================================================================
%% PRIVATE: PING & TIMEOUT
%% =============================================================================


%% @private
reset_ping_attempts(St) ->
    St#state{ping_attempts = 0}.


%% @private
reset_ping_interval(#state{ping_enabled = true} = St) ->
    Ref = erlang:start_timer(St#state.ping_interval, self(), ping_interval),
    St#state{ping_interval_ref = Ref};

reset_ping_interval(St) ->
    St.


%% @private
send_ping(#state{ping_attempts = N, ping_max_attempts = M} = St) when N > M ->
    _ = log(
        error,
        "Connection closing; reason=ping_timeout, attempts=~p",
        [N],
        St
    ),
    {stop, St};

send_ping(St0) ->
    St1 = reset_ping_interval(St0),
    St2 = St1#state{ping_attempts = St0#state.ping_attempts + 1},
    {reply, {ping, <<"bondy">>}, St2}.


%% @private
cancel_timer(Ref) when is_reference(Ref) ->
    _ = erlang:cancel_timer(Ref),
    ok;

cancel_timer(_) ->
    ok.