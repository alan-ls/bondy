%% =============================================================================
%%  bondy.erl -
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
-module(bondy).
-include("bondy.hrl").
-include("bondy_uris.hrl").
-include_lib("wamp/include/wamp.hrl").

-type wamp_error_map() :: #{
    error_uri => uri(),
    details => map(),
    arguments => list(),
    arguments_kw => map()
}.

-export_type([wamp_error_map/0]).

-export([ack/2]).
-export([call/5]).
-export([publish/5]).
-export([subscribe/3]).
-export([subscribe/4]).
-export([send/2]).
-export([send/3]).
-export([send/4]).
-export([start/0]).
-export([aae_exchanges/0]).

%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% Starts bondy
%% @end
%% -----------------------------------------------------------------------------
start() ->
    application:ensure_all_started(bondy).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
aae_exchanges() ->
    plumtree_broadcast:exchanges().


%% -----------------------------------------------------------------------------
%% @doc
%% Sends a message to a WAMP peer.
%% It calls `send/3' with a an empty map for Options.
%% @end
%% -----------------------------------------------------------------------------
-spec send(bondy_session:t(), wamp_message()) -> ok.

send(PeerInfo, M) ->
    send(PeerInfo, M, #{}).


%% -----------------------------------------------------------------------------
%% @doc
%% Sends a message to a local WAMP peer.
%% If the transport is not open it fails with an exception.
%% This function is used by the router (dealer | broker) to send WAMP messages
%% to local peers.
%% Opts is a map with the following keys:
%%
%% * timeout - timeout in milliseconds (defaults to 10000)
%% * enqueue (boolean) - if the peer is not reachable and this value is true,
%% bondy will enqueue the message so that the peer can resume the session and
%% consume all enqueued messages.
%%
%% @end
%% -----------------------------------------------------------------------------
-spec send(bondy_session:ref(), wamp_message(), map()) ->
    ok | no_return().

send(To, M, Opts0)  ->
    %% Validations
    bondy_session:is_ref(To) orelse error(badarg),

    bondy_session:node(To) =:= bondy_peer_service:mynode()
    orelse error(not_my_node),

    wamp_message:is_message(M) orelse error(invalid_wamp_message),

    Opts = validate_send_opts(Opts0),

    bondy_session:send(M, Opts, To).


-spec send(
    From :: bondy_session:t(),
    To :: bondy_session:t(),
    M :: wamp_message(),
    Opts :: map()) -> ok | no_return().

send(From, To, M, Opts0) ->
    %% Validations
    bondy_session:realm_uri(From) =:= bondy_session:realm_uri(To)
        orelse error(badarg),

    wamp_message:is_message(M) orelse error(invalid_wamp_message),

    Opts = validate_send_opts(Opts0),

    case bondy_session:node(To) =:= bondy_peer_service:mynode() of
        true ->
            bondy_session:send(M, Opts, To);
        false ->
            bondy_peer_wamp_forwarder:forward(From, To, M, Opts)
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% Acknowledges the reception of a WAMP message. This function should be used by
%% the peer transport module to acknowledge the reception of a message sent with
%% {@link send/3}.
%% @end
%% -----------------------------------------------------------------------------
-spec ack(pid(), reference()) -> ok.

ack(Pid, _) when Pid =:= self()  ->
    %% We do not need to send an ack (implicit ack send case)
    ok;

ack(Pid, Ref) when is_pid(Pid), is_reference(Ref) ->
    Pid ! {?BONDY_PEER_ACK, Ref},
    ok.



%% =============================================================================
%% API - SESSION
%% =============================================================================




%% =============================================================================
%% API - SUBSCRIBER ROLE
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc Calls bondy_broker:subscribe/3.
%% @end
%% -----------------------------------------------------------------------------
subscribe(RealmUri, Opts, TopicUri) ->
    bondy_broker:subscribe(RealmUri, Opts, TopicUri).


%% -----------------------------------------------------------------------------
%% @doc Calls bondy_broker:subscribe/4.
%% @end
%% -----------------------------------------------------------------------------
subscribe(RealmUri, Opts, TopicUri, Fun) ->
    bondy_broker:subscribe(RealmUri, Opts, TopicUri, Fun).



%% =============================================================================
%% API - PUBLISHER ROLE
%% =============================================================================



publish(Opts, TopicUri, Args, ArgsKw, CtxtOrRealm) ->
    bondy_broker:publish(Opts, TopicUri, Args, ArgsKw, CtxtOrRealm).



%% =============================================================================
%% API - CALLER ROLE
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc
%% A blocking call.
%% @end
%% -----------------------------------------------------------------------------
-spec call(
    binary(),
    map(),
    list() | undefined,
    map() | undefined,
    bondy_context:t()) ->
    {ok, map()} | {error, wamp_error_map()}.

call(ProcedureUri, Opts, Args, ArgsKw, Ctxt) ->
    %% @TODO ID should be session scoped and not global
    %% FIXME we need to fix the wamp.hrl timeout
    %% TODO also, according to WAMP the default is 0 which deactivates
    %% the Call Timeout Feature
    Timeout = case maps:find(timeout, Opts) of
        {ok, 0} -> bondy_config:get(wamp_call_timeout);
        {ok, Val} -> Val;
        error -> bondy_config:get(wamp_call_timeout)
    end,
    ReqId = bondy_utils:get_id(global),

    M = wamp_message:call(ReqId, Opts, ProcedureUri, Args, ArgsKw),

    case bondy_router:forward(M, Ctxt) of
        ok ->
            receive
                {?BONDY_PEER_REQUEST, Pid, Ref, #result{} = R} ->
                    ok = bondy:ack(Pid, Ref),
                    {ok, message_to_map(R), Ctxt};
                {?BONDY_PEER_REQUEST, Pid, Ref, #error{} = R} ->
                    ok = bondy:ack(Pid, Ref),
                    {error, message_to_map(R), Ctxt}
            after
                Timeout ->
                    Mssg = iolist_to_binary(
                        io_lib:format(
                            "The operation could not be completed in time"
                            " (~p milliseconds).",
                            [Timeout]
                        )
                    ),
                    ErrorDetails = maps:new(),
                    ErrorArgs = [Mssg],
                    ErrorArgsKw = #{
                        procedure_uri => ProcedureUri,
                        timeout => Timeout
                    },
                    Error = wamp_message:error(
                        ?CALL,
                        ReqId,
                        ErrorDetails,
                        ?BONDY_ERROR_TIMEOUT,
                        ErrorArgs,
                        ErrorArgsKw
                    ),
                    ok = bondy_event_manager:notify({wamp, Error, Ctxt}),
                    {error, message_to_map(Error), Ctxt}
            end;
        {reply, #error{} = Error} ->
            %% A sync reply (should not ever happen with calls)
            {error, message_to_map(Error)};
        {reply, _} ->
            %% A sync reply (should not ever happen with calls)
            Error = wamp_message:error(
                ?CALL, ReqId, #{}, ?BONDY_ERROR_INCONSISTENCY_ERROR,
                [<<"Inconsistency error">>]
            ),
            ok = bondy_event_manager:notify({wamp, Error, Ctxt}),
            {error, message_to_map(Error), Ctxt};
        {stop, #error{} = Error} ->
            %% A sync reply (should not ever happen with calls)
            ok = bondy_event_manager:notify({wamp, Error, Ctxt}),
            {error, message_to_map(Error), Ctxt};
        {stop, _} ->
            %% A sync reply (should not ever happen with calls)
            Error = wamp_message:error(
                ?CALL, ReqId, #{}, ?BONDY_ERROR_INCONSISTENCY_ERROR,
                [<<"Inconsistency error">>]
            ),
            ok = bondy_event_manager:notify({wamp, Error, Ctxt}),
            {error, message_to_map(Error), Ctxt}
    end.



%% =============================================================================
%% API - CALLEE ROLE
%% =============================================================================






%% =============================================================================
%% PRIVATE
%% =============================================================================



%% @private
validate_send_opts(Opts) ->
    maps_utils:validate(Opts, #{
        timeout => #{
            required => true,
            datatype => timeout,
            default => ?SEND_TIMEOUT
        },
        enqueue => #{
            required => true,
            datatype => boolean,
            default => false
        }
    }).


%% @private
message_to_map(#result{} = M) ->
    #result{
        request_id = Id,
        details = Details,
        arguments = Args,
        arguments_kw = ArgsKw
    } = M,
    #{
        request_id => Id,
        details => Details,
        arguments => args(Args),
        arguments_kw => args_kw(ArgsKw)
    };

message_to_map(#error{} = M) ->
    #error{
        request_type = Type,
        request_id = Id,
        details = Details,
        error_uri = Uri,
        arguments = Args,
        arguments_kw = ArgsKw
    } = M,
    %% We need these keys to be binaries, becuase we will
    %% inject this in a mops context.
    #{
        request_type => Type,
        request_id => Id,
        details => Details,
        error_uri => Uri,
        arguments => args(Args),
        arguments_kw => args_kw(ArgsKw)
    }.


%% @private
args(undefined) -> [];
args(L) -> L.

%% @private
args_kw(undefined) -> #{};
args_kw(M) -> M.
