%% =============================================================================
%%  bondy_rpc_promise.erl -
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
-module(bondy_rpc_promise).
-include_lib("wamp/include/wamp.hrl").
-include("bondy.hrl").

-define(INVOCATION_QUEUE, bondy_rpc_promise).

-record(bondy_rpc_promise, {
    invocation_id                           ::  id(),
    procedure_uri                           ::  uri() | undefined,
    call_id                                 ::  id() | undefined,
    caller                                  ::  bondy_session:t(),
    callee                                  ::  bondy_session:t(),
    timestamp                               :: integer()
}).


-opaque t() :: #bondy_rpc_promise{}.
-type match_opts()      ::  #{
    id => id(),
    caller => bondy_session:t(),
    callee => bondy_session:t()
}.
-type dequeue_fun()     ::  fun((empty | {ok, t()}) -> any()).

-export_type([t/0]).
-export_type([match_opts/0]).
-export_type([dequeue_fun/0]).

-export([call_id/1]).
-export([callee/1]).
-export([caller/1]).
-export([dequeue_call/2]).
-export([dequeue_call/3]).
-export([dequeue_invocation/2]).
-export([dequeue_invocation/3]).
-export([enqueue/3]).
-export([flush/1]).
-export([invocation_id/1]).
-export([new/3]).
-export([new/5]).
-export([peek_call/2]).
-export([peek_invocation/2]).
-export([procedure_uri/1]).
-export([queue_size/0]).
-export([timestamp/1]).



%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc Creates a new promise for a remote invocation
%% @end
%% -----------------------------------------------------------------------------
-spec new(
    InvocationId :: id(),
    Callee :: bondy_session:t(),
    Ctxt :: bondy_context:t()) -> t().

new(InvocationId, Callee, Caller) ->
    #bondy_rpc_promise{
        invocation_id = InvocationId,
        caller = Caller,
        callee = Callee,
        timestamp = erlang:monotonic_time()
    }.


%% -----------------------------------------------------------------------------
%% @doc Creates a new promise for a local call - invocation
%% @end
%% -----------------------------------------------------------------------------
-spec new(
    InvocationId :: id(),
    CallId :: id(),
    ProcUri :: uri(),
    Callee :: bondy_session:t(),
    Ctxt :: bondy_context:t()) -> t().

new(InvocationId, CallId, ProcUri, Callee, Ctxt) ->
    #bondy_rpc_promise{
        invocation_id = InvocationId,
        procedure_uri = ProcUri,
        call_id = CallId,
        caller = bondy_context:session_ref(Ctxt),
        callee = Callee,
        timestamp = bondy_context:timestamp(Ctxt)
    }.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
invocation_id(#bondy_rpc_promise{invocation_id = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
call_id(#bondy_rpc_promise{call_id = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec callee(t()) -> bondy_session:t().

callee(#bondy_rpc_promise{callee = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec caller(t()) -> bondy_session:t().

caller(#bondy_rpc_promise{caller = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
procedure_uri(#bondy_rpc_promise{procedure_uri = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
timestamp(#bondy_rpc_promise{timestamp = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
enqueue(RealmUri, #bondy_rpc_promise{} = P, Timeout) ->
    InvocationId = P#bondy_rpc_promise.invocation_id,
    CallId = P#bondy_rpc_promise.call_id,
    SessionId = bondy_session:id(P#bondy_rpc_promise.caller),
    %% We match realm_uri for extra validation
    Key = key(RealmUri, P),
    OnEvict = fun(_) ->
        _ = lager:debug(
            "RPC Promise evicted from queue;"
            " realm_uri=~p, caller_session_id=~p, invocation_id=~p, call_id=~p"
            " timeout=~p",
            [RealmUri, SessionId, InvocationId, CallId, Timeout]
        )
    end,
    Secs = erlang:round(Timeout / 1000),
    Opts = #{key => Key, ttl => Secs, on_evict => OnEvict},
    tuplespace_queue:enqueue(?INVOCATION_QUEUE, P, Opts).


%% -----------------------------------------------------------------------------
%% @doc Dequeues the promise that matches the Id for the IdType in Ctxt.
%% @end
%% -----------------------------------------------------------------------------
-spec dequeue_call(CallId :: id(), Caller :: bondy_session:t()) ->
    empty | {ok, t()}.

dequeue_call(Id, Caller) ->
    dequeue_promise(call_key_pattern(Id, Caller)).


%% -----------------------------------------------------------------------------
%% @doc Dequeues the promise that matches the Id for the IdType in Ctxt.
%% @end
%% -----------------------------------------------------------------------------
-spec dequeue_call(CallId :: id(), Caller :: bondy_session:t(), Fun ::

dequeue_fun()) ->
    any().

dequeue_call(Id, Caller, Fun) ->
    dequeue_promise(call_key_pattern(Id, Caller), Fun).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec dequeue_invocation(CallId :: id(), Callee :: bondy_session:t()) ->
    empty | {ok, t()}.

dequeue_invocation(Id, Callee) ->
    dequeue_promise(invocation_key_pattern(Id, Callee)).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec dequeue_invocation(CallId :: id(), Callee :: bondy_session:t(),

dequeue_fun()) ->
    any().

dequeue_invocation(Id, Callee, Fun) ->
    dequeue_promise(invocation_key_pattern(Id, Callee), Fun).


%% -----------------------------------------------------------------------------
%% @doc Reads the promise that matches the Id for the IdType in Ctxt.
%% @end
%% -----------------------------------------------------------------------------
-spec peek_call(CallId :: id(), Caller :: bondy_session:t()) ->
    empty | {ok, t()}.

peek_call(CallId, Caller) ->
    peek_promise(call_key_pattern(CallId, Caller)).


%% -----------------------------------------------------------------------------
%% @doc Reads the promise that matches the Id for the IdType in Ctxt.
%% @end
%% -----------------------------------------------------------------------------
-spec peek_invocation(
    InvocationId :: id(), Callee :: bondy_session:t()) ->
    empty | {ok, t()}.

peek_invocation(InvocationId, Callee) ->
    peek_promise(invocation_key_pattern(InvocationId, Callee)).


%% -----------------------------------------------------------------------------
%% @doc Removes all pending promises from the queue for the peer's SessionId
%% @end
%% -----------------------------------------------------------------------------
-spec flush(bondy_session:t()) -> ok.

flush(Peer) ->
    %% This will match all promises for SessionId
    RealmUri = bondy_session:realm_uri(Peer),
    SessionId = bondy_session:id(Peer),

    %% Remove all entries as callee
    _ = tuplespace_queue:remove(
        ?INVOCATION_QUEUE, #{key => {RealmUri, {'_', SessionId}, '_'}}
    ),
    %% Remove all entries as caller
    _ = tuplespace_queue:remove(
        ?INVOCATION_QUEUE, #{key => {RealmUri, '_', {'_', SessionId}}}
    ),
    ok.


queue_size() ->
    tuplespace_queue:size(?INVOCATION_QUEUE).


%% =============================================================================
%% PRIVATE
%% =============================================================================


key(RealmUri, #bondy_rpc_promise{} = P) ->
    CallId = P#bondy_rpc_promise.call_id,
    InvocationId = P#bondy_rpc_promise.invocation_id,
    CallerSessionId = bondy_session:id(
        P#bondy_rpc_promise.caller
    ),
    CalleeSessionId = bondy_session:id(
        P#bondy_rpc_promise.callee
    ),

    {
        RealmUri,
        {InvocationId, CalleeSessionId},
        {CallId, CallerSessionId}
    }.


%% @private
call_key_pattern(CallId, Caller) ->
    RealmUri = bondy_session:realm_uri(Caller),
    SessionId = bondy_session:id(Caller),
    %% We exclude the pid from the match
    {RealmUri, '_', {CallId, SessionId}}.


%% @private
invocation_key_pattern(InvocationId, Callee) ->
    RealmUri = bondy_session:realm_uri(Callee),
    SessionId = bondy_session:id(Callee),
    %% We exclude the pid from the match
    {RealmUri, {InvocationId, SessionId}, '_'}.


%% @private
-spec dequeue_promise(tuple()) -> empty | {ok, t()}.

dequeue_promise(Key) ->
    Opts = #{key => Key},
    case tuplespace_queue:dequeue(?INVOCATION_QUEUE, Opts) of
        empty ->
            %% The promise might have expired so we GC it.
            %% case tuplespace_queue:remove(?INVOCATION_QUEUE, Opts) of
            %%     0 -> empty;
            %%     _ -> empty
            %% end;
            empty;
        [#bondy_rpc_promise{} = Promise] ->
            {ok, Promise}
    end.


%% @private
-spec dequeue_promise(tuple(), dequeue_fun()) -> any().

dequeue_promise(Key, Fun) when is_function(Fun, 1) ->
    Fun(dequeue_promise(Key)).


%% @private
-spec peek_promise(tuple()) -> {ok, t()} | empty.

peek_promise(Key) ->
    Opts = #{key => Key},
    case tuplespace_queue:peek(?INVOCATION_QUEUE, Opts) of
        empty ->
            empty;
        [#bondy_rpc_promise{} = P] ->
            {ok, P}
    end.