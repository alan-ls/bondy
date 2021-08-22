
%% =============================================================================
%%  bondy_context.erl -
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


%% =============================================================================
%% @doc The Bondy Context represents the current context of an interaction.
%% It contains references to information specific to the interaction, such as
%% the current WAMP peer, realm, current session, and current message.
%%
%% The Bondy Context is passed as an argument through the whole processing
%% handling flow of a WAMP message to provide access to that information.
%% @end
%% =============================================================================
-module(bondy_context).
-include("bondy.hrl").
-include_lib("wamp/include/wamp.hrl").


-type t()       ::  #{
    session := bondy_session:t(),
    session_ref := bondy_session:ref(),
    timestamp => integer(),
    user_info => map()
}.
-export_type([t/0]).


-export([authorize/3]).
-export([encoding/1]).
-export([get/2]).
-export([has_session/1]).
-export([is_feature_enabled/3]).
-export([new/1]).
-export([node/1]).
-export([session_ref/1]).
-export([realm_uri/1]).
-export([session/1]).
-export([session_id/1]).
-export([set/3]).
-export([timestamp/1]).


-export([local_context/1]).
-export([new/0]).
-export([reply/2]).





%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% Initialises a new context.
%% @end
%% -----------------------------------------------------------------------------
-spec new() -> t().

new() ->
    #{
        timestamp => erlang:monotonic_time()
    }.


%% -----------------------------------------------------------------------------
%% @doc
%% Initialises a new context.
%% @end
%% -----------------------------------------------------------------------------
-spec new(bondy_session:t()) -> t().

new(Session) ->
    #{
        id => bondy_utils:trace_id(),
        session => Session,
        session_ref => bondy_session:make_ref(Session),
        timestamp => erlang:monotonic_time()
    }.

%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
local_context(RealmUri) when is_binary(RealmUri) ->
    Ctxt = new(),
    Ctxt#{realm_uri => RealmUri}.


%% -----------------------------------------------------------------------------
%% @doc
%% Returns true if the context is associated with a session,
%% false otherwise.
%% @end
%% -----------------------------------------------------------------------------
-spec has_session(t()) -> boolean().
has_session(#{session := _}) -> true;
has_session(#{}) -> false.


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the sessionId of the provided context or 'undefined'
%% if there is none.
%% @end
%% -----------------------------------------------------------------------------
-spec session_id(t()) -> maybe(id()).
session_id(#{session := S}) ->
    bondy_session:id(S);

session_id(#{}) ->
    undefined.


%% -----------------------------------------------------------------------------
%% @doc
%% Fetches and returns the bondy_session for the associated sessionId.
%% @end
%% -----------------------------------------------------------------------------
-spec session(t()) -> bondy_session:t() | no_return().

session(#{session := S}) ->
    S.
%% Returns the realm uri of the provided context.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec realm_uri(t()) -> uri().

realm_uri(#{realm_uri := Uri}) ->
    %% A local context
    Uri;

realm_uri(#{session := S}) ->
    bondy_session:realm_uri(S).


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the encoding used by the peer of the provided context.
%% @end
%% -----------------------------------------------------------------------------
-spec encoding(t()) -> encoding().
encoding(#{session := S}) ->

    bondy_session:encoding(S);
encoding(#{}) ->


%% -----------------------------------------------------------------------------
%% @doc
%% Set the peer to the provided context.
%% @end
%% -----------------------------------------------------------------------------
-spec set_subprotocol(t(), subprotocol_2()) -> t().
set_subprotocol(Ctxt, {_, _, _} = S) when is_map(Ctxt) ->
    Ctxt#{subprotocol => S}.


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the roles of the provided context.
%% @end
%% -----------------------------------------------------------------------------
-spec roles(t()) -> map().
roles(Ctxt) ->
    bondy_session:roles(session(Ctxt)).


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the realm uri of the provided context.
%% @end
%% -----------------------------------------------------------------------------
-spec realm_uri(t()) -> maybe(uri()).
realm_uri(#{realm_uri := Val}) -> Val;
realm_uri(_) -> undefined.


%% -----------------------------------------------------------------------------
%% @doc
%% Sets the realm uri of the provided context.
%% @end
%% -----------------------------------------------------------------------------
-spec set_realm_uri(t(), uri()) -> t().
set_realm_uri(Ctxt, Uri) ->
    Ctxt#{realm_uri => Uri}.


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the agent of the provided context or 'undefined'
%% if there is none.
%% @end
%% -----------------------------------------------------------------------------
-spec agent(t()) -> binary() | undefined.

agent(#{session := S}) ->
    bondy_session:agent(S);

agent(#{}) ->
    undefined.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec session_ref(t()) -> bondy_session:t().

is_security_enabled(#{session := Session}) when Session =/= undefined ->
    bondy_session:is_security_enabled(Session);

session_ref(#{session_ref := Val}) ->
    Val;

session_ref(#{session := S}) ->
    bondy_session:session_ref(S).



%% -----------------------------------------------------------------------------
%% @doc
%% Returns the peer of the provided context.
%% @end
%% -----------------------------------------------------------------------------
-spec node(t()) -> atom().
node(#{session := S}) ->
    bondy_session:node(S);

node(#{}) ->
    undefined.


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the current request timestamp.
%% @end
%% -----------------------------------------------------------------------------
-spec timestamp(t()) -> integer().

timestamp(#{timestamp := Val}) ->
    Val.


%% -----------------------------------------------------------------------------
%% @doc Returns true if the feature Feature is enabled for role Role.
%% %% See {@link bondy_session:is_feature_enabled/3}.
%% @end
%% -----------------------------------------------------------------------------
-spec is_feature_enabled(t(), atom(), binary()) -> boolean().

is_feature_enabled(Role, Feature, #{session := Session}) ->
    bondy_session:is_feature_enabled(Role, Feature, Session).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec get(Key :: any(), Ctxt :: t()) -> maybe(any()).
get(Key, #{user_info := Map}) ->

    maps:get(Key, Map, undefined).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec set(Key :: any(), Value :: any(), Ctxt :: t()) -> NewCtxt :: t().

set(Key, Value, #{user_info := Map} = Ctxt) ->
    maps:put(user_info, maps:put(Key, Value, Map), Ctxt).


%% -----------------------------------------------------------------------------
%% @doc Returns 'ok' or an exception.
%% See {@link bondy_session:authorize/3}.
%% @end
%% -----------------------------------------------------------------------------
-spec authorize(
    Permission :: binary(), Resource :: binary(), Context :: t()) ->
    ok | no_return().

authorize(Permission, Resource, #{session := Session}) ->
    bondy_session:authorize(Permission, Resource, Session).


%% -----------------------------------------------------------------------------
%% @doc
%% %% See {@link bondy_session:send/2}.
%% @end
%% -----------------------------------------------------------------------------
-spec reply(wamp_message(), t()) -> ok | no_return().

reply(Message, Ctxt) ->
    bondy:send(session_ref(Ctxt), Message).

