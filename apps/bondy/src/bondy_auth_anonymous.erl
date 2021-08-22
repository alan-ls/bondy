%% =============================================================================
%%  bondy_auth_anonymous.erl -
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
%% @doc This module implements the {@link bondy_auth} behaviour to allow access
%% to clients which connect without credentials assigning them the 'anonymous'
%% group.
%% @end
%% -----------------------------------------------------------------------------
-module(bondy_auth_anonymous).
-behaviour(bondy_auth).

-include("bondy_security.hrl").

-type state() :: #{
    id := binary() | undefined,
    role := binary(),
    roles := [binary()],
    ip_address := inet:ip_address()
}.

%% BONDY_AUTH CALLBACKS
-export([init/1]).
-export([requirements/0]).
-export([challenge/3]).
-export([authenticate/4]).



%% =============================================================================
%% BONDY_AUTH CALLBACKS
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% @throws invalid_context
%% @end
%% -----------------------------------------------------------------------------
-spec init(bondy_auth:context()) ->
    {ok, State :: state()} | {error, Reason :: any()}.

init(Ctxt) ->
    try
        bondy_auth:is_anonymous(Ctxt) orelse throw(invalid_context),
        {ok, state(Ctxt)}
    catch
        throw:Reason ->
            {error, Reason}
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec requirements() -> map().

requirements() ->
    #{
        identification => false,
        password => false,
        authorized_keys => false
    }.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec challenge(
    Details :: map(), AuthCtxt :: bondy_auth:context(), State :: state()) ->
    {ok, NewState :: state()}
    | {error, Reason :: any(), NewState :: state()}.

challenge(_, _, State) ->
    {ok, State}.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec authenticate(
    Signature :: binary(),
    DataIn :: map(),
    Ctxt :: bondy_auth:context(),
    CBState :: state()) ->
    {ok, DataOut :: map(), CBState :: state()}
    | {error, Reason :: any(), CBState :: state()}.

authenticate(_, _, Ctxt, State) ->
    %% We validate the ctxt has not changed between init and authenticate calls
    case State == state(Ctxt) of
        true ->
            {ok, #{}, State};
        false ->
            {error, invalid_context, State}
    end.



%% =============================================================================
%% PRIVATE
%% =============================================================================



%% @private
state(Ctxt) ->
    #{
        id => bondy_auth:id(Ctxt),
        ip_address => bondy_auth:ip_address(Ctxt),
        role => bondy_auth:role(Ctxt),
        roles => bondy_auth:roles(Ctxt)
    }.





