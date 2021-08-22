%% =============================================================================
%%  bondy_peer_message -
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
-module(bondy_peer_message).
-include("bondy.hrl").
-include_lib("wamp/include/wamp.hrl").

-record(bondy_peer_message, {
    id              ::  binary(),
    realm_uri       ::  uri(),
    %% Supporting process identifiers in Partisan, without changing the
    %% internal implementation of Erlang’s process identifiers, is not
    %% possible without allowing nodes to directly connect to every
    %% other node.
    %% We use the pid-to-bin trick since we will be using the pid to generate
    %% an ACK.
    %% TODO update this when we upgrade to latest plum_db (partisan 4.0)
    from            ::  bondy_session:ref(),
    to              ::  bondy_session:ref(),
    payload         ::  wamp_invocation()
                        | wamp_error()
                        | wamp_result()
                        | wamp_interrupt()
                        | wamp_publish(),
    hop_count = 0   ::  non_neg_integer(),
    options         ::  map()
}).


-opaque t()     ::  #bondy_peer_message{}.

-export_type([t/0]).


-export([from/1]).
-export([id/1]).
-export([is_message/1]).
-export([new/4]).
-export([peer_node/1]).
-export([options/1]).
-export([payload/1]).
-export([payload_type/1]).
-export([to/1]).
-export([realm_uri/1]).


%% =============================================================================
%% API
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% ----------------------------------------------------------------------------
new(From0, To0, Payload0, Opts) ->
    MyNode = bondy_peer_service:mynode(),
    element(2, To0) =/= MyNode orelse error(badarg),

    %% FromPid = bondy_utils:pid_to_bin(element(4, From0)),
    From = bondy_session:make_remote_ref(From0),

    %% ToPid = bondy_utils:pid_to_bin(element(4, To0)),
    To = bondy_session:make_remote_ref(To0),

    #bondy_peer_message{
        id = ksuid:gen_id(millisecond),
        to = To,
        from = From,
        payload = validate_payload(Payload0),
        options = Opts
    }.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
is_message(#bondy_peer_message{}) -> true;
is_message(_) -> false.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
id(#bondy_peer_message{id = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
realm_uri(#bondy_peer_message{from = Val}) -> element(1, Val).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
peer_node(#bondy_peer_message{to = Val}) -> element(2, Val).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
from(#bondy_peer_message{from = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
to(#bondy_peer_message{to = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
payload(#bondy_peer_message{payload = Val}) -> Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
payload_type(#bondy_peer_message{payload = Val}) -> element(1, Val).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
options(#bondy_peer_message{options = Val}) -> Val.



%% =============================================================================
%% PRIVATE
%% =============================================================================

validate_payload(#call{} = M) ->
    M;

validate_payload(#error{request_type = Type} = M)
when Type == ?CALL orelse Type == ?INVOCATION orelse Type == ?INTERRUPT ->
    M;

validate_payload(#interrupt{} = M) ->
    M;

validate_payload(#invocation{} = M) ->
    M;

validate_payload(#yield{} = M) ->
    M;

validate_payload(#publish{} = M) ->
    M;

validate_payload(M) ->
    error({badarg, [M]}).
