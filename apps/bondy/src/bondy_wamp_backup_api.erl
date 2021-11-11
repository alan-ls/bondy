%% =============================================================================
%%  bondy_wamp_backup_api.erl -
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
-module(bondy_wamp_backup_api).
-behaviour(bondy_wamp_api).

-include_lib("wamp/include/wamp.hrl").
-include("bondy.hrl").
-include("bondy_uris.hrl").

-export([handle_call/3]).



%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec handle_call(
    Proc :: uri(), M :: wamp_message:call(), Ctxt :: bony_context:t()) -> wamp_messsage:result() | wamp_message:error().


handle_call(?BONDY_BACKUP_CREATE, #call{} = M, Ctxt) ->
    [Info] = bondy_wamp_utils:validate_call_args(M, Ctxt, 1),
    bondy_wamp_utils:maybe_error(bondy_backup:backup(Info), M);

handle_call(?BONDY_BACKUP_STATUS, #call{} = M, Ctxt) ->
    [Info] = bondy_wamp_utils:validate_call_args(M, Ctxt, 1),
    bondy_wamp_utils:maybe_error(bondy_backup:status(Info), M);

handle_call(?BONDY_BACKUP_RESTORE, #call{} = M, Ctxt) ->
    [Info] = bondy_wamp_utils:validate_call_args(M, Ctxt, 1),
    bondy_wamp_utils:maybe_error(bondy_backup:restore(Info), M);

handle_call(_, #call{} = M, _) ->
    bondy_wamp_utils:no_such_procedure_error(M).