%% =============================================================================
%%  bondy_http_utils.erl -
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
-module(bondy_http_utils).
-include("bondy.hrl").

-export([client_ip/1]).
-export([real_ip/1]).
-export([real_peername/1]).
-export([forwarded_for/1]).
-export([set_meta_headers/1]).
-export([meta_headers/0]).




%% =============================================================================
%% API
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc Returns a binary representation of the IP or `<<"unknown">>'.
%% @end
%% -----------------------------------------------------------------------------
-spec client_ip(Req :: cowboy_req:req()) -> binary() | undefined.

client_ip(Req) ->
    case real_ip(Req) of
        undefined -> forwarded_for(Req);
        Value -> Value
    end.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec real_ip(cowboy_req:req()) -> binary() | undefined.

real_ip(Req) ->
    cowboy_req:header(<<"x-real-ip">>, Req, undefined).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec real_peername(cowboy_req:req()) -> maybe(peername()).

real_peername(Req) ->
    case maps:get(proxy_header, Req, #{}) of
        #{src_address := RealIP, src_port := RealPort} ->
            {RealIP, RealPort};
        _ ->
            undefined
    end.

%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec forwarded_for(cowboy_req:req()) -> binary() | undefined.

forwarded_for(Req) ->
    case cowboy_req:parse_header(<<"x-forwarded-for">>, Req, undefined) of
        [H|_] -> H;
        Val -> Val
    end.

%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec set_meta_headers(Req :: cowboy_req:req()) ->
    NewReq :: cowboy_req:req().

set_meta_headers(Req) ->
    cowboy_req:set_resp_headers(meta_headers(), Req).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec meta_headers() -> map().

meta_headers() ->
    case persistent_term:get({?MODULE, meta_headers}, undefined) of
        undefined ->
            Meta = #{
                <<"server">> => "bondy/" ++ bondy_config:get(vsn, "undefined")
            },
            _ = persistent_term:put({?MODULE, meta_headers}, Meta),
            Meta;
        Meta ->
            Meta
    end.