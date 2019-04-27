%% =============================================================================
%%  bondy_api_gateway_handler.erl -
%%
%%  Copyright (c) 2016-2019 Ngineo Limited t/a Leapsight. All rights reserved.
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
%% This module implements a generic Cowboy rest handler that handles a resource
%% specified using the Bondy API Gateway Specification Format (BAGS),
%% a JSON-based format for describing, producing and consuming
%% RESTful Web Services using Bondy.
%%
%% For every path defined in a BAGS file, Bondy will configure and install a
%% Cowboy route using this module. The initial state of the module responds to
%% a contract between this module and the {@link bondy_api_gateway_spec_parser}
%% and contains the parsed and preprocessed definition of the paths
%% specification which this module uses to dynamically implement its behaviour.
%%
%% See {@link bondy_api_gateway} for a detail description of the
%% Bondy API Gateway Specification Format.
%% @end
%% -----------------------------------------------------------------------------
-module(bondy_api_gateway_handler).
-include("bondy.hrl").
-include("bondy_api_gateway.hrl").
-include_lib("wamp/include/wamp.hrl").

-type state() :: #{
    api_spec => map(),
    api_context => map(),
    body_evaluated => boolean(),
    session => any(),
    realm_uri => binary(),
    deprecated => boolean(),
    security => map(),
    encoding => binary() | json | msgpack
}.


-export([accept/2]).
-export([allowed_methods/2]).
-export([content_types_accepted/2]).
-export([content_types_provided/2]).
-export([delete_completed/2]).
-export([delete_resource/2]).
-export([from_form_urlencoded/2]).
-export([from_json/2]).
-export([from_msgpack/2]).
-export([init/2]).
-export([is_authorized/2]).
-export([languages_provided/2]).
-export([options/2]).
-export([previously_existed/2]).
-export([provide/2]).
-export([rate_limited/2]).
-export([resource_exists/2]).
-export([to_json/2]).
-export([to_msgpack/2]).





%% =============================================================================
%% API
%% =============================================================================



init(Req, St0) ->
    Session = undefined, %TODO
    % SessionId = 1,
    % Ctxt0 = bondy_context:set_peer(
    %     bondy_context:new(), cowboy_req:peer(Req)),
    % Ctxt1 = bondy_context:set_session_id(SessionId, Ctxt0),
    St1 = St0#{
        body_evaluated => false,
        api_context => init_context(Req),
        session => Session,
        encoding => undefined
    },
    {cowboy_rest, Req, St1}.


allowed_methods(Req, #{api_spec := Spec} = St) ->
    {maps:get(<<"allowed_methods">>, Spec), Req, St}.


languages_provided(Req, #{languages := L} = St) ->
    {L, Req, St}.


content_types_accepted(Req, #{api_spec := Spec} = St) ->
    {maps:get(<<"content_types_accepted">>, Spec), Req, St}.


content_types_provided(Req, #{api_spec := Spec} = St) ->
    {maps:get(<<"content_types_provided">>, Spec), Req, St}.


options(Req, #{api_spec := Spec} = St) ->
    Allowed = iolist_to_binary(
        lists:join(<<$,>>, maps:get(<<"allowed_methods">>, Spec))
    ),
    Headers0 = eval_headers(Req, St),
    Headers1 = case maps:find(<<"access-control-allow-methods">>, Headers0) of
        {ok, _V} ->
            maps:put(<<"access-control-allow-methods">>, Allowed, Headers0);
        error ->
            Headers0
    end,
    Headers2 = maps:put(<<"allow">>, Allowed, Headers1),
    {ok, cowboy_req:set_resp_headers(Headers2, Req), St}.


is_authorized(Req0, St) ->
    try
        Realm = bondy_realm:fetch(maps:get(realm_uri, St)),
        RealmUri = bondy_realm:uri(Realm),
        case cowboy_req:method(Req0) of
            <<"OPTIONS">> -> {true, Req0, St};
            _ -> do_is_authorised(Req0, RealmUri, St)
        end
    catch
        ?EXCEPTION(error, no_such_realm = Reason, _) ->
            {StatusCode, Body} = take_status_code(bondy_error:map(Reason), 500),
            Response = #{<<"body">> => Body, <<"headers">> => #{}},
            Req1 = reply(StatusCode, json, Response, Req0),
            {stop, Req1, St};
        ?EXCEPTION(Class, Reason, Stacktrace) ->
            _ = log(
                error,
                "type=~p, reason=~p, stacktrace=~p",
                [Class, Reason, ?STACKTRACE(Stacktrace)],
                St
            ),
            {StatusCode, Body} = take_status_code(bondy_error:map(Reason), 500),
            Response = #{<<"body">> => Body, <<"headers">> => #{}},
            Req1 = reply(StatusCode, json, Response, Req0),
            {stop, Req1, St}
    end.


rate_limited(Req, St) ->
    %% Result :: false | {true, RetryAfter}
    {false, Req, St}.


resource_exists(Req, #{api_spec := Spec} = St) ->
    IsCollection = maps:get(<<"is_collection">>, Spec, false),
    Method = cowboy_req:method(Req),
    Resp = case {IsCollection, Method} of
        {true, <<"POST">>} ->
            %% A collection resource always exists.
            %% However, during a POST the check should be considered to
            %% refer to the resource that is about to be created and added
            %% to the collection, and not the collection itself.
            %% This allows Cowboy to return `201 Created` instead of `200 OK`.
            false;
        {true, _} ->
            %% A collection resource always exists.
            true;
        {false, _} ->
            %% TODO We should check for real here, but we carry on and let
            %% the underlying action to actually reply with a 404
            true
    end,
    {Resp, Req, St}.


previously_existed(Req, St) ->
    %% TODO
    {false, Req, St}.

delete_resource(Req0, #{api_spec := Spec} = St0) ->
    Method = method(Req0),
    Enc = json,
    St1 = St0#{encoding => Enc}, % TODO get this by parsing headers
    case perform_action(Method, maps:get(Method, Spec), St1) of
        {ok, Response, St2} ->
            Headers = maps:get(<<"headers">>, Response),
            Req1 = cowboy_req:set_resp_headers(Headers, Req0),
            {true, Req1, St2};

        {ok, StatusCode, Response, St2} ->
            Req1 = reply(StatusCode, Enc, Response, Req0),
            {stop, Req1, St2};

        {error, Response0, St2} ->
            {StatusCode, Response1} = take_status_code(Response0, 500),
            Req1 = reply(StatusCode, error_encoding(Enc), Response1, Req0),
            {stop, Req1, St2};

        {error, StatusCode, Response, St2} ->
            Req1 = reply(StatusCode, error_encoding(Enc), Response, Req0),
            {stop, Req1, St2}
    end.




delete_completed(Req, St) ->
    %% Called after delete_resource
    %% We asume deletes are final and synchronous
    {true, Req, St}.


to_json(Req, St) ->
    provide(Req, St#{encoding => json}).


to_msgpack(Req, St) ->
    provide(Req, St#{encoding => msgpack}).


from_json(Req, St) ->
    do_accept(Req, St#{encoding => json}).


from_msgpack(Req, St) ->
    do_accept(Req, St#{encoding => msgpack}).


from_form_urlencoded(Req, St) ->
    do_accept(Req, St#{encoding => urlencoded}).


accept(Req0, St0) ->
    %% Encoding is not JSON, MSGPACK or URLEncoded
    ContentType = cowboy_req:header(<<"content-type">>, Req0),
    do_accept(Req0, St0#{encoding => ContentType}).


%% =============================================================================
%% PRIVATE
%% =============================================================================

%% @private
do_is_authorised(
    Req0, Realm, #{security := #{<<"type">> := <<"oauth2">>}} = St0) ->
    %% TODO get auth method and status from St and validate
    %% check scopes vs action requirements
    Val = cowboy_req:parse_header(<<"authorization">>, Req0),
    Peer = cowboy_req:peer(Req0),
    case bondy_security_utils:authenticate(bearer, Val, Realm, Peer) of
        {ok, Claims} when is_map(Claims) ->
            %% The token claims
            Ctxt = update_context(
                {security, Claims}, maps:get(api_context, St0)),
            St1 = maps:update(api_context, Ctxt, St0),
            {true, Req0, St1};
        {ok, AuthCtxt} ->
            %% TODO Here we need the token or the session with the
            %% token grants and not the AuthCtxt
            St1 = St0#{
                user_id => ?CHARS2BIN(bondy_security:get_username(AuthCtxt))
            },
            %% TODO update context
            {true, Req0, St1};
        {error, no_such_realm} ->
            {_, ErrorMap} = take_status_code(bondy_error:map(no_such_realm)),
            Response = #{
                <<"body">> => ErrorMap,
                <<"headers">> => eval_headers(Req0, St0)
            },
            Req2 = reply(401, json, Response, Req0),
            {stop, Req2, St0};
        {error, Reason} ->
            Req1 = cowboy_req:set_resp_headers(eval_headers(Req0, St0), Req0),
            Req2 = reply_auth_error(
                Reason, <<"Bearer">>, Realm, json, Req1),
            {stop, Req2, St0}
    end;

do_is_authorised(Req, _, #{security := #{<<"type">> := <<"api_key">>}} = St) ->
    %% TODO get auth method and status from St and validate
    %% check scopes vs action requirements
    {true, Req, St};

do_is_authorised(Req, _, #{security := _} = St)  ->
    {true, Req, St}.


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% Provides the resource representation for a GET or HEAD
%% executing the configured action
%% @end
%% -----------------------------------------------------------------------------
provide(Req0, #{api_spec := Spec, encoding := Enc} = St0)  ->
    Method = method(Req0),
    try perform_action(Method, maps:get(Method, Spec), St0) of
        {ok, Response, St1} ->
            #{
                <<"body">> := Body,
                <<"headers">> := Headers
            } = Response,
            Req1 = cowboy_req:set_resp_headers(Headers, Req0),
            {maybe_encode(Enc, Body, Spec), Req1, St1};

        {ok, StatusCode, Response, St1} ->
            Req1 = reply(StatusCode, Enc, Response, Req0),
            {stop, Req1, St1};

        {error, Response0, St1} ->
            {StatusCode, Response1} = take_status_code(Response0, 500),
            Req1 = reply(StatusCode, error_encoding(Enc), Response1, Req0),
            {stop, Req1, St1};

        {error, StatusCode, Response, St1} ->
            Req1 = reply(StatusCode, error_encoding(Enc), Response, Req0),
            {stop, Req1, St1}
    catch
        ?EXCEPTION(throw, Reason, _) ->
            {StatusCode, Body} = take_status_code(bondy_error:map(Reason), 500),
            Response = #{<<"body">> => Body, <<"headers">> => #{}},
            Req1 = reply(StatusCode, error_encoding(Enc), Response, Req0),
            {stop, Req1, St0};
        ?EXCEPTION(Class, Reason, Stacktrace) ->
            _ = log(
                error,
                "type=~p, reason=~p, stacktrace=~p",
                [Class, Reason, ?STACKTRACE(Stacktrace)],
                St0
            ),
            {StatusCode, Body} = take_status_code(bondy_error:map(Reason), 500),
            Response = #{<<"body">> => Body, <<"headers">> => #{}},
            Req1 = reply(StatusCode, error_encoding(Enc), Response, Req0),
            {stop, Req1, St0}
    end.





%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% Accepts a POST, PATCH, PUT or DELETE over a resource by executing
%% the configured action
%% @end
%% -----------------------------------------------------------------------------
do_accept(Req0, #{api_spec := Spec, encoding := Enc} = St0) ->

    Method = method(Req0),
    try
        %% We now read the body from the request into the context
        {ok, Req1, St1} = read_body(Req0, St0),
        case perform_action(Method, maps:get(Method, Spec), St1) of
            {ok, Response, St2} ->
                Req2 = prepare_request(Enc, Response, Req1),
                {maybe_location(Method, Response), Req2, St2};

            {ok, HTTPCode, Response, St2} ->
                {stop, reply(HTTPCode, Enc, Response, Req1), St2};

            {error, Response0, St2} ->
                {HTTPCode, Response1} = take_status_code(Response0, 500),
                Req2 = reply(HTTPCode, error_encoding(Enc), Response1, Req1),
                {stop, Req2, St2};

            {error, HTTPCode, Response, St2} ->
                {stop, reply(HTTPCode, error_encoding(Enc), Response, Req1), St2}
        end
    catch
        ?EXCEPTION(throw, Reason, _) ->
            {StatusCode1, Body} = take_status_code(
                bondy_error:map(Reason), 400),
            ErrResp = #{ <<"body">> => Body, <<"headers">> => #{}},
            Req = reply(StatusCode1, error_encoding(Enc), ErrResp, Req0),
            {stop, Req, St0};
        ?EXCEPTION(Class, Reason, Stacktrace) ->
            _ = log(
                error,
                "type=~p, reason=~p, stacktrace=~p",
                [Class, Reason, ?STACKTRACE(Stacktrace)],
                St0
            ),
            {StatusCode1, Body} = take_status_code(
                bondy_error:map(Reason), 500),
            ErrResp = #{ <<"body">> => Body, <<"headers">> => #{}},
            Req = reply(StatusCode1, error_encoding(Enc), ErrResp, Req0),
            {stop, Req, St0}
    end.





%% =============================================================================
%% PRIVATE
%% =============================================================================


take_status_code(Term) ->
    take_status_code(Term, 500).


%% @private
-spec take_status_code(map(), pos_integer()) -> {pos_integer(), map()}.

take_status_code(#{<<"status_code">> := _} = Map, _) ->
    maps:take(<<"status_code">>, Map);

take_status_code(#{<<"body">> := Body0} = Map, Default) ->
    {HTTStatus, Body1} =  take_status_code(Body0, Default),
    {HTTStatus, Map#{<<"body">> => Body1}};

take_status_code(ErrorBody, Default) ->
    case maps:take(<<"status_code">>, ErrorBody) of
        error ->
            StatusCode = case maps:find(<<"code">>, ErrorBody) of
                {ok, Val} ->
                    uri_to_status_code(Val);
                _ ->
                    Default
            end,
            {StatusCode, ErrorBody};
        Res ->
            Res
    end.

%% -----------------------------------------------------------------------------
%% @doc
%% Creates a context object based on the passed Request
%% (`cowboy_request:request()').
%% @end
%% -----------------------------------------------------------------------------
-spec update_context(tuple(), map()) -> map().

update_context({error, Map}, #{<<"request">> := _} = Ctxt) when is_map(Map) ->
    maps_utils:put_path([<<"action">>, <<"error">>], Map, Ctxt);

update_context({result, Result}, #{<<"request">> := _} = Ctxt) ->
    maps_utils:put_path([<<"action">>, <<"result">>], Result, Ctxt);

update_context({security, Claims}, #{<<"request">> := Req} = Ctxt) ->
    Map = #{
        <<"realm_uri">> => maps:get(<<"aud">>, Claims),
        <<"session">> => maps:get(<<"id">>, Claims),
        <<"client_id">> => maps:get(<<"iss">>, Claims),
        <<"username">> => maps:get(<<"sub">>, Claims),
        <<"authmethod">> => <<"oauth2">>, %% Todo get this dynamically
        <<"groups">> => maps:get(<<"groups">>, Claims),
        <<"locale">> => maps:get(<<"language">>, Req),
        <<"meta">> => maps:get(<<"meta">>, Claims)
    },
    maps:put(<<"security">>, Map, Ctxt);

update_context({body, Body}, #{<<"request">> := _} = Ctxt0) ->
    Ctxt1 = maps_utils:put_path([<<"request">>, <<"body">>], Body, Ctxt0),
    maps_utils:put_path(
        [<<"request">>, <<"body_length">>], byte_size(Body), Ctxt1).


init_context(Req) ->
    Peer = cowboy_req:peer(Req),
    Id = opencensus:generate_trace_id(),

    M = #{
        %% Msgpack does not support 128-bit integers,
        %% so for the time being we encod it as binary string
        <<"id">> => integer_to_binary(Id),
        <<"method">> => method(Req),
        <<"scheme">> => cowboy_req:scheme(Req),
        <<"peer">> => Peer,
        <<"peername">> => inet_utils:peername_to_binary(Peer),
        <<"path">> => trim_trailing_slash(cowboy_req:path(Req)),
        <<"host">> => cowboy_req:host(Req),
        <<"port">> => cowboy_req:port(Req),
        <<"headers">> => cowboy_req:headers(Req),
        <<"language">> => maps:get(language, Req, <<"en">>),
        <<"query_string">> => cowboy_req:qs(Req),
        <<"query_params">> => maps:from_list(cowboy_req:parse_qs(Req)),
        <<"bindings">> => bondy_utils:to_binary_keys(cowboy_req:bindings(Req)),
        <<"body">> => <<>>,
        <<"body_length">> => 0
    },
    maps:put(<<"request">>, M, #{}).


%% is_multipart_form_body(Req) ->
%%     case cowboy_req:parse_header(<<"content-type">>, Req) of
%%         {<<"multipart">>, <<"form-data">>, _} ->
%%             true;
%%         _ ->
%%             false
%%     end.



%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% By default, Cowboy will attempt to read up to 8MB of data, for up to 15
%% seconds. The call will return once Cowboy has read at least 8MB of data, or
%% at the end of the 15 seconds period.
%% We get the path's body_max_bytes, body_read_bytes and body_read_seconds
%% attributes to configure the cowboy_req's length and period options and also
%% setup a total max length.
%% @end
%% -----------------------------------------------------------------------------
-spec read_body(cowboy_req:request(), state()) ->
    {ok, cowboy_req:request(), state()} | no_return().

read_body(Req, St) ->
    read_body(Req, St, <<>>).


%% @private
read_body(Req0, #{api_spec := Spec, api_context := Ctxt0} = St0, Acc) ->
    MSpec = maps:get(method(Req0), Spec),
    Opts = #{
        length => maps:get(<<"body_read_bytes">>, MSpec),
        period => maps:get(<<"body_read_seconds">>, MSpec)
    },
    MaxLen = maps:get(<<"body_max_bytes">>, MSpec),

    case cowboy_req:read_body(Req0, Opts) of
        {_, Data, _Req1} when byte_size(Data) > MaxLen - byte_size(Acc) ->
            throw({badarg, {body_max_bytes_exceeded, MaxLen}});
        {ok, Data, Req1} ->
            %% @TODO Stream Body in the future using WAMP Progressive Calls
            %% The API Spec will need a way to tell me you want to stream
            Body = <<Acc/binary, Data/binary>>,
            Ctxt1 = update_context({body, Body}, Ctxt0),
            St1 = St0#{
                body_evaluated => true,
                api_context => Ctxt1
            },
            {ok, Req1, St1};
        {more, Data, Req1} ->
            read_body(Req1, St0, <<Acc/binary, Data/binary>>)
    end.


%% @private
decode_body_in_context(Method, St)
when Method =:= <<"post">>
orelse Method =:= <<"patch">>
orelse Method =:= <<"put">> ->
    Ctxt = maps:get(api_context, St),
    Path = [<<"request">>, <<"body">>],
    Bin = maps_utils:get_path(Path, Ctxt),
    Enc = maps:get(encoding, St),
    try
        Body = bondy_utils:decode(Enc, Bin),
        maps:update(api_context, maps_utils:put_path(Path, Body, Ctxt), St)
    catch
        ?EXCEPTION(Class, Reason, Stacktrace) ->
            _ = log(
                error,
                "Error while decoding HTTP body, "
                "type=~p, reason=~p, stacktrace=~p",
                [Class, Reason, ?STACKTRACE(Stacktrace)],
                St
            ),
            throw({badarg, {decoding, Enc}})
    end;

decode_body_in_context(_, #{api_context := Ctxt} = St) ->
    Path = [<<"request">>, <<"body">>],
    maps:update(api_context, maps_utils:put_path(Path, <<>>, Ctxt), St).



%% @private
-spec perform_action(binary(), map(), state()) ->
    {ok, Response :: any(), state()}
    | {ok, Code :: integer(), Response :: any(), state()}
    | {error, Response :: map(), state()}
    | {error, Code :: integer(), Response :: any(), state()}.

perform_action(
    Method, #{<<"action">> := #{<<"type">> := <<"static">>}} = Spec, St0) ->
    St1 = decode_body_in_context(Method, St0),
    Ctxt0 = maps:get(api_context, St1),
    %% We get the response directly as it should be statically defined
    Result = maps_utils:get_path([<<"response">>, <<"on_result">>], Spec),
    Response = mops_eval(Result, Ctxt0),
    St2 = maps:update(api_context, Ctxt0, St1),
    {ok, Response, St2};

perform_action(
    Method0,
    #{<<"action">> := #{<<"type">> := <<"forward">>} = Act} = Spec,
    St0) ->
    %% At the moment we just do not decode it and asume upstream accepts
    %% the same type
    Ctxt0 = maps:get(api_context, St0),
    %% Arguments might be funs waiting for the
    %% request.* values to be bound
    %% so we need to evaluate them passing the
    %% context
    #{
        <<"host">> := Host,
        <<"path">> := Path,
        <<"query_string">> := QS,
        <<"headers">> := Headers,
        <<"timeout">> := T,
        <<"connect_timeout">> := CT,
        % <<"retries">> := R,
        % <<"retry_timeout">> := RT,
        <<"body">> := Body
    } = Act1 = mops_eval(Act, Ctxt0),


    Opts = [
        {connect_timeout, CT},
        {recv_timeout, T}
    ],
    Url = url(Host, Path, QS),
    _ = log(
        info,
        "Gateway is forwarding request to upstream host, "
        "upstream_url=~p, headers=~p, body=~p, opts=~p",
        [Url, Headers, Body, Opts],
        St0
    ),
    RSpec = maps:get(<<"response">>, Spec),

    AtomMethod = method_to_atom(maps:get(<<"http_method">>, Act1, Method0)),

    case
        hackney:request(AtomMethod, Url, maps:to_list(Headers), Body, Opts)
    of
        {ok, StatusCode, RespHeaders} when AtomMethod =:= head ->
            from_http_response(StatusCode, RespHeaders, <<>>, RSpec, St0);

        {ok, StatusCode, RespHeaders, ClientRef} ->
            {ok, RespBody} = hackney:body(ClientRef),
            from_http_response(StatusCode, RespHeaders, RespBody, RSpec, St0);

        {error, Reason} ->
            Error = #{
                <<"code">> => ?BONDY_BAD_GATEWAY_ERROR,
                <<"message">> => <<"Error while connecting with upstream URL '", Url/binary, "'.">>,
                <<"description">> => Reason %% TODO convert to string
            },
            throw(Error)
    end;

perform_action(
    Method,
    #{<<"action">> := #{<<"type">> := <<"wamp_call">>} = Act} = Spec, St0) ->
    St1 = decode_body_in_context(Method, St0),
    Ctxt0 = maps:get(api_context, St1),
    %% Arguments might be funs waiting for the
    %% request.* values to be bound
    %% so we need to evaluate them passing the context
    #{
        <<"procedure">> := P,
        <<"arguments">> := A,
        <<"arguments_kw">> := Akw,
        <<"options">> := Opts,
        <<"retries">> := _R,
        <<"timeout">> := T
    } = mops_eval(Act, Ctxt0),
    RSpec = maps:get(<<"response">>, Spec),

    %% @TODO We need to recreate ctxt and session from token
    Peer = maps_utils:get_path([<<"request">>, <<"peer">>], Ctxt0),
    RealmUri = maps:get(realm_uri, St1),
    WampCtxt0 = #{
        peer => Peer,
        node => bondy_peer_service:mynode(),
        subprotocol => {http, text, maps:get(encoding, St0)},
        realm_uri => RealmUri,
        timeout => T,
        session => bondy_session:new(Peer, RealmUri, #{
            roles => #{
                caller => #{
                    features => #{
                        call_timeout => true,
                        call_canceling => false,
                        caller_identification => true,
                        call_trustlevels => true,
                        progressive_call_results => false
                    }
                }
            }
        })
    },

    case bondy:call(P, Opts, A, Akw, WampCtxt0) of
        {ok, Result0, _WampCtxt1} ->
            %% mops uses binary keys
            Result1 = bondy_utils:to_binary_keys(Result0),
            Ctxt1 = update_context({result, Result1}, Ctxt0),
            Response = mops_eval(
                maps:get(<<"on_result">>, RSpec), Ctxt1),
            St2 = maps:update(api_context, Ctxt1, St1),
            {ok, Response, St2};
        {error, WampError0, _WampCtxt1} ->
            StatusCode0 = uri_to_status_code(maps:get(error_uri, WampError0)),
            WampError1 = bondy_utils:to_binary_keys(WampError0),
            Error = maps:put(<<"status_code">>, StatusCode0, WampError1),
            Ctxt1 = update_context({error, Error}, Ctxt0),
            Response0 = mops_eval(maps:get(<<"on_error">>, RSpec), Ctxt1),
            St2 = maps:update(api_context, Ctxt1, St1),
            {StatusCode1, Response1} = take_status_code(Response0, 500),
            {error, StatusCode1, Response1, St2}
    end.



%% @private
from_http_response(StatusCode, RespHeaders, RespBody, Spec, St0)
when StatusCode >= 400 andalso StatusCode < 600->
    Ctxt0 = maps:get(api_context, St0),
    Error = #{
        <<"status_code">> => StatusCode,
        <<"body">> => RespBody,
        <<"headers">> => RespHeaders
    },
    Ctxt1 = update_context({error, Error}, Ctxt0),
    Response0 = mops_eval(maps:get(<<"on_error">>, Spec), Ctxt1),
    St1 = maps:update(api_context, Ctxt1, St0),
    {FinalCode, Response1} = take_status_code(Response0),
    {error, FinalCode, Response1, St1};

from_http_response(StatusCode0, RespHeaders, RespBody, Spec, St0) ->
    Ctxt0 = maps:get(api_context, St0),
    % HeadersMap = maps:with(?HEADERS, maps:from_list(RespHeaders)),
    Result0 = #{
        <<"status_code">> => StatusCode0,
        <<"body">> => RespBody,
        <<"headers">> => RespHeaders
    },
    Result1 = case lists:keyfind(<<"Location">>, 1, RespHeaders) of
        {_, Uri} ->
            maps:put(<<"uri">>, Uri, Result0);
        _ ->
            maps:put(<<"uri">>, <<>>, Result0)
    end,
    Ctxt1 = update_context({result, Result1}, Ctxt0),
    Response0 = mops_eval(maps:get(<<"on_result">>, Spec), Ctxt1),
    St1 = maps:update(api_context, Ctxt1, St0),
    {StatusCode1, Response1} = take_status_code(Response0),
    {ok, StatusCode1, Response1, St1}.


reply_auth_error(Error, Scheme, Realm, Enc, Req) ->
    {_, Body} = take_status_code(bondy_error:map(Error)),
    Code = maps:get(<<"code">>, Body, <<>>),
    Msg = maps:get(<<"message">>, Body, <<>>),
    Desc = maps:get(<<"description">>, Body, <<>>),
    Auth = <<
        Scheme/binary,
        " realm=", $", Realm/binary, $", $\,,
        " error=", $", Code/binary, $", $\,,
        " message=", $", Msg/binary, $", $\,,
        " description=", $", Desc/binary, $"
    >>,
    Resp = #{
        <<"body">> => Body,
        <<"headers">> => #{
            <<"www-authenticate">> => Auth
        }
    },
    reply(401, error_encoding(Enc), Resp, Req).


%% @private
-spec reply(integer(), atom(), map(), cowboy_req:req()) ->
    cowboy_req:req().

reply(HTTPCode, Enc, Response, Req0) ->
    %% We add the content-type since we are bypassing Cowboy by replying
    %% ourselves
    MimeType = case Enc of
        msgpack ->
            <<"application/msgpack; charset=utf-8">>;
        json ->
            <<"application/json; charset=utf-8">>;
        undefined ->
            <<"application/json; charset=utf-8">>;
        Bin ->
            Bin
    end,
    Req1 = cowboy_req:set_resp_header(<<"content-type">>, MimeType, Req0),
    cowboy_req:reply(HTTPCode, prepare_request(Enc, Response, Req1)).



%% @private
-spec prepare_request(atom(), map(), cowboy_req:req()) ->
    cowboy_req:req().

prepare_request(Enc, Response, Req0) ->
    Body = maps:get(<<"body">>, Response),
    Headers = maps:get(<<"headers">>, Response),
    Req1 = cowboy_req:set_resp_headers(Headers, Req0),
    cowboy_req:set_resp_body(maybe_encode(Enc, Body), Req1).


%% @private
maybe_location(<<"post">>, #{<<"uri">> := Uri}) when Uri =/= <<>> ->
    {true, Uri};

maybe_location(_, _) ->
    true.




%% @private
url(Host, Path, <<>>) ->
    <<Host/binary, Path/binary>>;

url(Host, Path, QS) ->
    <<Host/binary, Path/binary, $?, QS/binary>>.




%% -----------------------------------------------------------------------------
% private
%% @doc
%% The Spec uses lowercase for the method names but Cowboy uses uppercase
%% @end
%% -----------------------------------------------------------------------------
method(Req) ->
    method_to_lowercase(cowboy_req:method(Req)).

method_to_lowercase(<<"DELETE">>) -> <<"delete">>;
method_to_lowercase(<<"GET">>) -> <<"get">>;
method_to_lowercase(<<"HEAD">>) -> <<"head">>;
method_to_lowercase(<<"OPTIONS">>) -> <<"options">>;
method_to_lowercase(<<"PATCH">>) -> <<"patch">>;
method_to_lowercase(<<"POST">>) -> <<"post">>;
method_to_lowercase(<<"PUT">>) -> <<"put">>.



%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% This function exists just becuase because hackney (http client) uses atoms
%% @end
%% -----------------------------------------------------------------------------
method_to_atom(<<"delete">>) -> delete;
method_to_atom(<<"get">>) -> get;
method_to_atom(<<"head">>) -> head;
method_to_atom(<<"options">>) -> options;
method_to_atom(<<"patch">>) -> patch;
method_to_atom(<<"post">>) -> post;
method_to_atom(<<"put">>) -> put.


%% @private
maybe_encode(undefined, Body) ->
    Body;

maybe_encode(Enc, Body) ->
    bondy_utils:maybe_encode(Enc, Body).


%% @private
maybe_encode(_, <<>>, _) ->
    <<>>;

maybe_encode(undefined, Body, _) ->
    Body;

maybe_encode(_, Body, #{<<"action">> := #{<<"type">> := <<"forward">>}}) ->
    Body;

maybe_encode(Enc, Body, _) ->
    bondy_utils:maybe_encode(Enc, Body).


error_encoding(json) -> json;
error_encoding(msgpack) -> msgpack;
error_encoding(undefined) -> json;
error_encoding(_Other) -> json.



%% @private
uri_to_status_code(timeout) ->                              504;
uri_to_status_code(?BONDY_BAD_GATEWAY_ERROR) ->             503;
uri_to_status_code(?BONDY_ERROR_TIMEOUT) ->                 504;
uri_to_status_code(?WAMP_AUTHORIZATION_FAILED) ->           403;
uri_to_status_code(?WAMP_CANCELLED) ->                      400;
uri_to_status_code(?WAMP_CLOSE_REALM) ->                    500;
uri_to_status_code(?WAMP_DISCLOSE_ME_NOT_ALLOWED) ->        400;
uri_to_status_code(?WAMP_GOODBYE_AND_OUT) ->                500;
uri_to_status_code(?WAMP_INVALID_ARGUMENT) ->               400;
uri_to_status_code(?WAMP_INVALID_URI) ->                    400;
uri_to_status_code(?WAMP_NET_FAILURE) ->                    502;
uri_to_status_code(?WAMP_NOT_AUTHORIZED) ->                 401;
uri_to_status_code(?WAMP_NO_ELIGIBLE_CALLE) ->              502;
uri_to_status_code(?WAMP_NO_SUCH_PROCEDURE) ->              501;
uri_to_status_code(?WAMP_NO_SUCH_REALM) ->                  502;
uri_to_status_code(?WAMP_NO_SUCH_REGISTRATION) ->           502;
uri_to_status_code(?WAMP_NO_SUCH_ROLE) ->                   400;
uri_to_status_code(?WAMP_NO_SUCH_SESSION) ->                500;
uri_to_status_code(?WAMP_NO_SUCH_SUBSCRIPTION) ->           502;
uri_to_status_code(?WAMP_OPTION_DISALLOWED_DISCLOSE_ME) ->  400;
uri_to_status_code(?WAMP_OPTION_NOT_ALLOWED) ->             400;
uri_to_status_code(?WAMP_PROCEDURE_ALREADY_EXISTS) ->       400;
uri_to_status_code(?WAMP_SYSTEM_SHUTDOWN) ->                500;
uri_to_status_code(_) ->                                    500.


%% @private
eval_headers(Req, #{api_spec := Spec, api_context := Ctxt}) ->
    Expr = maps_utils:get_path(
        [<<"response">>, <<"on_error">>, <<"headers">>],
        maps:get(method(Req), Spec),
        #{}
    ),
    mops_eval(Expr, Ctxt).


trim_trailing_slash(Bin) ->
    case binary:longest_common_suffix([Bin, <<$/>>]) of
        1 ->
            binary:part(Bin, 0, byte_size(Bin) -1);
        0 ->
            Bin
    end.



mops_eval(Expr, Ctxt) ->
    try mops:eval(Expr, Ctxt)
    catch
        ?EXCEPTION(error, {badkey, Key}, _) ->
            throw(#{
                <<"code">> => ?BONDY_API_GATEWAY_INVALID_EXPR_ERROR,
                <<"message">> => <<"There is no value for key '", Key/binary, "' in the HTTP Request context.">>,
                <<"description">> => <<"This might be due to an error in the action expression (mops) itself or as a result of a key missing in the response to a gateway action (WAMP or HTTP call).">>
            });
        ?EXCEPTION(error, {badkeypath, Path}, _) ->
            throw(#{
                <<"code">> => ?BONDY_API_GATEWAY_INVALID_EXPR_ERROR,
                <<"message">> => <<"There is no value for path '", Path/binary, "' in the HTTP Request context.">>,
                <<"description">> => <<"This might be due to an error in the action expression (mops) itself or as a result of a key missing in the response to a gateway action (WAMP or HTTP call).">>
            })
    end.


%% @private
log(Level, Prefix, Head, #{api_context := Ctxt} = St)
when is_binary(Prefix) orelse is_list(Prefix), is_list(Head) ->
    #{
        <<"id">> := TraceId,
        <<"method">> := Method,
        <<"scheme">> := Scheme,
        <<"peername">> := Peername,
        <<"path">> := Path,
        %% <<"headers">> := Headers,
        <<"query_string">> := QueryString,
        <<"bindings">> := Bindings,
        <<"body_length">> := Len
    } = maps:get(<<"request">>, Ctxt),

    Format = iolist_to_binary([
        Prefix,
        <<
            %% Right now trace_id is a bin as msgpack does not support
            %% 128-bit integers
            ", trace_id=~s"
            ", realm_uri=~s"
            ", encoding=~s"
            ", method=~s"
            ", scheme=~s"
            ", peername=~s"
            ", path=~s"
            %% ", headers=~s"
            ", query_string=~s",
            ", bindings=~p"
            ", body_length=~p"
        >>
    ]),
    BodyLen = case maps:get(body_evaluated, St) of
        true ->
            Len;
        false ->
            undefined
    end,

    Tail = [
        TraceId,
        maps:get(realm_uri, St, undefined),
        maps:get(encoding, St, undefined),
        Method,
        Scheme,
        Peername,
        Path,
        %% Headers,
        QueryString,
        Bindings,
        BodyLen
    ],
    lager:log(Level, self(), Format, lists:append(Head, Tail)).
