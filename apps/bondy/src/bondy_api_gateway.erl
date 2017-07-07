%% -----------------------------------------------------------------------------
%% Copyright (C) Ngineo Limited 2017. All rights reserved.
%% -----------------------------------------------------------------------------

%% =============================================================================
%% @doc
%%
%% @end
%% =============================================================================
-module(bondy_api_gateway).
-include_lib("wamp/include/wamp.hrl").
-include("bondy.hrl").


-define(HTTP, api_gateway_http).
-define(HTTPS, api_gateway_https).
-define(ADMIN_HTTP, admin_api_http).
-define(ADMIN_HTTPS, admin_api_https).

-type listener()  ::    api_gateway_http
                        | api_gateway_https
                        | admin_api_http
                        | admin_api_https.


%% API
-export([add_client/2]).
-export([add_resource_owner/2]).
-export([dispatch_table/1]).
-export([load/1]).

-export([start_listeners/0]).
-export([start_admin_listeners/0]).

% -export([start_http/1]).
% -export([start_https/1]).




%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec load(file:filename() | map()) -> 
    ok | {error, {invalid_specification_format, any()}}.

load(Spec) when is_map(Spec) ->
    %% We append the new spec to the base ones
    Specs = [Spec | specs()],
    _ = [
        update_dispatch_table(Scheme, Routes) 
        || {Scheme, Routes} <- parse_specs(Specs)
    ],
    ok;

load(FName) ->
    try jsx:consult(FName, [return_maps]) of
        [Spec] ->
            load(Spec)
    catch
        error:badarg ->
            {error, invalid_specification_format}
    end.



%% -----------------------------------------------------------------------------
%% @doc
%% Adds an API client to realm RealmUri.
%% Creates a new user adding it to the `api_clients` group.
%% @end
%% -----------------------------------------------------------------------------
-spec add_client(uri(), map()) -> {ok, map()} | {error, term()}.

add_client(RealmUri, Info0) ->
    try 
        ok = maybe_init_security(RealmUri),
        Info1 = maps_utils:validate(Info0, #{
            <<"client_id">> => #{
                required => true,
                allow_null => false,
                datatype => binary,
                default => fun() -> bondy_oauth2:generate_fragment(32) end
            },
            <<"client_secret">> => #{
                required => true,
                allow_null => false,
                datatype => binary,
                default => fun() -> bondy_oauth2:generate_fragment(48) end
            },
            <<"description">> => #{
                datatype => binary
            }
        }),
        {Props, Info2} = maps_utils:split(
            [<<"client_id">>, <<"client_secret">>], Info1),
        Opts = [
            {info, Info2},
            {"password", maps:get(<<"client_secret">>, Props)},
            {"groups", ["api_clients"]}
        ],
        Id = maps:get(<<"client_id">>, Props),
        case bondy_security:add_user(RealmUri, Id, Opts) of
            {error, _} = Error ->
                Error;
            ok ->
                {ok, Info1}
        end
    catch
        error:Reason when is_map(Reason) ->
            {error, Reason}
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% Adds a resource owner (end-user or system) to realm RealmUri.
%% Creates a new user adding it to the `resource_owners` group.
%% @end
%% -----------------------------------------------------------------------------
-spec add_resource_owner(uri(), map()) -> 
    {ok, map()} | {error, term()} | no_return().

add_resource_owner(RealmUri, Info0) ->
    ok = maybe_init_security(RealmUri),
    {Props, Info1} = maps_utils:split(
            [<<"username">>, <<"password">>], Info0),
    Info2 = maps_utils:validate(Info1, #{
        <<"username">> => #{
            required => true,
            allow_null => false,
            datatype => binary,
            default => fun() -> bondy_oauth2:generate_fragment(32) end
        },
        <<"password">> => #{
            required => true,
            allow_null => false,
            datatype => binary,
            default => fun() -> bondy_oauth2:generate_fragment(48) end
        },
        <<"description">> => #{
            datatype => binary
        }
    }),
    Username = maps:get(<<"username">>, Info2),
    Opts = [
        {info, Props},
        {"password", maps:get(<<"password">>, Info2)},
        {"groups", ["resource_owners"]}
    ],
    case bondy_security:add_user(RealmUri, Username, Opts) of
        {error, _} = Error ->
            Error;
        ok ->
            {ok, maps:merge(Info1, Props)}
    end.



%% -----------------------------------------------------------------------------
%% @doc
%% Conditionally start the public http and https listeners based on the 
%% configuration. This will load any default Bondy api specs.
%% Notice this is not the way to start the admin api listeners see 
%% {@link start_admin_listeners()} for that.
%% @end
%% -----------------------------------------------------------------------------
start_listeners() ->
    % Parsed = [bondy_api_gateway_spec:parse(S) || S <- Specs],
    % Compiled = bondy_api_gateway_spec:compile(Parsed),
    % SchemeRoutes = case bondy_api_gateway_spec:load(Compiled) of
    %     [] ->
    %         [{<<"http">>, []}];
    %     Val ->
    %         Val
    % end,
    _ = [
        start_listener({Scheme, Routes}) 
        || {Scheme, Routes} <- parse_specs(specs())],
    ok.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
start_admin_listeners() ->
    _ = [
        start_admin_listener({Scheme, Routes}) 
        || {Scheme, Routes} <- parse_specs([admin_spec()])],
    ok.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec start_listener({Scheme :: binary(), [tuple()]}) -> ok.

start_listener({<<"http">>, Routes}) ->
    {ok, _} = start_http(Routes, ?HTTP),
    ok;

start_listener({<<"https">>, Routes}) ->
    {ok, _} = start_https(Routes, ?HTTPS),
    ok.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec start_admin_listener({Scheme :: binary(), [tuple()]}) -> ok.

start_admin_listener({<<"http">>, Routes}) ->
    {ok, _} = start_http(Routes, ?ADMIN_HTTP),
    ok;

start_admin_listener({<<"https">>, Routes}) ->
    {ok, _} = start_https(Routes, ?ADMIN_HTTPS),
    ok.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec start_http(list(), atom()) -> {ok, Pid :: pid()} | {error, any()}.

start_http(Routes, Name) ->
    %% io:format("HTTP Routes ~p~n", [Routes]),
    % io:format("Table ~p~n", [Table]),
    {ok, Opts} = application:get_env(bondy, Name),
    {_, PoolSize} = lists:keyfind(acceptors_pool_size, 1, Opts),
    {_, Port} = lists:keyfind(port, 1, Opts),
    
    cowboy:start_clear(
        Name,
        PoolSize,
        [{port, Port}],
        #{
            env => #{
                bondy => #{
                    auth => #{
                        schemes => [basic, digest, bearer]
                    }
                },
                dispatch => cowboy_router:compile(Routes), 
                max_connections => infinity
            },
            middlewares => [
                cowboy_router, 
                % bondy_api_gateway,
                % bondy_security_middleware, 
                cowboy_handler
            ]
        }
    ).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec start_https(list(), atom()) -> {ok, Pid :: pid()} | {error, any()}.

start_https(Routes, Name) ->
    %% io:format("HTTPS Routes ~p~n", [Routes]),
    {ok, Opts} = application:get_env(bondy, Name),
    {_, PoolSize} = lists:keyfind(acceptors_pool_size, 1, Opts),
    {_, Port} = lists:keyfind(port, 1, Opts),
    {_, PKIFiles} = lists:keyfind(pki_files, 1, Opts),
    cowboy:start_tls(
        Name,
        PoolSize,
        [{port, Port} | PKIFiles],
        #{
            env => #{
                bondy => #{
                    auth => #{
                        schemes => [basic, digest, bearer]
                    }
                },
                dispatch => cowboy_router:compile(Routes), 
                max_connections => infinity
            },
            middlewares => [
                cowboy_router, 
                % bondy_api_gateway,
                % bondy_security_middleware, 
                cowboy_handler
            ]
        }
    ).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec dispatch_table(listener()) -> any().


dispatch_table(Listener) ->
    Map = ranch:get_protocol_options(Listener),
    maps_utils:get_path([env, dispatch], Map).






%% =============================================================================
%% PRIVATE: REST LISTENERS
%% =============================================================================




%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec update_dispatch_table(atom() | binary(), list()) -> ok.

update_dispatch_table(http, Routes) ->
    update_dispatch_table(<<"http">>, Routes);

update_dispatch_table(https, Routes) ->
    update_dispatch_table(<<"https">>, Routes);

update_dispatch_table(<<"http">>, Routes) ->
    cowboy:set_env(?HTTP, dispatch, cowboy_router:compile(Routes));

update_dispatch_table(<<"https">>, Routes) ->
    cowboy:set_env(?HTTPS, dispatch, cowboy_router:compile(Routes)).


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%% -----------------------------------------------------------------------------
base_routes() ->
    %% The WS entrypoint required for WAMP WS subprotocol
    [ {'_', [{"/ws", bondy_ws_handler, #{}}]} ].


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% Reads all Bondy Gateway Specification files in the provided `specs_path`
%% configuration option.
%% @end
%% -----------------------------------------------------------------------------
specs() ->
    case application:get_env(bondy, api_gateway, undefined) of
        undefined ->
            % specs("./etc");
            [];
        Opts ->
            case lists:keyfind(specs_path, 1, Opts) of
                false ->
                    % specs("./etc");
                    [];
                {_, Path} ->
                    % lists:append([specs(Path), specs("./etc")])
                    specs(Path)
            end
    end.



admin_spec() ->
    File = "./etc/bondy_admin_api.json",
    try jsx:consult(File, [return_maps]) of
        [Spec] ->
            Spec
    catch
        error:badarg ->
            lager:error("Error processing API Gateway Specification file. File not found or invalid specification format, file_name=~p", [File]),
            exit(badarg)
    end.


%% @private
specs(Path) ->

    case filelib:wildcard(filename:join([Path, "*.json"])) of
        [] ->
            [];
        FNames ->
            Fold = fun(FName, Acc) ->
                try jsx:consult(FName, [return_maps]) of
                    [Spec] ->
                        [Spec|Acc]
                catch
                    error:badarg ->
                        lager:error("Error processing API Gateway Specification file, reason=~p, file_name=~p", [invalid_specification_format, FName]),
                        Acc
                end
            end,
            lists:foldl(Fold, [], FNames)
    end.


%% @private
parse_specs(Specs) ->
    case [bondy_api_gateway_spec_parser:parse(S) || S <- Specs] of
        [] ->
            [{<<"http">>, base_routes()}, {<<"https">>, base_routes()}];
        Parsed ->
            bondy_api_gateway_spec_parser:dispatch_table(
                Parsed, base_routes())
    end.



%% =============================================================================
%% PRIVATE: SECURITY
%% =============================================================================



%% @private
maybe_init_security(RealmUri) ->
    Gs = [
        #{
            <<"name">> => <<"api_clients">>,
            <<"description">> => <<"A group of applications making protected resource requests through Bondy API Gateway on behalf of the resource owner and with its authorisation.">>
        },
        #{
            <<"name">> => <<"resource_owners">>,
            <<"description">> => <<"A group of entities capable of granting access to a protected resource. When the resource owner is a person, it is referred to as an end-user.">>
        }
    ],
    [maybe_init_group(RealmUri, G) || G <- Gs],
    ok.


%% @private
maybe_init_group(RealmUri, #{<<"name">> := Name} = G) ->
    case bondy_security_group:lookup(RealmUri, Name) of
        not_found -> 
            bondy_security_group:add(RealmUri, G);
        _ ->
            ok
    end.