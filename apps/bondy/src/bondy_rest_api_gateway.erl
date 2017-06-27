%% -----------------------------------------------------------------------------
%% Copyright (C) Ngineo Limited 2017. All rights reserved.
%% -----------------------------------------------------------------------------

%% =============================================================================
%% @doc
%%
%% @end
%% =============================================================================
-module(bondy_rest_api_gateway).
-include("bondy.hrl").

-define(DEFAULT_POOL_SIZE, 200).
-define(HTTP, bondy_gateway_http_listener).
-define(HTTPS, bondy_gateway_https_listener).

%% COWBOY MIDDLEWARE CALLBACKS
-export([start_listeners/0]).
-export([start_http/1]).
-export([start_https/1]).
% -export([update_hosts/1]).
-export([add_consumer/4]).
-export([dispatch_table/1]).
-export([load_spec/1]).




%% =============================================================================
%% API
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc
%% Conditionally start http and https listeners based on the configured APIs
%% @end
%% -----------------------------------------------------------------------------
start_listeners() ->
    Specs = specs(),
    % Parsed = [bondy_rest_api_gateway_spec:parse(S) || S <- Specs],
    % Compiled = bondy_rest_api_gateway_spec:compile(Parsed),
    % SchemeRoutes = case bondy_rest_api_gateway_spec:load(Compiled) of
    %     [] ->
    %         [{<<"http">>, []}];
    %     Val ->
    %         Val
    % end,
    L = case [bondy_rest_api_gateway_spec_parser:parse(S) || S <- Specs] of
        [] ->
            [{<<"http">>, []}, {<<"https">>, []}];
        Parsed ->
            bondy_rest_api_gateway_spec_parser:dispatch_table(
                Parsed, base_routes())
    end,
    _ = [start_listener({Scheme, Routes}) || {Scheme, Routes} <- L],
    ok.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec start_listener({Scheme :: binary(), [tuple()]}) -> ok.

start_listener({<<"http">>, Routes}) ->
    {ok, _} = start_http(Routes),
    % io:format("HTTP Listener startin with Routes~p~n", [Routes]),
    ok;

start_listener({<<"https">>, Routes}) ->
    {ok, _} = start_https(Routes),
    ok.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec start_http(list()) -> {ok, Pid :: pid()} | {error, any()}.
start_http(Routes) ->
    % io:format("Routes ~p~n", [Routes]),
    % io:format("Table ~p~n", [Table]),
    cowboy:start_clear(
        ?HTTP,
        bondy_config:http_acceptors_pool_size(),
        [{port, bondy_config:http_port()}],
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
                % bondy_rest_api_gateway,
                % bondy_security_middleware, 
                cowboy_handler
            ]
        }
    ).



-spec start_https(list()) -> {ok, Pid :: pid()} | {error, any()}.
start_https(Routes) ->
    cowboy:start_tls(
        ?HTTPS,
        bondy_config:https_acceptors_pool_size(),
        [{port, bondy_config:https_port()}],
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
                % bondy_rest_api_gateway,
                % bondy_security_middleware, 
                cowboy_handler
            ]
        }
    ).



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec load_spec(file:filename()) -> ok | {error, any()}.

load_spec(FName) ->
    case file:consult(FName) of
        {ok, [Spec]} ->
            L = case bondy_rest_api_gateway_spec_parser:parse(Spec) of
                [] ->
                    [{<<"http">>, []}, {<<"https">>, []}];
                Parsed ->
                    bondy_rest_api_gateway_spec_parser:dispatch_table(
                        Parsed, base_routes())
            end,
            _ = [
                update_dispatch_table(Scheme, Routes) || {Scheme, Routes} <- L
            ],
            ok;
        {error, _} = Error ->
            Error
    end.



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec dispatch_table(binary() | atom()) -> any().

dispatch_table(<<"http">>) ->
    dispatch_table(http);

dispatch_table(<<"https">>) ->
    dispatch_table(https);

dispatch_table(http) ->
    Map = ranch:get_protocol_options(?HTTP),
    maps_utils:get_path([env, dispatch], Map);

dispatch_table(https) ->
    Map = ranch:get_protocol_options(?HTTPS),
    maps_utils:get_path([env, dispatch], Map).





%% =============================================================================
%% API: CONSUMERS
%% =============================================================================




%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
add_consumer(RealmUri, ClientId, Password, Info) ->
    ok = maybe_init_security(RealmUri),
    Opts = [
        {info, Info},
        {"password", binary_to_list(Password)},
        {"groups", "api_consumers"}
    ],
    bondy_security:add_user(RealmUri, ClientId, Opts).
    




%% =============================================================================
%% PRIVATE: REST LISTENERS
%% =============================================================================




%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%% -----------------------------------------------------------------------------
update_dispatch_table(http, Routes) ->
    update_dispatch_table(<<"http">>, Routes);

update_dispatch_table(https, Routes) ->
    update_dispatch_table(<<"http">>, Routes);

update_dispatch_table(<<"http">>, Routes) ->
    cowboy:set_env(?HTTP, dispatch, cowboy_router:compile(Routes));

update_dispatch_table(<<"https">>, Routes) ->
    cowboy:set_env(?HTTPS, dispatch, cowboy_router:compile(Routes)).



%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% Reads all Bondy Gateway Specification files in the provided `specs_path`
%% configuration option.
%% @end
%% -----------------------------------------------------------------------------
specs() ->
    case bondy_config:api_gateway() of
        undefined ->
            [];
        Opts ->
            case lists:keyfind(specs_path, 1, Opts) of
                false ->
                    [];
                {_, Path} ->
                    case filelib:wildcard(filename:join([Path, "*.bgs"])) of
                        [] ->
                            [];
                        FNames ->
                            Fold = fun(FName, Acc) ->
                                case file:consult(FName) of
                                    {ok, Terms} ->
                                        [Terms|Acc];
                                    {error, _} ->
                                        lager:error("Error processing API Gateway Specification file, reason=~p, file_name=~p", [invalid_specification_format, FName]),
                                        Acc
                                end
                            end,
                            lists:append(lists:foldl(Fold, [], FNames))
                    end
            end
    end.


%% @private
base_routes() ->
    %% The WS entrypoint
    [{'_', [{"/ws", bondy_ws_handler, #{}}]}].





%% =============================================================================
%% PRIVATE: SECURITY
%% =============================================================================


%% @private
maybe_init_security(RealmUri) ->
    case bondy_security_group:lookup(RealmUri, <<"api_consumers">>) of
        not_found -> 
            G = #{
                <<"name">> => <<"api_consumers">>,
                <<"description">> => <<"A group of users allowed to consume APIs from the Bondy RESTful API Gateway.">>
            },
            bondy_security_group:add(RealmUri, G);
        _ ->
            ok
    end.
    



