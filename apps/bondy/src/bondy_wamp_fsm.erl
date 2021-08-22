%% =============================================================================
%%  bondy_wamp_fsm.erl -
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
%%
%% @end
%% -----------------------------------------------------------------------------
-module(bondy_wamp_fsm).
-include("bondy.hrl").
-include("bondy_uris.hrl").
-include("bondy_security.hrl").
-include_lib("wamp/include/wamp.hrl").

-define(SHUTDOWN_TIMEOUT, 5000).


-type message()             ::  wamp_message:message()
                                | {raw, ping}
                                | {raw, pong}
                                | {raw, wamp_encoding:raw_error()}.

-export([init/2]).
-export([handle_inbound/2]).
-export([handle_outbound/2]).
-export([terminate/1]).


%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc Returns a new wamp session (FSM) in a 'closed' state.
%% @end
%% -----------------------------------------------------------------------------
-spec init(
    Subprotocol :: binary() | subprotocol(), Conn :: bondy_connection:t()) ->
    {ok, bondy_session:t()} | {error, any(), bondy_session:t()}.

init(Subprotocol, Conn) ->
    bondy_session:new(Subprotocol, Conn, #{}).


%% -----------------------------------------------------------------------------
%% @doc Handles incoming wamp frames from clients, decoding 1 or more messages,
%% routing them and replying when required.
%% @end
%% -----------------------------------------------------------------------------
-spec handle_inbound(binary(), bondy_session:t()) ->
    {ok, bondy_session:t()}
    | {stop, bondy_session:t()}
    | {stop, [binary()], bondy_session:t()}
    | {reply, [binary()], bondy_session:t()}.

handle_inbound(Data, S) ->
    try wamp_encoding:decode(bondy_session:subprotocol(S), Data) of
        {Messages, <<>>} ->
            handle_inbound_messages(Messages, S)
    catch
        _:{unsupported_encoding, _} = Reason ->
            stop(Reason, S);

        _:badarg ->
            stop(decoding_error, S);

        Class:function_clause ->
            _ = lager:warning(
                "Invalid message; class=~p, reason=~s, state_name=~p, " "data=~p",
                [Class, function_clause, bondy_session:state_name(S), Data]
            ),
            stop(invalid_message, S)
    end.



%% -----------------------------------------------------------------------------
%% @doc Handles outgoing wamp messages from Router to client.
%% @end
%% -----------------------------------------------------------------------------
-spec handle_outbound(wamp_message:message(), bondy_session:t()) ->
    {ok, binary(), bondy_session:t()}
    | {stop, bondy_session:t()}
    | {stop, binary(), bondy_session:t()}
    | {stop, binary(), bondy_session:t(), After :: non_neg_integer()}.

handle_outbound(M, S) ->
    Result = case bondy_session:state_name(S) of
        closed ->
            %% It should never happen, function_clause error expected
            closed(out, [M], S, []);
        challenging ->
            %% It should never happen, function_clause error expected
            challenging(out, [M], S, []);
        failed ->
            %% It should never happen, function_clause error expected
            failed(out, [M], S, []);
        established ->
            established(out, [M], S, []);
        shutting_down ->
            shutting_down(out, [M], S, [])
    end,

    case Result of
        {ok, [Bin], S} ->
            {ok, Bin, S};
        {stop, [Bin], S, Timeout} ->
            {stop, Bin, S, Timeout};
        {stop, _} = Stop -> Stop
    end.

%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec terminate(Session :: bondy_session:t()) -> ok.


terminate(Session) ->
    bondy_session:close(Session).



%% =============================================================================
%% PRIVATE: FSM STATE FUNCTIONS
%% =============================================================================



%% @private
-spec handle_inbound_messages([message()], bondy_session:t()) ->
    {ok, bondy_session:t()}
    | {stop, bondy_session:t()}
    | {stop, [binary()], bondy_session:t()}
    | {reply, [binary()], bondy_session:t()}.

handle_inbound_messages(Messages, S) ->
    try
        handle_inbound_messages(Messages, S, [])
    catch
        throw:Reason ->
            stop(Reason, S);

        Class:Reason:Stacktrace ->
            _ = lager:error(
                "Unexpected error; class=~p reason=~s, state_name=~p, stacktrace=~p",
                [Class, Reason, bondy_session:state_name(S), Stacktrace]
            ),
            %% REVIEW shouldn't we call stop({system_failure, Reason}) to abort?
            error(Reason)
    end.


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% Handles one or more messages, routing them and returning a reply
%% when required.
%% @end
%% -----------------------------------------------------------------------------
-spec handle_inbound_messages(
    [message()], bondy_session:t(), Acc :: [message()]) ->
    {ok, bondy_session:t()}
    | {stop, bondy_session:t()}
    | {stop, [binary()], bondy_session:t()}
    | {reply, [binary()], bondy_session:t()}.

handle_inbound_messages([], S, []) ->
    {ok, S};

handle_inbound_messages([], S, Acc) ->
    {reply, lists:reverse(Acc), S};

handle_inbound_messages(L, S, Acc) ->
    case bondy_session:state_name(S) of
        closed ->
            closed(in, L, S, Acc);

        challenging ->
            challenging(in, L, S, Acc);

        failed ->
            failed(in, L, S, Acc);

        established ->
            established(in, L, S, Acc);

        shutting_down ->
            shutting_down(in, L, S, Acc)
    end.



%% -----------------------------------------------------------------------------
%% @doc This function implements the handling FSM logic for the `closed' state.
%% In this state the FSM can only accept a HELLO message. Reception of any
%% other message implies a procotol violation.
%% Possible next states: `challenging' , `closed' or `failed'.
%% @end
%% -----------------------------------------------------------------------------
closed(in, [#hello{realm_uri = RealmUri} = M|_], S0, _) ->
    %% Client is requesting a session
    %% This will return either reply with wamp_welcome() | wamp_challenge()
    %% or abort
    ok = bondy_event_manager:notify({wamp, M, S0}),

    try
        %% We make sure the realm exists (creating it if allowed)
        %% If it does not, it will fail with a 'no_such_realm' exception
        _ = bondy_realm:get(RealmUri),

        Props0 = maps:with([agent, roles], M#hello.details),
        Props1 = maps:put(realm_uri, RealmUri, Props0),

        S1 = bondy_session:set_state(closed, Props1, S0),

        maybe_establish(maybe_challenge(M#hello.details, S1))
    catch
        error:no_such_realm ->
            stop({authentication_failed, no_such_realm}, S0)
    end;

closed(in, [#abort{} = M|_], S0, _) ->
    %% Client aborting, we ignore any subsequent messages
    Uri = M#abort.reason_uri,
    Details = M#abort.details,
    _ = lager:info(
        "Client aborted; reason=~s, state_name=~p, details=~p",
        [Uri, closed, Details]
    ),
    {stop, bondy_session:set_state(closed, #{}, S0)};

closed(in, _, S, _) ->
    %% Client does not have a session and message is not HELLO
    stop({protocol_violation, no_session}, S).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
failed(_, _, S, _) ->
    %% Client does not have a session and message is not HELLO
    {stop, S}.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
challenging(in, [#hello{} = M|_], S, _) ->
    %% Client does not have a session but we already sent a challenge message
    %% in response to a previous HELLO message
    ok = bondy_event_manager:notify({wamp, M, S}),
    stop({protocol_violation, session_establishing}, S);

challenging(in, [#authenticate{} = M|_], S0, _) ->
    %% Client is responding to our challenge
    ok = bondy_event_manager:notify({wamp, M, S0}),

    AuthCtxt0 = bondy_session:get_meta(auth_ctxt, S0),
    Signature = M#authenticate.signature,
    Extra = M#authenticate.extra,

    case bondy_auth:authenticate(Signature, Extra, AuthCtxt0) of
        {ok, WelcomeAuthExtra, AuthCtxt1} ->
            S1 = bondy_session:put_meta(auth_ctxt, AuthCtxt1, S0),
            establish(WelcomeAuthExtra, S1);
        {error, Reason} ->
            stop({authentication_failed, Reason}, S0)
    end;

challenging(in, [#abort{} = M|_], S0, _) ->
    %% Client aborting, we ignore any subsequent messages
    _ = lager:info(
        "Client aborted; reason=~s, state_name=~p, details=~p",
        [M#abort.reason_uri, challenging, M#abort.details]
    ),
    {stop, bondy_session:set_state(closed, #{}, S0)};

challenging(in, _, S, _) ->
    stop({protocol_violation, invalid_message}, S).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
established(in, [], S, []) ->
    {ok, S};

established(in, [], S, Acc) ->
    {reply, lists:reverse(Acc), S};

established(out, [], S, []) ->
    {ok, S};

established(out, [], S, Acc) ->
    {ok, lists:reverse(Acc), S};

established(in, [#goodbye{}|_], S0, Acc) ->
    %% Client is closing the session, we ignore any subsequent messages
    %% We reply with all previous messages plus a goodbye and stop
    Reply = wamp_message:goodbye(
        #{message => <<"Session closed by client.">>},
        ?WAMP_GOODBYE_AND_OUT
    ),
    Bin = wamp_encoding:encode(Reply, bondy_session:encoding(S0)),
    S1 = bondy_session:set_state(closed, #{}, S0),
    {stop, normal, lists:reverse([Bin|Acc]), S1};

established(in, [#hello{} = M|_], S, Acc) ->
    %% Client already has a session!
    %% RFC: It is a protocol error to receive a second "HELLO" message during
    %% the lifetime of the session and the _Peer_ must fail the session if that
    %% happens.
    %% We reply all previous messages plus an abort message and close
    ok = bondy_event_manager:notify({wamp, M, S}),
    stop({protocol_violation, session_establishing}, Acc, S);

established(in, [#authenticate{} = M|_], S, Acc) ->
    %% Client already has a session!
    %% We reply all previous messages plus an abort message and close
    ok = bondy_event_manager:notify({wamp, M, S}),
    Reason = <<"You've sent an AUTHENTICATE message more than once.">>,
    stop({protocol_violation, Reason}, Acc, S);

established(in, [H|T], S, Acc) ->
    case bondy_router:forward(H, bondy_context:new(S)) of
        ok ->
            established(in, T, S, Acc);
        {reply, M} ->
            Bin = wamp_encoding:encode(M, bondy_session:encoding(S)),
            established(in, T, S, [Bin | Acc]);
        {stop, M} ->
            Bin = wamp_encoding:encode(M, bondy_session:encoding(S)),
            {stop, [Bin | Acc], S}
    end;

established(out, [#result{} = M|T], S, Acc) ->
    ok = bondy_event_manager:notify({wamp, M, S}),
    Bin = wamp_encoding:encode(M, bondy_session:encoding(S)),
    established(out, T, S, [Bin|Acc]);

established(out, [#error{request_type = ?CALL} = M|T], S, Acc) ->
    ok = bondy_event_manager:notify({wamp, M, S}),
    Bin = wamp_encoding:encode(M, bondy_session:encoding(S)),
    established(out, T, S, [Bin|Acc]);

established(out, [#goodbye{} = M|_], S0, Acc) ->
    %% Bondy is shutting_down this session, we will stop when we
    %% get the client's goodbye response
    ok = bondy_event_manager:notify({wamp, M, S0}),
    Bin = wamp_encoding:encode(M, bondy_session:encoding(S0)),
    S1 = bondy_session:set_state(shutting_down, #{}, S0),
    {stop, lists:reverse([Bin|Acc]), S1, ?SHUTDOWN_TIMEOUT};

established(out, [H|T], S, Acc) ->
    case wamp_message:is_message(H) of
        true ->
            ok = bondy_event_manager:notify({wamp, H, S}),
            Bin = wamp_encoding:encode(H, bondy_session:encoding(S)),
            established(out, T, S, [Bin|Acc]);
        false ->
            %% RFC: WAMP implementations MUST close sessions (disposing all of their resources such as subscriptions and registrations) on protocol errors caused by offending peers.
            {stop, lists:reverse(Acc), S}
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
shutting_down(in, [#goodbye{}|_], S0, Acc) ->
    %% Client is replying to our goodbye, we ignore any subsequent messages
    %% We reply all previous messages and close
    S1 = bondy_session:set_state(closed, #{}, S0),
    {stop, shutdown, lists:reverse(Acc), S1};

shutting_down(in, _, S0, Acc) ->
    %% We ignore any other message
    {stop, shutdown, lists:reverse(Acc), S0};

shutting_down(out, _, S0, Acc) ->
    %% We ignore any other message
    {stop, shutdown, lists:reverse(Acc), S0}.




%% =============================================================================
%% PRIVATE: FSM STATE TRANSITIONS
%% =============================================================================



%% @private
maybe_establish({ok, S}) ->
    %% No need for a challenge, authmethod is anonymous or trust,
    %% or security has been disabled
    establish(undefined, S);

maybe_establish({error, Reason, S}) ->
    %% Realm does not exist or authentication failed due to wrong authid, or
    %% unavailable authmethods
    stop(Reason, S);

maybe_establish({challenge, AuthMethod, Challenge, S0}) ->
    %% We need to perform a challenge
    S1 = bondy_session:set_state(challenging, #{}, S0),
    M = wamp_message:challenge(AuthMethod, Challenge),
    Bin = wamp_encoding:encode(M, bondy_session:encoding(S1)),

    ok = bondy_event_manager:notify({wamp, M, S1}),

    {reply, [Bin], S1}.


%% -----------------------------------------------------------------------------
%% @private
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec establish(map() | undefined, bondy_session:t()) ->
    {reply, [binary()], bondy_session:t()}
    | {stop, [binary()], bondy_session:t()}.

establish(Extra, S0) ->
    try
        Id = bondy_session:id(S0),
        RealmUri = bondy_session:realm_uri(S0),
        {AuthCtxt, S1} = bondy_session:take_meta(auth_ctxt, S0),

        %% We establish the session.
        SessionState = #{
            anonymous => bondy_auth:is_anonymous(AuthCtxt),
            authid => bondy_auth:id(AuthCtxt),
            authmethod => bondy_auth:method(AuthCtxt),
            authprovider => bondy_auth:provider(AuthCtxt),
            authrole => bondy_auth:role(AuthCtxt),
            authroles => bondy_auth:roles(AuthCtxt)
        },
        S2 = bondy_session:set_state(established, SessionState, S1),

        Agent = bondy_session:agent(S2),
        Peername = bondy_session:peername(S2),

        %% TODO replace the following by {session_opened, Session}
        ok = bondy_event_manager:notify(
            {session_opened, RealmUri, Id, Agent, Peername, self()}
        ),

        %% We send back a WELCOME message
        Welcome = wamp_message:welcome(
            Id,
            #{
                authid => bondy_session:authid(S2),
                authmethod =>  bondy_session:authmethod(S2),
                authprovider =>  bondy_session:authprovider(S2),
                agent => bondy_router:agent(),
                roles => bondy_router:roles(), %% TODO match requested roles
                authrole => to_bin(bondy_session:authrole(S2)),
                'x_authroles' => [
                    to_bin(R) || R <- bondy_session:authroles(S2)
                ],
                authextra => Extra
            }
        ),
        ok = bondy_event_manager:notify({wamp, Welcome, S1}),
        Bin = wamp_encoding:encode(Welcome, bondy_session:encoding(S1)),

        {reply, [Bin], S1}

    catch
        error:{invalid_options, missing_client_role} = Reason ->
            stop(Reason, S0)
    end.



%% @private
maybe_challenge(Details, S) ->
    RealmUri = bondy_session:realm_uri(S),
    Status = bondy_realm:security_status(RealmUri),
    maybe_challenge(Status, Details, S).


%% @private
maybe_challenge(enabled, #{authid := Username} = Details, S0)
when Username =/= <<"anonymous">> ->
    Roles = get_authroles(Details),

    %% We initialise the auth state
    case bondy_auth:new(Username, Roles, S0) of
        {ok, AuthCtxt} ->
            %% We just store the auth_ctxt in the session's dictionary
            S1 = bondy_session:put_meta(auth_ctxt, AuthCtxt, S0),
            RequestedMethods = maps:get(authmethods, Details, []),
            Methods = bondy_auth:available_methods(RequestedMethods, AuthCtxt),
            auth_challenge(Methods, Details, S1);
        {error, Reason} ->
            {error, {authentication_failed, Reason}, S0}
    end;

maybe_challenge(enabled, Details, S0) ->
    %% authid is <<"anonymous">> or missing
    %% We initialise the auth context
    %% An anonymous user only belongs to the anonymous group
    Roles = [<<"anonymous">>],

    case bondy_auth:new(anonymous, Roles, S0) of
        {ok, AuthCtxt} ->
            S1 = bondy_session:put_meta(auth_ctxt, AuthCtxt, S0),
            auth_challenge([?WAMP_ANON_AUTH], Details, S1);

        {error, Reason} ->
            {error, {authentication_failed, Reason}, S0}
    end;

maybe_challenge(disabled, #{authid := Username}, S0) ->
    %% Authentication and Authorization is disabled
    S1 = bondy_session:set_state(closed, #{authid => Username}, S0),
    {ok, S1};

maybe_challenge(disabled, _, S0) ->
    %% We set a temporary authid
    S1 = bondy_session:set_state(closed, #{authid => bondy_utils:uuid()}, S0),
    {ok, S1}.


%% @private
auth_challenge([H|T], Details, S0) ->
    AuthCtxt0 = bondy_session:get_meta(auth_ctxt, S0),

    case bondy_auth:challenge(H, Details, AuthCtxt0) of
        {ok, AuthCtxt1} ->
            %% Authenticated
            S1 = bondy_session:put_meta(auth_ctxt, AuthCtxt1, S0),
            {ok, S1};

        {ok, ChallengeExtra, AuthCtxt1} ->
            %% We need to challenge
            S1 = bondy_session:put_meta(auth_ctxt, AuthCtxt1, S0),
            {challenge, H, ChallengeExtra, S1};

        {error, Reason} ->
            _ = lager:debug(
                "Authentication challenge step preparation failed; "
                "reason=~s, authmethod=~p",
                [Reason, H]
            ),
            auth_challenge(T, Details, S0)
    end;

auth_challenge([], _, S) ->
    {error, no_authmethod, S}.


%% @private
stop(#abort{} = M, S) ->
    stop(M, [], S);

stop(Reason, S) ->
    stop(abort_message(Reason), S).


%% @private
stop(#abort{reason_uri = Uri} = M, Acc, S0) ->
    ok = bondy_event_manager:notify({wamp, M, S0}),
    Bin = wamp_encoding:encode(M, bondy_session:encoding(S0)),

    %% We reply all previous messages plus an abort message and close
    S1 = bondy_session:set_state(closed, #{}, S0),
    {stop, Uri, [Bin|Acc], S1}.



%% =============================================================================
%% PRIVATE: UTILS
%% =============================================================================


%% @private
to_bin(Term) when is_atom(Term) ->
    atom_to_binary(Term, utf8);

to_bin(Term) when is_binary(Term) ->
    Term.


%% @private
get_authroles(Details) ->
    case maps:get('x_authroles', Details, undefined) of
        undefined ->
            case maps:get(authrole, Details, undefined) of
                undefined ->
                    %% null
                    undefined;
                <<>> ->
                    %% empty string
                    undefined;
                Role ->
                    [Role]
            end;
        List when is_list(List) ->
            List;
        _ ->
            Reason = <<"The value for 'x_authroles' is invalid. It should be a list of groupnames.">>,
            throw({protocol_violation, Reason})
    end.


%% @private
abort_message(internal_error) ->
    Details = #{
        message => <<"Internal system error, contact your administrator.">>
    },
    wamp_message:abort(Details, ?BONDY_ERROR_INTERNAL);

abort_message(decoding_error) ->
    Details = #{
        message => <<"An error ocurred while deserealising a message.">>
    },
    wamp_message:abort(Details, ?WAMP_PROTOCOL_VIOLATION);

abort_message(invalid_message) ->
    Details = #{
        message => <<"An invalid message was received.">>
    },
    wamp_message:abort(Details, ?WAMP_PROTOCOL_VIOLATION);

abort_message(no_authmethod) ->
    Details = #{
        message => <<"Router could not use the authmethod requested.">>
    },
    wamp_message:abort(Details, ?WAMP_NOT_AUTH_METHOD);

abort_message(no_such_realm) ->
    Details = #{
        message => <<"Realm does not exist.">>
    },
    wamp_message:abort(Details, ?WAMP_NO_SUCH_REALM);

abort_message(no_such_group) ->
    Details = #{
        message => <<"Group does not exist.">>
    },
    wamp_message:abort(Details, ?WAMP_NO_SUCH_ROLE);

abort_message(no_such_user) ->
    Details = #{
        message => <<"User does not exist.">>
    },
    wamp_message:abort(Details, ?WAMP_NO_SUCH_PRINCIPAL);

abort_message({protocol_violation, no_session}) ->
    Reason = <<
        "You need to request a session first by sending a HELLO message."
    >>,
    wamp_message:abort(#{message => Reason}, ?WAMP_PROTOCOL_VIOLATION);

abort_message({protocol_violation, session_establishing}) ->
    Reason = <<"You've sent a HELLO message more than once.">>,
    wamp_message:abort(#{message => Reason}, ?WAMP_PROTOCOL_VIOLATION);

abort_message({protocol_violation, Reason}) when is_binary(Reason) ->
    wamp_message:abort(#{message => Reason}, ?WAMP_PROTOCOL_VIOLATION);

abort_message({authentication_failed, invalid_authmethod}) ->
    Details = #{
        message => <<"Unsupported authentication method.">>
    },
    wamp_message:abort(Details, ?WAMP_AUTHENTICATION_FAILED);

abort_message({authentication_failed, no_such_realm}) ->
    Details = #{
        message => <<"Realm does not exist.">>
    },
    wamp_message:abort(Details, ?WAMP_NO_SUCH_REALM);

abort_message({authentication_failed, no_such_group}) ->
    Details = #{
        message => <<"A group does not exist for the the groupname or one of the groupnames requested ('authrole' or 'x_authroles').">>
    },
    wamp_message:abort(Details, ?WAMP_NO_SUCH_ROLE);

abort_message({authentication_failed, no_such_user}) ->
    Details = #{
        message => <<"The user requested (via 'authid') does not exist.">>
    },
    wamp_message:abort(Details, ?WAMP_NO_SUCH_PRINCIPAL);

abort_message({authentication_failed, invalid_scheme}) ->
    Details = #{
        message => <<"Unsupported authentication scheme.">>
    },
    wamp_message:abort(Details, ?WAMP_AUTHENTICATION_FAILED);

abort_message({authentication_failed, missing_signature}) ->
    Details = #{
        message => <<"The signature did not match.">>
    },
    wamp_message:abort(Details, ?WAMP_AUTHENTICATION_FAILED);

abort_message({authentication_failed, oauth2_invalid_grant}) ->
    Details = #{
        message => <<
            "The access token provided is expired, revoked, malformed,"
            " or invalid either because it does not match the Realm used in the"
            " request, or because it was issued to another peer."
        >>
    },
    wamp_message:abort(Details, ?WAMP_AUTHENTICATION_FAILED);

abort_message({authentication_failed, _}) ->
    %% bad_signature,
    Details = #{
        message => <<"The signature did not match.">>
    },
    wamp_message:abort(Details, ?WAMP_AUTHENTICATION_FAILED);

abort_message({unsupported_encoding, Encoding}) ->
    Details = #{
        message => <<
            "Unsupported message encoding '",
            (atom_to_binary(Encoding))/binary,
            "'."
        >>
    },
    wamp_message:abort(Details, ?WAMP_PROTOCOL_VIOLATION);

abort_message({invalid_options, missing_client_role}) ->
    Details = #{
        message => <<
            "No client roles provided. Please provide at least one client role."
        >>
    },
    wamp_message:abort(Details, ?WAMP_PROTOCOL_VIOLATION);

abort_message({missing_param, Param}) ->
    Details = #{
        message => <<
            "Missing value for required parameter '", Param/binary, "'."
        >>
    },
    wamp_message:abort(Details, ?WAMP_PROTOCOL_VIOLATION);

abort_message({unsupported_authmethod, Method}) ->
    Details = #{
        message => <<
            "Router could not use the '", Method/binary, "' authmethod requested."
            " Either the method is not supported by the Router or it is not"
            " allowed by the Realm."
        >>
    },
    wamp_message:abort(Details, ?WAMP_NOT_AUTH_METHOD);

abort_message({invalid_authmethod, Method}) ->
    Details = #{
        message => <<
            "Router could not use the authmethod requested ('",
            Method/binary,
            "')."
        >>
    },
    wamp_message:abort(Details, ?WAMP_NOT_AUTH_METHOD);

abort_message({Code, Term}) when is_atom(Term) ->
    abort_message({Code, ?CHARS2BIN(atom_to_list(Term))}).
