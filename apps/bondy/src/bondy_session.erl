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
-module(bondy_session).
-include("bondy.hrl").
-include("bondy_uris.hrl").
-include("bondy_security.hrl").
-include_lib("wamp/include/wamp.hrl").

-define(SHUTDOWN_TIMEOUT, 5000).

%% Sessions are store in an in-memory sharded ets table
-define(SPACE, ?MODULE).
-define(TAB(Id), tuplespace:locate_table(?SPACE, Id)).

-define(SESSION_SEQ_POS, #bondy_session.seq).

-record(bondy_session, {
    id                              ::  id(),
    %% undefined when state_name == closed
    realm_uri                       ::  maybe(uri()),
    state_name = closed             ::  state_name(),
    persistent = true               ::  boolean(),
    subprotocol                     ::  subprotocol(),
    connection                      ::  bondy_connection:t(),
    agent                           ::  maybe(binary()),
    %% Sequence number used for ID generation
    seq = 0                         ::  non_neg_integer(),
    %% WAMP Peer Roles played by peer e.g. caller, callee, etc.
    roles                           ::  maybe(map()),
    %% Authentication
    anonymous = false               ::  boolean(),
    authid                          ::  maybe(bondy_rbac_user:username()),
    %% WAMP only specifies a single role a user can request
    %% when openning a session
    authrole                        ::  maybe(bondy_rbac_group:name()),
    %% Bondy allows the user to request more all the roles (groups) the user
    %% belongs too
    authroles                       ::  maybe([bondy_rbac_group:name()]),
    authmethod                      ::  maybe(binary()),
    authprovider                    ::  maybe(binary()),
    %% Authorization
    rbac_ctxt                       ::  maybe(bondy_rbac:context()),
    meta = #{}                      ::  map(),
    %% Expiration
    created_timestamp               ::  pos_integer(),
    expires_in                      ::  pos_integer() | infinity
}).


-record(bondy_session_ref, {
    realm_uri               ::  uri(),
    node                    ::  atom(),
    session_id              ::  maybe(id()),
    pid                     ::  maybe(pid() | list())
}).



-type t()                   ::  #bondy_session{}.
-type ref()                 ::  #bondy_session_ref{}.
-type state_name()          ::  closed
                                | challenging
                                | failed
                                | established
                                | shutting_down.

-type continuation()        ::  any() | undefined.

-type properties()              ::  #{
                                    id => integer(),
                                    agent => binary(),
                                    realm_uri => uri(),
                                    roles => map(),
                                    authid => binary(),
                                    authmethod => binary(),
                                    authprovider => binary(),
                                    authrole => binary(),
                                    authroles => binary(),
                                    persistent => boolean(),
                                    anonymous => boolean()
                                }.

-export_type([encoding/0]).
-export_type([frame_type/0]).
-export_type([properties/0]).
-export_type([ref/0]).
-export_type([t/0]).


-export([agent/1]).
-export([authid/1]).
-export([authmethod/1]).
-export([authorize/3]).
-export([authprovider/1]).
-export([authrole/1]).
-export([authroles/1]).
-export([close/1]).
-export([connection/1]).
-export([count/0]).
-export([created/1]).
-export([encoding/1]).
-export([erase_meta/2]).
-export([fetch/1]).
-export([get_meta/2]).
-export([get_meta/3]).
-export([id/1]).
-export([incr_seq/1]).
-export([ip_address/1]).
-export([is_anonymous/1]).
-export([is_feature_enabled/3]).
-export([is_local/1]).
-export([is_process_alive/1]).
-export([is_ref/1]).
-export([is_remote/1]).
-export([is_remote_ref/1]).
-export([is_type/1]).
-export([list/0]).
-export([list/1]).
-export([list_connections/1]).
-export([list_connections/2]).
-export([lookup/1]).
-export([lookup/2]).
-export([make_ref/1]).
-export([make_remote_ref/1]).
-export([new/3]).
-export([node/1]).
-export([peername/1]).
-export([pid/1]).
-export([put_meta/3]).
-export([real_ip_address/1]).
-export([realm_uri/1]).
-export([roles/1]).
-export([send/3]).
-export([set_state/3]).
-export([state_name/1]).
-export([subprotocol/1]).
-export([take_meta/2]).
-export([username/1]).

-compile({no_auto_import, [node/1]}).



%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc Returns a new wamp session (FSM) in a 'closed' state.
%% @end
%% -----------------------------------------------------------------------------
-spec new(
    Subprotocol :: binary() | subprotocol(),
    ConnOrPid :: bondy_connection:t() | pid(),
    Opts :: map()) -> {ok, t()} | {error, any(), t()}.

new(Subprotocol, Conn, Opts) ->
    try
        %% Validate the input
        {ok, Sub} = validate_subprotocol(Subprotocol),

        true == bondy_connection:is_type(Conn) orelse throw({badarg, Conn}),

        Session0 = set_properties(Opts, #bondy_session{}),

        IsPersistent = case Sub of
            {http, _, _} ->
                %% We force sessions not to persist if the procotol is HTTP
                false;
            _ ->
                true
        end,

        %% Create a closed session state
        Session = Session0#bondy_session{
            id = bondy_utils:get_id(global),
            persistent = IsPersistent,
            subprotocol = Sub,
            connection = Conn,
            created_timestamp = erlang:system_time(millisecond)
        },
        ok = maybe_store_new(Session),
        {ok, Session}

    catch
        throw:Reason ->
            {error, Reason, undefined};
        error:Reason ->
            {error, Reason, undefined}
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec is_type(any()) -> boolean().

is_type(#bondy_session{}) -> true;
is_type(_) -> false.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec is_ref(any()) -> boolean().

is_ref(#bondy_session_ref{}) -> true;
is_ref(_) -> false.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec is_remote_ref(any()) -> boolean().

is_remote_ref(#bondy_session_ref{node = Node}) ->
    Node =:= bondy_peer_service:mynode();

is_remote_ref(_) ->
    false.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec id(Session :: t() | ref()) -> id().


id(#bondy_session_ref{session_id = Id}) ->
    Id;
id(#bondy_session{id = Id}) ->
    Id.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec realm_uri(t() | id() | ref()) -> uri().

realm_uri(#bondy_session{realm_uri = Val}) ->
    Val;

realm_uri(#bondy_session_ref{realm_uri = Val}) ->
    Val;

realm_uri(Id) when is_integer(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.realm_uri).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec state_name(t() | id() | ref()) -> state_name().

state_name(#bondy_session{state_name = Val}) ->
    Val;

state_name(#bondy_session_ref{session_id = Id}) ->
    state_name(Id);

state_name(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.state_name).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec roles(t() | id() | ref()) -> map().

roles(#bondy_session{roles = Val}) ->
    Val;

roles(#bondy_session_ref{session_id = Id}) ->
    roles(Id);

roles(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.roles).


%% -----------------------------------------------------------------------------
%% @doc Returns true if the feature Feature is enabled for role Role.
%% @end
%% -----------------------------------------------------------------------------
-spec is_feature_enabled(
    Role :: atom(), Feature :: binary(), Session :: t() | id() | ref()) ->
    boolean().

is_feature_enabled(Role, Feature, #bondy_session{} = S) ->
    maps_utils:get_path([Role, Feature], S#bondy_session.roles, false);

is_feature_enabled(Role, Feature, #bondy_session_ref{session_id = Id}) ->
    is_feature_enabled(Role, Feature, Id);

is_feature_enabled(Role, Feature, Id) when is_integer(Id) ->
    Roles = ets:lookup_element(?TAB(Id), Id, #bondy_session.roles),
    maps_utils:get_path([Role, Feature], Roles, false).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec subprotocol(t() | id() | ref()) -> subprotocol().

subprotocol(#bondy_session{subprotocol = Val}) ->
    Val;

subprotocol(#bondy_session_ref{session_id = Id}) ->
    subprotocol(Id);

subprotocol(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.subprotocol).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec authid(t() | id() | ref()) -> binary().

authid(#bondy_session{authid = Val}) ->
    Val;

authid(#bondy_session_ref{session_id = Id}) ->
    authid(Id);

authid(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.authid).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec is_anonymous(t() | id() | ref()) -> boolean().

is_anonymous(#bondy_session{anonymous = Val}) ->
    Val;

is_anonymous(#bondy_session_ref{session_id = Id}) ->
    is_anonymous(Id);

is_anonymous(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.anonymous).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec username(t() | id() | ref()) -> binary().

username(Term) ->
    authid(Term).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec authrole(t() | id() | ref()) -> maybe(binary()).

authrole(#bondy_session{authrole = Val}) ->
    Val;

authrole(#bondy_session_ref{session_id = Id}) ->
    authrole(Id);

authrole(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.authrole).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec authroles(t() | id() | ref()) -> maybe([binary()]).

authroles(#bondy_session{authroles = Val}) ->
    Val;

authroles(#bondy_session_ref{session_id = Id}) ->
    authroles(Id);

authroles(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.authroles).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec authmethod(t() | id() | ref()) -> maybe(binary()).

authmethod(#bondy_session{authmethod = Val}) ->
    Val;

authmethod(#bondy_session_ref{session_id = Id}) ->
    authmethod(Id);

authmethod(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.authmethod).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec authprovider(t() | id() | ref()) -> binary().

authprovider(#bondy_session{authprovider = undefined}) ->
    <<"com.leapsight.bondy">>;

authprovider(#bondy_session{authprovider = Val}) ->
    Val;

authprovider(#bondy_session_ref{session_id = Id}) ->
    authprovider(Id);

authprovider(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.authprovider).


%% -----------------------------------------------------------------------------
%% @doc Returns the identifier for the owner of this session
%% @end
%% -----------------------------------------------------------------------------
-spec connection(t() | id() | ref()) -> bondy_connection:t().

connection(#bondy_session{connection = Val}) ->
    Val;

connection(#bondy_session_ref{session_id = Id}) ->
    connection(Id);

connection(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.connection).


%% -----------------------------------------------------------------------------
%% @doc Returns the identifier for the owner of this session
%% @end
%% -----------------------------------------------------------------------------
-spec encoding(t() | id() | ref()) -> encoding().

encoding(#bondy_session{connection = Conn}) ->
    bondy_connection:encoding(Conn);

encoding(#bondy_session_ref{session_id = Id}) ->
    encoding(Id);

encoding(Id) ->
    case ets:lookup_element(?TAB(Id), Id, #bondy_session.connection) of
        undefined ->
            undefined;
        Conn ->
            bondy_connection:encoding(Conn)
    end.


%% -----------------------------------------------------------------------------
%% @doc Returns the identifier for the owner of this session
%% @end
%% -----------------------------------------------------------------------------
-spec ip_address(Session :: t() | id() | ref()) -> inet:ip_address().

ip_address(#bondy_session{connection = C}) ->
    bondy_connection:ip_address(C);

ip_address(#bondy_session_ref{session_id = Id}) ->
    ip_address(Id);

ip_address(Id) ->
    P = ets:lookup_element(?TAB(Id), Id, #bondy_session.connection),
    C = bondy_connection:connection(P),
    bondy_connection:ip_address(C).


%% -----------------------------------------------------------------------------
%% @doc Returns the identifier for the owner of this session
%% @end
%% -----------------------------------------------------------------------------
-spec real_ip_address(Session :: t() | id() | ref()) ->
    maybe(inet:ip_address()).

real_ip_address(#bondy_session{connection = C}) ->
    bondy_connection:real_ip_address(C);

real_ip_address(#bondy_session_ref{session_id = Id}) ->
    real_ip_address(Id);

real_ip_address(Id) ->
    C = ets:lookup_element(?TAB(Id), Id, #bondy_session.connection),
    bondy_connection:real_ip_address(C).


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the pid of the process managing the transport that the session
%% identified by Id runs on.
%% @end
%% -----------------------------------------------------------------------------
-spec pid(Session :: t() | id() | ref()) -> pid().

pid(#bondy_session{connection = P}) ->
    bondy_connection:pid(P);

pid(#bondy_session_ref{pid = Pid}) ->
    Pid;

pid(Id) when is_integer(Id) ->
    P = ets:lookup_element(?TAB(Id), Id, #bondy_session.connection),
    bondy_connection:pid(P).


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the node of the process managing the transport that the session
%% identified by Id runs on.
%% @end
%% -----------------------------------------------------------------------------
-spec node(Session :: t() | id() | ref()) -> atom().

node(#bondy_session{connection = P}) ->
    bondy_connection:node(P);

node(#bondy_session_ref{node = Node}) ->
    Node;

node(Id) when is_integer(Id) ->
    P = ets:lookup_element(?TAB(Id), Id, #bondy_session.connection),
    bondy_connection:node(P).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec created(Session :: t() | id() | ref()) -> calendar:date_time().

created(#bondy_session{created_timestamp = Val}) ->
    Val;

created(#bondy_session_ref{session_id = Id}) ->
    created(Id);

created(Id) when is_integer(Id) ->
    #bondy_session{created_timestamp = Val} = fetch(Id),
    Val.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec agent(Session :: t() | id() | ref()) -> maybe(binary()).

agent(#bondy_session{agent = Val}) ->
    Val;

agent(#bondy_session_ref{session_id = Id}) ->
    agent(Id);

agent(Id) when is_integer(Id) ->
    ets:lookup_element(?TAB(Id), Id, #bondy_session.agent).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec make_ref(Session :: t()) -> bondy:ref().

make_ref(#bondy_session{} = Session) ->
    bondy:make_ref(
        Session#bondy_session.realm_uri,
        Node,
        pid(Session),
        Session#bondy_session.id
    );

make_ref(Id) when is_integer(Id) ->
    make_ref(fetch(Id)).


%% -----------------------------------------------------------------------------
%% @doc Converts a (local) ref into a remote ref
%% @end
%% -----------------------------------------------------------------------------
-spec make_remote_ref(t()) -> ref().

make_remote_ref(#bondy_session{} = Session) ->
    #bondy_session_ref{
        realm_uri = Session#bondy_session.realm_uri,
        session_id = Session#bondy_session.id,
        node = node(Session),
        pid = undefined
    };

make_remote_ref(#bondy_session_ref{pid = Pid} = Ref) when is_pid(Pid) ->
    Ref#bondy_session_ref{
        pid = undefined
    };

make_remote_ref(#bondy_session_ref{} = Ref) ->
    Ref;

make_remote_ref(Id) when is_integer(Id) ->
    make_remote_ref(fetch(Id)).


%% -----------------------------------------------------------------------------
%% @doc Returns `true' is the peer is connected on a different Bondy node,
%% `false' otherwise.
%% @end
%% -----------------------------------------------------------------------------
-spec is_local(t() | id() | ref()) -> boolean().

is_local(Session) ->
    node(Session) =:= bondy_peer_service:mynode().


%% -----------------------------------------------------------------------------
%% @doc Returns `true' is the peer is connected on a different Bondy node,
%% `false' otherwise.
%% @end
%% -----------------------------------------------------------------------------
-spec is_remote(t() | id() | ref()) -> boolean().

is_remote(Session) ->
    not is_local(Session).


%% -----------------------------------------------------------------------------
%% @doc Returns true is the connection process is alive, `false' otherwise.
%% Fails with a bad arguyment exception is the peer does not have a connection
%% process (See {@link pid/1}.
%% @end
%% -----------------------------------------------------------------------------
-spec is_process_alive(t() | id() | ref()) -> boolean() | no_return().

is_process_alive(Session) ->
    erlang:is_process_alive(pid(Session)).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec peername(Session :: t() | id() | ref()) -> peername().

peername(#bondy_session{connection = Conn}) ->
    conn_peername(Conn);

peername(#bondy_session_ref{session_id = Id}) ->
    peername(Id);

peername(Id) when is_integer(Id) ->
    #bondy_session{connection = Conn} = fetch(Id),
    conn_peername(Conn).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec incr_seq(t() | id() | ref()) -> integer().

incr_seq(#bondy_session{id = Id}) ->
    incr_seq(Id);

incr_seq(#bondy_session_ref{session_id = Id}) ->
    incr_seq(Id);

incr_seq(Id) when is_integer(Id), Id >= 0 ->
    ets:update_counter(?TAB(Id), Id, {?SESSION_SEQ_POS, 1, ?MAX_ID, 0}).


%% -----------------------------------------------------------------------------
%% @doc
%% Returns the number of sessions in the tuplespace.
%% @end
%% -----------------------------------------------------------------------------
-spec count() -> non_neg_integer().

count() ->
    tuplespace:size(?SPACE).


%% -----------------------------------------------------------------------------
%% @doc
%% Retrieves the session identified by Id from the tuplespace or 'not_found'
%% if it doesn't exist.
%% @end
%% -----------------------------------------------------------------------------
-spec lookup(id() | ref()) -> {ok, t()} | {error, not_found}.

lookup(#bondy_session_ref{realm_uri = RealmUri, session_id = Id}) ->
    lookup(RealmUri, Id);

lookup(Id) when is_integer(Id) ->
    do_lookup(Id).


%% -----------------------------------------------------------------------------
%% @doc
%% Retrieves the session identified by Id from the tuplespace or 'not_found'
%% if it doesn't exist.
%% @end
%% -----------------------------------------------------------------------------
-spec lookup(uri(), id()) -> {ok, t()} | {error, not_found}.

lookup(RealmUri, Id) ->
    case do_lookup(Id) of
        {ok, #bondy_session{realm_uri = RealmUri}} = OK ->
            OK;
        {ok, #bondy_session{}} ->
            {error, not_found};
        Error ->
            Error
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% Retrieves the session identified by Id from the tuplespace. If the session
%% does not exist it fails with reason '{badarg, Id}'.
%% @end
%% -----------------------------------------------------------------------------
-spec fetch(id() | ref()) -> t() | no_return().

fetch(#bondy_session_ref{session_id = Id}) ->
    fetch(Id);

fetch(Id) when is_integer(Id) ->
    case lookup(Id) of
        {ok, Session} ->
            Session;
        {error, not_found} ->
            error({badarg, Id})
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
%% @TODO provide a limit and itereate on each table providing a custom
%% continuation
-spec list() -> [t()].

list() ->
    Tabs = tuplespace:tables(?SPACE),
    lists:append([ets:tab2list(T) || T <- Tabs]).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
%% @TODO provide a limit and itereate on each table providing a custom
%% continuation
-spec list(N :: integer() | continuation()) ->
    {[bondy_connection:t()], continuation()}.

list(N) when is_integer(N) ->
    %% TODO
    {list(), undefined};

list(undefined) ->
    %% TODO
    {[], undefined}.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec list_connections(N :: pos_integer()) ->
    [bondy_connection:t()].

list_connections(N) ->
    list_connections('_', N).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec list_connections(RealmUri :: uri(), N :: pos_integer()) ->
    [bondy_connection:t()].

list_connections(RealmUri, N) when is_integer(N), N >= 1 ->
    Tabs = tuplespace:tables(?SPACE),
    do_list_connections(Tabs, RealmUri, N).



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec get_meta(Key :: any(), Session :: t()) -> any().

get_meta(Key, #bondy_session{meta = Map}) ->
    maps:get(Key, Map).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec get_meta(Key :: any(), Session :: t(), Default :: any()) -> any().

get_meta(Key, #bondy_session{meta = Map}, Default) ->
    maps:get(Key, Map, Default).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec put_meta(Key :: any(), Value :: any(), Session :: t()) -> Session :: t().

put_meta(Key, Value, #bondy_session{meta = Map} = Session) ->
    NewSession = Session#bondy_session{meta = maps:put(Key, Value, Map)},
    maybe_store(NewSession).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec take_meta(Key :: any(), Session :: t()) ->
    {Value :: any(), NewSession :: t()}.

take_meta(Key, #bondy_session{meta = Map} = Session) ->
    {Value, NewMap} = maps:take(Key, Map),
    NewSession = Session#bondy_session{meta = NewMap},
    {Value, maybe_store(NewSession)}.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec erase_meta(Key :: any(), Session :: t()) -> NewSession :: t().

erase_meta(Key, #bondy_session{meta = Map} = Session) ->
    NewSession = Session#bondy_session{meta = maps:remove(Key, Map)},
    maybe_store(NewSession).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec close(Session :: t()) -> ok.

close(#bondy_session{id = Id} = S) ->

    ok = bondy_router:on_session_close(bondy_context:new(S)),
    ok = bondy_session_monitor:demonitor(S),
    true = ets:delete(?TAB(Id), Id),

    %% FIXME {session_closed, Session}
    RealmUri = S#bondy_session.realm_uri,
    Agent = S#bondy_session.agent,
    Peername = peername(S),
    Now = erlang:system_time(millisecond),
    Secs = (Now - S#bondy_session.created_timestamp) / 1000,
    ok = bondy_event_manager:notify(
        {session_closed, Id, RealmUri, Agent, Peername, Secs}
    ),

    _ = lager:debug(
        "Session closed; session_id=~p, realm=~s",
        [Id, RealmUri]
    ),

    ok;

close(Id) when is_integer(Id) ->
    case lookup(Id) of
        {ok, #bondy_session{} = S} ->
            close(S);
        _ ->
            ok
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec set_state(
    StateName :: closed | challenging | failed | shutting_down,
    Map :: properties(),
    Session :: t()) -> NewSession :: t().

set_state(Name, Map, #bondy_session{} = Session) ->
    Name == closed orelse
    Name == challenging orelse
    Name == established orelse
    Name == failed orelse
    Name == shutting_down orelse error(badarg),

    maybe_store(set_properties(Map, Session#bondy_session{state_name = Name})).




%% -----------------------------------------------------------------------------
%% @doc Returns 'ok' or an exception.
%% @throws {not_authorized, Reason :: binary()}.
%% @end
%% -----------------------------------------------------------------------------
-spec authorize(
    Permission :: binary(), Resource :: binary(), Session :: t()) ->
    ok | no_return().

authorize(Permission, Resource, #bondy_session{} = S) ->
    case bondy_realm:is_security_enabled(S#bondy_session.realm_uri) of
        true ->
            try
                Ctxt = get_rbac_ctxt(S),
                bondy_rbac:authorize(Permission, Resource, Ctxt)
            catch
                error:invalid_context ->
                    %% We force to refresh and store the context
                    NewCtxt = get_rbac_ctxt(
                        S#bondy_session{rbac_ctxt = undefined}
                    ),
                    bondy_rbac:authorize(Permission, Resource, NewCtxt)
            end;

        false ->
            ok
    end.


%% -----------------------------------------------------------------------------
%% @doc Sends a message `Msg' to a local peer with session `Session' using
%% options `Opts'. `Session' can be a session identifier, a session reference
%% or a session type.
%% This function is used by the router (dealer | broker) to send WAMP messages
%% to local peers.
%% Opts is a map with the following keys:
%%
%% * timeout - timeout in milliseconds (defaults to 10000)
%% * enqueue (boolean) - if the peer is not reachable and this value is true,
%% bondy will enqueue the message so that the peer can resume the session and
%% consume all enqueued messages.
%% @end
%% -----------------------------------------------------------------------------
-spec send(Msg :: wamp_message:t(), Opts :: map(), Session :: t() | ref()) ->
    ok | {error, any()}.

send(Msg, Opts, #bondy_session_ref{} = Ref) ->
    send(Msg, Opts, fetch(Ref));

send(Msg, Opts0, #bondy_session{state_name = established} = Session)
when is_record(Msg, error); is_record(Msg, result); is_record(Msg, event) ->
    Opts = validate_send_opts(Opts0),
    Timeout = maps:get(timeout, Opts),
    Conn = Session#bondy_session.connection,

    case bondy_connection:async_send(Conn, Msg, Timeout) of
        ok ->
            ok;
        {error, nosocket} ->
            %% Websockets dot not allow us to do an ascyn_send
            send_or_enqueue(Msg, Opts, Session);
        {error, _} = Error ->
            %& Maybe enqueue here
            Error
    end;

send(Msg, Opts0, #bondy_session{} = Session) ->
    Opts = validate_send_opts(Opts0),
    send_or_enqueue(Msg, Opts, Session).



%% =============================================================================
%% PRIVATE: STORAGE
%% =============================================================================



%% @private
conn_peername(Connection) ->
    case bondy_connection:real_peername_bin(Connection) of
        undefined ->
            bondy_connection:peername_bin(Connection);
        Value ->
            Value
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec maybe_store_new(Session :: t()) -> Session :: t().

maybe_store_new(#bondy_session{persistent = true, id = Id} = Session) ->
    case ets:insert_new(?TAB(Id), Session) of
        true ->
            ok = bondy_session_monitor:monitor(Session),
            Session;
        false ->
            error({integrity_constraint_violation, Id})
    end;

maybe_store_new(Session) ->
    Session.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec maybe_store(Session :: t()) -> ok.

maybe_store(#bondy_session{persistent = true, id = Id} = S) ->
    true = ets:insert(?TAB(Id), S),
    S;

maybe_store(S) ->
    S.


%% @private
-spec do_lookup(id()) -> {ok, t()} | {error, not_found}.

do_lookup(Id) ->
    Tab = ?TAB(Id),
    case ets:lookup(Tab, Id)  of
        [#bondy_session{} = Session] ->
            {ok, Session};
        [] ->
            {error, not_found}
    end.



%% @private
do_list_connections([], _, _) ->
    ?EOT;

do_list_connections([Tab | Tabs], RealmUri, N)
when is_binary(RealmUri) orelse RealmUri == '_' ->
    Pattern0 = select_pattern(),
    Pattern1 = setelement(#bondy_session.realm_uri, Pattern0, '$1'),
    Pattern2 = setelement(#bondy_session.connection, Pattern1, '$2'),

    Conds = case RealmUri of
        '_' -> [];
        _ ->  [{'=:=', '$1', RealmUri}]
    end,

    Projection = ['$2'],

    MS = [{Pattern2, Conds, Projection}],

    case ets:select(Tab, MS, N) of
        {L, Cont} ->
            FunCont = fun() ->
                do_list_connections({continuation, Tabs, RealmUri, N, Cont})
            end,
           {L, FunCont};
        ?EOT ->
            do_list_connections(Tabs, RealmUri, N)
    end.


%% @private
do_list_connections({continuation, [], _, _, ?EOT}) ->
    ?EOT;

do_list_connections({continuation, Tabs, RealmUri, N, ?EOT}) ->
    do_list_connections(Tabs, RealmUri, N);

do_list_connections({continuation, Tabs, RealmUri, N, Cont}) ->
    case ets:select(Cont) of
        ?EOT ->
            ?EOT;
        {L, Cont} ->
            FunCont = fun() ->
                do_list_connections({continuation, Tabs, RealmUri, N, Cont})
            end,
            {L, FunCont}
    end.


%% @private
select_pattern() ->
    case persistent_term:get({?MODULE, select_pattern}, undefined) of
        undefined ->
            Size = record_info(size, bondy_session),
            Pattern = setelement(
                1, erlang:make_tuple(Size, '_'), bondy_session
            ),
            _ = persistent_term:set({?MODULE, select_pattern}, Pattern),
            Pattern;
        Pattern ->
            Pattern
    end.


%% =============================================================================
%% PRIVATE: OPERATIONS
%% =============================================================================



%% @private
get_rbac_ctxt(#bondy_session{persistent = true} = S) ->
    %% We access it from ets storage
    Id = S#bondy_session.id,
    Ctxt = ets:lookup_element(
        ?TAB(Id), Id, S#bondy_session.realm_uri
    ),
    S#bondy_session{rbac_ctxt = Ctxt};

get_rbac_ctxt(#bondy_session{rbac_ctxt = undefined} = S) ->
    Ctxt = bondy_rbac:get_context(
        S#bondy_session.realm_uri,
        S#bondy_session.id,
        S#bondy_session.anonymous
    ),
    ok = maybe_store(S#bondy_session{rbac_ctxt = Ctxt}),
    Ctxt;

get_rbac_ctxt(#bondy_session{rbac_ctxt = Ctxt}) ->
    Ctxt.





%% @private
validate_send_opts(Opts) ->
    maps_utils:validate(Opts, #{
        timeout => #{
            required => true,
            datatype => timeout,
            default => ?SEND_TIMEOUT
        },
        enqueue => #{
            required => true,
            datatype => boolean,
            default => false
        }
    }).


%% @private
send_or_enqueue(Msg, Opts, #bondy_session{connection = Conn} = Session) ->
    Timeout = maps:get(timeout, Opts),
    Enqueue = maps:get(enqueue, Opts),

    case bondy_connection:send(Conn, Msg, Timeout) of
        ok ->
            ok;

        {error, noproc} when Enqueue ->
            %% The handler no longer exists
            maybe_enqueue(Msg, Session);

        {error, timeout} when Enqueue ->
            maybe_enqueue(Msg, Session);

        {error, Reason} = Error ->
            _ = lager:info(
                "Could not deliver message to WAMP peer; "
                "reason=~p, session_id=~p, message_type=~p",
                [Reason, Session#bondy_session.id, element(1, Msg)]
            ),
            Error
    end.


%% @private
maybe_enqueue(_Msg, _Session) ->
    %% TODO Enqueue for session resumption
    ok.


%% =============================================================================
%% PRIVATE: UTILS
%% =============================================================================



%% @private
validate_subprotocol(Term) ->
    case bondy_data_validators:subprotocol(Term) of
        {ok, _} =
            OK -> OK;
        true ->
            {ok, Term};
        false ->
            throw(invalid_subprotocol)
    end.


%% ------------------------------------------------------------------------
%% private
%% @doc
%% Merges the client provided role features with the ones provided by
%% the router. This will become the feature set used by the router on
%% every session request.
%% @end
%% ------------------------------------------------------------------------
parse_roles(Roles) ->
    parse_roles(maps:keys(Roles), Roles).


%% @private
parse_roles([], Roles) ->
    Roles;

parse_roles([caller|T], Roles) ->
    F = bondy_utils:merge_map_flags(
        maps:get(caller, Roles), ?CALLER_FEATURES),
    parse_roles(T, Roles#{caller => F});

parse_roles([callee|T], Roles) ->
    F = bondy_utils:merge_map_flags(
        maps:get(callee, Roles), ?CALLEE_FEATURES),
    parse_roles(T, Roles#{callee => F});

parse_roles([subscriber|T], Roles) ->
    F = bondy_utils:merge_map_flags(
        maps:get(subscriber, Roles), ?SUBSCRIBER_FEATURES),
    parse_roles(T, Roles#{subscriber => F});

parse_roles([publisher|T], Roles) ->
    F = bondy_utils:merge_map_flags(
        maps:get(publisher, Roles), ?PUBLISHER_FEATURES),
    parse_roles(T, Roles#{publisher => F});

parse_roles([_|T], Roles) ->
    parse_roles(T, Roles).


%% @private
-spec set_properties(properties(), t()) -> t() | no_return().

set_properties(Opts, Session)  when is_map(Opts) ->
    maps:fold(fun set_properties/3, Session, Opts).


%% @private
set_properties(id, V, Session) when is_integer(V) ->
    Session#bondy_session{id = V};

set_properties(realm_uri, V, Session) when is_binary(V) ->
    Session#bondy_session{realm_uri = V};

set_properties(agent, V, Session) when is_binary(V) ->
    Session#bondy_session{agent = V};

set_properties(persistent, V, Session) when is_boolean(V) ->
    Session#bondy_session{persistent = V};

set_properties(authid, V, Session) when is_binary(V) ->
    Session#bondy_session{authid = V};

set_properties(authmethod, V, Session) when is_binary(V) ->
    Session#bondy_session{authmethod = V};

set_properties(authprovider, V, Session) when is_binary(V) ->
    Session#bondy_session{authprovider = V};

set_properties(authrole, V, Session) when is_binary(V) ->
    Session#bondy_session{authrole = V};

set_properties(authroles, V, Session) when is_list(V) ->
    Session#bondy_session{authroles = V};

set_properties(created_timestamp, V, Session) when is_integer(V) ->
    Session#bondy_session{created_timestamp = V};

set_properties(expires_in, V, Session) when is_integer(V) ->
    Session#bondy_session{expires_in = V};


set_properties(roles, Roles, Session) when is_map(Roles) ->
    length(maps:keys(Roles)) > 0 orelse
        error({invalid_options, missing_client_role}),
    Session#bondy_session{roles = parse_roles(Roles)};

set_properties(K, V, _) ->
    error({invalid_option, {K, V}}).

