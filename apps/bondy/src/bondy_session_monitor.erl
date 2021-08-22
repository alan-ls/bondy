-module(bondy_session_monitor).
-behaviour(gen_server).
-include("bondy.hrl").
-include_lib("wamp/include/wamp.hrl").

-record(state, {}).

%% API
-export([start_link/0]).
-export([monitor/1]).
-export([demonitor/1]).


%% GEN_SERVER CALLBACKS
-export([init/1]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).
-export([handle_call/3]).
-export([handle_cast/2]).



%% =============================================================================
%% API
%% =============================================================================



%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


%% -----------------------------------------------------------------------------
%% @doc
%% Creates a new session provided the RealmUri exists or can be dynamically
%% created.
%% It calls {@link bondy_session:new/4} which will fail with an exception
%% if the realm does not exist or cannot be created.
%%
%% This function also sets up a monitor for the calling process which is
%% assummed to be the client connection process e.g. WAMP connection. In case
%% the connection crashes it performs the cleanup of any session data that
%% should not be retained.
%% -----------------------------------------------------------------------------
-spec monitor(bondy_session:t()) -> ok | no_return().

monitor(Session) ->
    case gen_server:call(?MODULE, {monitor, Session}, 5000) of
        ok ->
            Session;
        Error ->
            Error
    end.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec demonitor(bondy_session:t()) -> ok.

demonitor(Session) ->
    gen_server:cast(?MODULE, {demonitor, Session}).



%% =============================================================================
%% GEN_SERVER CALLBACKS
%% =============================================================================



init([]) ->
    {ok, #state{}}.


handle_call({monitor, Session}, _From, State) ->
    Id = bondy_session:id(Session),
    Uri = bondy_session:realm_uri(Session),
    Key = {session, Uri, Id},
    Pid = bondy_session:pid(Session),

    true = gproc:reg_other({n, l, Key}, Pid),
    ok = gproc_monitor:subscribe({n, l, Key}),

    {reply, ok, State};

handle_call(Event, From, State) ->
    _ = lager:error(
        "Error handling call, reason=unsupported_event, event=~p, from=~p", [Event, From]
    ),
    {reply, {error, {unsupported_call, Event}}, State}.


handle_cast({demonitor, Session}, State) ->
    Id = bondy_session:id(Session),
    Uri = bondy_session:realm_uri(Session),
    ok = gproc_monitor:unsubscribe({n, l, {session, Uri, Id}}),
    _ = lager:debug(
        "Demonitoring session connection; realm=~p, session_id=~p",
        [Uri, Id]
    ),
    {noreply, State};

handle_cast(Event, State) ->
    _ = lager:error(
        "Error handling cast, reason=unsupported_event, event=~p", [Event]
    ),
    {noreply, State}.


handle_info({gproc_monitor, {n, l, {session, Uri, Id}}, undefined}, State) ->
    %% The connection process has died or closed
    _ = lager:debug(
        "Connection process for session terminated, cleaning up; "
        "realm=~p, session_id=~p",
        [Uri, Id]
    ),
    case bondy_session:lookup(Id) of
        {ok, Session} ->
            cleanup(Session);
        {error, not_found} ->
            ok
    end,
    {noreply, State};

handle_info({gproc_monitor, {n, l, {session, Uri, Id}}, Pid}, State) ->
    _ = lager:debug(
        "Monitoring session connection; realm=~p, session_id=~p, pid=~p",
        [Uri, Id, Pid]
    ),
    {noreply, State};

handle_info(Info, State) ->
    _ = lager:debug("Unexpected message, message=~p", [Info]),
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.



%% =============================================================================
%% PRIVATE
%% =============================================================================


%% TODO we should close the session not the ctxt?
cleanup(Session) ->
    bondy_session:terminate(Session).