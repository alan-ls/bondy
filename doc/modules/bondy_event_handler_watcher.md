

# Module bondy_event_handler_watcher #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)

Implements the event watcher capability as designed by Lager.

__Behaviours:__ [`gen_server`](gen_server.md).

<a name="functions"></a>

## Function Details ##

<a name="code_change-3"></a>

### code_change/3 ###

`code_change(OldVsn, State, Extra) -> any()`

<a name="handle_call-3"></a>

### handle_call/3 ###

`handle_call(X1, X2, State) -> any()`

<a name="handle_cast-2"></a>

### handle_cast/2 ###

`handle_cast(Event, State) -> any()`

<a name="handle_info-2"></a>

### handle_info/2 ###

`handle_info(Info, State) -> any()`

<a name="init-1"></a>

### init/1 ###

`init(X1) -> any()`

<a name="start-2"></a>

### start/2 ###

`start(Manager, Args) -> any()`

<a name="start-3"></a>

### start/3 ###

`start(Manager, Handler, Args) -> any()`

<a name="start_link-2"></a>

### start_link/2 ###

`start_link(Manager, Args) -> any()`

<a name="start_link-3"></a>

### start_link/3 ###

`start_link(Manager, Handler, Args) -> any()`

<a name="terminate-2"></a>

### terminate/2 ###

`terminate(Reason, State) -> any()`
