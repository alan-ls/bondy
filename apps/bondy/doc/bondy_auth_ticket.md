

# Module bondy_auth_ticket #
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

__Behaviours:__ [`bondy_auth`](bondy_auth.md).

<a name="types"></a>

## Data Types ##




### <a name="type-state">state()</a> ###


<pre><code>
state() = map()
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#authenticate-4">authenticate/4</a></td><td></td></tr><tr><td valign="top"><a href="#challenge-3">challenge/3</a></td><td></td></tr><tr><td valign="top"><a href="#init-1">init/1</a></td><td></td></tr><tr><td valign="top"><a href="#requirements-0">requirements/0</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="authenticate-4"></a>

### authenticate/4 ###

<pre><code>
authenticate(Ticket::binary(), DataIn::map(), Ctxt::<a href="bondy_auth.md#type-context">bondy_auth:context()</a>, CBState::<a href="#type-state">state()</a>) -&gt; {ok, DataOut::map(), CBState::<a href="#type-state">state()</a>} | {error, Reason::any(), CBState::<a href="#type-state">state()</a>}
</code></pre>
<br />

<a name="challenge-3"></a>

### challenge/3 ###

<pre><code>
challenge(Details::map(), AuthCtxt::<a href="bondy_auth.md#type-context">bondy_auth:context()</a>, State::<a href="#type-state">state()</a>) -&gt; {ok, Extra::map(), NewState::<a href="#type-state">state()</a>} | {error, Reason::any(), NewState::<a href="#type-state">state()</a>}
</code></pre>
<br />

<a name="init-1"></a>

### init/1 ###

<pre><code>
init(Ctxt::<a href="bondy_auth.md#type-context">bondy_auth:context()</a>) -&gt; {ok, State::<a href="#type-state">state()</a>} | {error, Reason::any()}
</code></pre>
<br />

<a name="requirements-0"></a>

### requirements/0 ###

<pre><code>
requirements() -&gt; <a href="bondy_auth.md#type-requirements">bondy_auth:requirements()</a>
</code></pre>
<br />

