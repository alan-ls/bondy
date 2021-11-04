

# Module bondy_retained_message #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

This is experimental and does not scale with high traffic at the moment.

<a name="types"></a>

## Data Types ##


<a name="continuation()"></a>


### continuation() ###


<pre><code>
continuation() = #bondy_retained_continuation{realm = binary(), topic = binary(), session_id = <a href="#type-id">id()</a>, strategy = binary(), opts = list()}
</code></pre>


<a name="eot()"></a>


### eot() ###


<pre><code>
eot() = ?EOT
</code></pre>


<a name="evict_fun()"></a>


### evict_fun() ###


<pre><code>
evict_fun() = fun((<a href="#type-uri">uri()</a>, <a href="#type-t">t()</a>) -&gt; ok)
</code></pre>


<a name="match_opts()"></a>


### match_opts() ###


<pre><code>
match_opts() = #{eligible =&gt; [<a href="#type-id">id()</a>], exclude =&gt; [<a href="#type-id">id()</a>]}
</code></pre>


<a name="t()"></a>


### t() ###


<pre><code>
t() = #bondy_retained_message{valid_to = pos_integer(), publication_id = <a href="#type-id">id()</a>, match_opts = map(), details = map(), arguments = list() | undefined, arguments_kw = map() | undefined, payload = binary() | undefined}
</code></pre>


<a name="functions"></a>

## Function Details ##

<a name="evict_expired-0"></a>

### evict_expired/0 ###

<pre><code>
evict_expired() -&gt; non_neg_integer()
</code></pre>
<br />

Evict expired retained messages from all realms.

<a name="evict_expired-1"></a>

### evict_expired/1 ###

<pre><code>
evict_expired(Realm::<a href="#type-uri">uri()</a> | _) -&gt; non_neg_integer()
</code></pre>
<br />

Evict expired retained messages from realm `Realm`.

<a name="evict_expired-2"></a>

### evict_expired/2 ###

<pre><code>
evict_expired(Realm::<a href="#type-uri">uri()</a> | _, EvictFun::<a href="#type-evict_fun">evict_fun()</a> | undefined) -&gt; non_neg_integer()
</code></pre>
<br />

Evict expired retained messages from realm `Realm` or all realms if
wildcard '_' is used.
Evaluates function Fun for each entry passing Realm and Entry as arguments.

<a name="get-2"></a>

### get/2 ###

<pre><code>
get(Realm::<a href="#type-uri">uri()</a>, Topic::<a href="#type-uri">uri()</a>) -&gt; <a href="#type-t">t()</a> | undefined
</code></pre>
<br />

<a name="match-1"></a>

### match/1 ###

<pre><code>
match(Bondy_retained_continuation::<a href="#type-continuation">continuation()</a>) -&gt; {[<a href="#type-t">t()</a>] | <a href="#type-continuation">continuation()</a>} | <a href="#type-eot">eot()</a>
</code></pre>
<br />

<a name="match-4"></a>

### match/4 ###

<pre><code>
match(Realm::<a href="#type-uri">uri()</a>, Topic::<a href="#type-uri">uri()</a>, SessionId::<a href="#type-id">id()</a>, Strategy::binary()) -&gt; {[<a href="#type-t">t()</a>], <a href="#type-continuation">continuation()</a>} | <a href="#type-eot">eot()</a>
</code></pre>
<br />

<a name="match-5"></a>

### match/5 ###

<pre><code>
match(Realm::<a href="#type-uri">uri()</a>, Topic::<a href="#type-uri">uri()</a>, SessionId::<a href="#type-id">id()</a>, Strategy::binary(), Opts::<a href="/Volumes/Work/Leapsight/bondy/_build/default/lib/plum_db/doc/plum_db.md#type-fold_opts">plum_db:fold_opts()</a>) -&gt; {[<a href="#type-t">t()</a>], <a href="#type-continuation">continuation()</a>} | <a href="#type-eot">eot()</a>
</code></pre>
<br />

<a name="put-4"></a>

### put/4 ###

<pre><code>
put(Realm::<a href="#type-uri">uri()</a>, Topic::<a href="#type-uri">uri()</a>, Event::<a href="#type-wamp_event">wamp_event()</a>, MatchOpts::<a href="#type-match_opts">match_opts()</a>) -&gt; ok
</code></pre>
<br />

<a name="put-5"></a>

### put/5 ###

<pre><code>
put(Realm::<a href="#type-uri">uri()</a>, Topic::<a href="#type-uri">uri()</a>, Event::<a href="#type-wamp_event">wamp_event()</a>, MatchOpts::<a href="#type-match_opts">match_opts()</a>, TTL::non_neg_integer()) -&gt; ok
</code></pre>
<br />

<a name="size-1"></a>

### size/1 ###

<pre><code>
size(Mssg::<a href="#type-t">t()</a>) -&gt; integer()
</code></pre>
<br />

<a name="take-2"></a>

### take/2 ###

<pre><code>
take(Realm::<a href="#type-uri">uri()</a>, Topic::<a href="#type-uri">uri()</a>) -&gt; <a href="#type-t">t()</a> | undefined
</code></pre>
<br />

<a name="to_event-2"></a>

### to_event/2 ###

<pre><code>
to_event(Retained::<a href="#type-t">t()</a>, SubscriptionId::<a href="#type-id">id()</a>) -&gt; <a href="#type-wamp_event">wamp_event()</a>
</code></pre>
<br />
