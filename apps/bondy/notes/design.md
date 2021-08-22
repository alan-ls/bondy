
-spec bondy:send(wamp_message(), map(), Ref :: bondy_wamp_session:ref()).

bondy:send(M, Opts, Ref)
    If session_ref is local
        Session = bondy_session:fetch(Ref)
        bondy_session:send(M, Opts, Session)
            bondy_connection:send
                send to Pid | send to Socket
    else
        forward(M, Opts, Ref)



{proc, Uri, Match, bondy_session_ref}
{subs, Uri, Match, bondy_session_ref}


call(foo, Args, ArgKw, Opts) ->
    [bondy_session_ref] = L = reg:get_callees(Uri, Match)
    bondy_session_ref = lb:choose(L)
    bondy:send(Call, bondy_session_ref)

