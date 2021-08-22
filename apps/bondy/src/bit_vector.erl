%% =============================================================================
%%  bit_vector.erl
%%  Original source from gist by Lukas Larsson
%%  https://gist.github.com/garazdawi/48f1284c0d533ab5a39eeac6f8ff99a0
%%
%%  Copyright (c) 2019 Leapsight. All rights reserved.
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
%% @doc A bit vector implemented using atomics.
%% > Atomics are not tied to the current process and are automatically garbage
%% collected when they are no longer referenced.
%% @end
%% -----------------------------------------------------------------------------
-module(bit_vector).

-export([new/1]).
-export([get/2]).
-export([set/2]).
-export([clear/2]).
-export([flip/2]).
-export([print/1]).
-export([size/1]).
-export([union/2]).
-export([intersection/2]).



%% =============================================================================
%% API
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
new(Size) ->
    Words = (Size + 63) div 64,
    {?MODULE, Size, atomics:new(Words, [{signed, false}])}.


%% -----------------------------------------------------------------------------
%% @doc Returns the size of the bit vector.
%% @end
%% -----------------------------------------------------------------------------
size({?MODULE, Size, _}) ->
    Size.


%% -----------------------------------------------------------------------------
%% @doc Returns the value of the Nth bit.
%% @end
%% -----------------------------------------------------------------------------
get(Bix, {?MODULE, _Size, Aref}) ->
    Wix = (Bix div 64) + 1,
    Mask = (1 bsl (Bix rem 64)),
    case atomics:get(Aref, Wix) band Mask of
        0 -> 0;
        Mask -> 1
    end.


%% -----------------------------------------------------------------------------
%% @doc Sets the value of the Nth bit to 1.
%% @end
%% -----------------------------------------------------------------------------
set(Bix, {?MODULE, _Size, Aref}) ->
    Mask = (1 bsl (Bix rem 64)),
    update(Bix, Aref, fun(Word) -> Word bor Mask end).


%% -----------------------------------------------------------------------------
%% @doc Sets the value of the Nth bit to 0.
%% @end
%% -----------------------------------------------------------------------------
clear(Bix, {?MODULE, _Size, Aref}) ->
    Mask = bnot (1 bsl (Bix rem 64)),
    update(Bix, Aref, fun(Word) -> Word band Mask end).


%% -----------------------------------------------------------------------------
%% @doc Flips the value of the Nth bit.
%% @end
%% -----------------------------------------------------------------------------
flip(Bix, {?MODULE, _Size, Aref}) ->
    Mask = (1 bsl (Bix rem 64)),
    update(Bix, Aref, fun(Word) -> Word bxor Mask end).


%% -----------------------------------------------------------------------------
%% @doc Prints the bit vector to the console
%% @end
%% -----------------------------------------------------------------------------
print({?MODULE, Size, _Aref} = BV) ->
    print(BV, Size-1).


%% -----------------------------------------------------------------------------
%% @doc Returns a new bit vector that is the result of the logical or between
%% the provided bit vectors.
%% @end
%% -----------------------------------------------------------------------------
union({?MODULE, Size, _} = A, {?MODULE, Size, _} = B) ->
    union(A, B, new(Size), Size - 1);

union(_, _) ->
    error(badarg).


%% -----------------------------------------------------------------------------
%% @doc Returns a new bit vector that is the result of the logical and between
%% the provided bit vectors.
%% @end
%% -----------------------------------------------------------------------------
intersection({?MODULE, Size, _} = A, {?MODULE, Size, _} = B) ->
    intersection(A, B, new(Size), Size - 1);

intersection(_, _) ->
    error(badarg).



%% =============================================================================
%% PRIVATE
%% =============================================================================



update(Bix, Aref, Fun) ->
    Wix = (Bix div 64) + 1,
    update_loop(Wix, Aref, Fun, atomics:get(Aref, Wix)).

update_loop(Wix, Aref, Fun, Expected) ->
    case atomics:compare_exchange(Aref, Wix, Expected, Fun(Expected)) of
        ok ->
            ok;
        Was ->
            update_loop(Wix, Aref, Fun, Was)
    end.


union(A, B, C, 0 = Slot) ->
    Or = get(Slot, A) bor get(Slot, B),
    ok = maybe_set(Or, C, Slot),
    C;

union(A, B, C, Slot) ->
    Or = get(Slot, A) bor get(Slot, B),
    ok = maybe_set(Or, C, Slot),
    union(A, B, C, Slot - 1).


intersection(A, B, C, 0 = Slot) ->
    And = get(Slot, A) band get(Slot, B),
    ok = maybe_set(And, C, Slot),
    C;

intersection(A, B, C, Slot) ->
    And = get(Slot, A) band get(Slot, B),
    ok = maybe_set(And, C, Slot),
    intersection(A, B, C, Slot - 1).


maybe_set(1, C, Slot) -> set(Slot, C);
maybe_set(0, _, _) -> ok.


print(BV, 0) ->
    io:format("~B~n",[get(0, BV)]);
print(BV, Slot) ->
    io:format("~B",[get(Slot, BV)]),
    print(BV, Slot-1).