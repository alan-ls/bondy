%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-module(bloom_filter).

-record(bloom_filter, {
    size        ::  pos_integer(),
    %% error probability
    p           ::  float(),
    %% maximum number of elements
    capacity    ::  pos_integer(),
    %% 2^slice_size = m, the size of each slice (bitvector)
    slice_size  ::  pos_integer(),
    %% This bloom filter implementation consists of partitioning the M bits
    %% among the k hash functions, thus creating k slices of m =
    %% M/k bits.
    %% Each hash function hi, with 1 < i < k, produces an index
    %% over m for its respective slice.
    slices      ::  [bit_vector:t()]
}).

-type t()       ::  #bloom_filter{}.

-export_type([t/0]).

-export([new/1]).
-export([new/2]).
-export([new/3]).
-export([size/1]).
-export([capacity/1]).
-export([member/2]).
-export([add/2]).
-export([union/2]).
%% -export([new/4]).
%% -export([bloom/1]).
%% -export([bloom/2]).
%% -export([member/2]).
%% -export([add/2]).
%% -export([size/1]).
%% -export([capacity/1]).



%% =============================================================================
%% API
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc Returns a new bloom filter with fixed capacity based on the
%% requested `Capacity' and error probability of `0.001'.
%% The actual capacity will be equal or greater than the requested one.
%%
%% @end
%% -----------------------------------------------------------------------------
-spec new(Capacity :: pos_integer()) -> t().

new(Capacity) ->
    new(Capacity, 0.001).


%% -----------------------------------------------------------------------------
%% @doc Returns a new bloom filter with fixed capacity `Capacity' and error
%% probability of `P'.
%% @end
%% -----------------------------------------------------------------------------
new(Capacity, P) when
is_number(Capacity), Capacity > 0, is_float(P), P > 0, P < 1, Capacity >= 4/P ->
    %% N >= 4/rule of thumb; due to double hashing
    new(size, Capacity, P).


%% -----------------------------------------------------------------------------
%% @doc Returns a new bloom filter with fixed capacity `Capacity' and error
%% probability of `P'.
%% @end
%% -----------------------------------------------------------------------------
-spec new(size | bits, Capacity :: pos_integer(), P :: float()) ->
    t() | no_return().

new(bits, Capacity, P) ->
    SliceCount = 1 + trunc(log2(1 / P)),
    init(SliceCount, Capacity, P);

new(size, Capacity, P) ->
    SliceCount = 1 + trunc(log2(1 / P)),
    FPP = math:pow(P, 1 / SliceCount),
    SliceSize = 1 + trunc(-log2(1 - math:pow(1 - FPP, 1 / Capacity))),
    init(SliceCount, SliceSize, P).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec size(t()) -> pos_integer().

size(#bloom_filter{size = Size}) -> Size.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec capacity(t()) -> pos_integer().

capacity(#bloom_filter{capacity = Capacity}) -> Capacity.


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
member(Element, #bloom_filter{slice_size = SliceSize} = BF) ->
    hash_member(make_hashes(SliceSize, Element), BF).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
add(Element, #bloom_filter{slice_size = SliceSize} = BF) ->
    hash_add(make_hashes(SliceSize, Element), BF).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec union(t(), t()) -> t() | no_return().

union(
    #bloom_filter{capacity = N, slice_size = S, slices = Sa} = _A,
    #bloom_filter{capacity = N, slice_size = S, slices = Sb} = _B
) when length(Sa) ==  length(Sb) ->
    error(not_implemented);

union(_, _) ->
    error(badarg).



%% =============================================================================
%% PRIVATE
%% =============================================================================



init(SliceCount, SliceSize, P) when is_integer(SliceSize) ->
    FPP = math:pow(P, 1 / SliceCount),
    M = 1 bsl SliceSize,
    Capacity = trunc(math:log(1 - FPP) / math:log(1 - 1 / M)),
    #bloom_filter{
        size = 0,
        p = P,
        capacity = Capacity,
        slice_size = SliceSize,
        slices = [
            bit_vector:new(1 bsl SliceSize) || _ <- lists:seq(1, SliceCount)
        ]
    }.


%% @private
log2(X) ->
    math:log(X) / math:log(2).


%% @private
hash_add(Hashes, BF) ->
    Mask = 1 bsl BF#bloom_filter.slice_size - 1,
    {I1, I0} = make_indexes(Mask, Hashes),

    case all_set(Mask, I1, I0, BF#bloom_filter.slices) of
        true ->
            BF;
        false ->
            BF#bloom_filter{
                size = BF#bloom_filter.size + 1,
                slices = set_bits(Mask, I1, I0, BF#bloom_filter.slices, [])
            }
    end.


%% @private
set_bits(_Mask, _I1, _I, [], Acc) ->
    lists:reverse(Acc);

set_bits(Mask, I1, I, [H|T], Acc) ->
    ok = bit_vector:set(I, H),
    set_bits(Mask, I1, (I + I1) band Mask, T, [H|Acc]).



%% @private
make_hashes(SliceSize, Element) when SliceSize =< 16 ->
    erlang:phash2({Element}, 1 bsl 32);

make_hashes(SliceSize, Element) when SliceSize =< 32 ->
    {erlang:phash2({Element}, 1 bsl 32), erlang:phash2([Element], 1 bsl 32)}.


%% @private
hash_member(Hashes, #bloom_filter{slice_size = SliceSize, slices = Slices}) ->
    Mask = 1 bsl SliceSize - 1,
    {I1, I0} = make_indexes(Mask, Hashes),
    all_set(Mask, I1, I0, Slices).


%% @private
make_indexes(Mask, {H0, H1}) when Mask > 1 bsl 16 ->
    masked_pair(Mask, H0, H1);

make_indexes(Mask, {H0, _}) ->
    make_indexes(Mask, H0);

make_indexes(Mask, H0) ->
    masked_pair(Mask, H0 bsr 16, H0).


%% @private
masked_pair(Mask, X, Y) ->
    {X band Mask, Y band Mask}.


%% @private
all_set(_Mask, _I1, _I, []) ->
    true;

all_set(Mask, I1, I, [H|T]) ->
    case bit_vector:get(I, H) of
        1 -> all_set(Mask, I1, (I + I1) band Mask, T);
        0 -> false
    end.