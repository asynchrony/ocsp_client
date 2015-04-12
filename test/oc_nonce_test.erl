-module(oc_nonce_test).

-include_lib("eunit/include/eunit.hrl").

-compile([export_all]).

generate_should_return_unique_bitstrings_test() ->
    Nonce1 = oc_nonce:generate(),
    Nonce2 = oc_nonce:generate(),
    Nonce3 = oc_nonce:generate(),

    ?assertEqual(20, size(Nonce1)),
    ?assertEqual(20, size(Nonce2)),
    ?assertEqual(20, size(Nonce3)),
    ?assert(is_bitstring(Nonce1)),
    ?assert(Nonce1 =/= Nonce2),
    ?assert(Nonce2 =/= Nonce3),
    ?assert(Nonce1 =/= Nonce3).



