-module(oc_nonce).

-export([generate/0]).

generate() ->
    crypto:sha(crypto:rand_bytes(20)).
