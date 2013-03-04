-module(oc_request_data_test).

-include_lib("test_support/include/test_helper.hrl").

-compile([export_all]).

?MOCK_FIXTURE.

get_request_data_should_return_issuer_issuer_key_peer_serial() ->
    {ok, PemBinary} = file:read_file("../test/data/client_0001.pem"),
    [{_, PeerCert, _}] = public_key:pem_decode(PemBinary),

    {ok, CAChainPem} = file:read_file("../test/data/cacerts.pem"),
    CAChain = [ CA || {_, CA, _} <- public_key:pem_decode(CAChainPem) ],

    {IssuerName, IssuerKey, Serial} = oc_request_data:get_request_data(PeerCert, CAChain),

    ExpectedIssuerName = <<48,129,135,49,11,48,9,6,3,85,4,6,19,2,85,83,49,24,48,22,6,3,85,4,10,19,15,85,
                           46,83,46,32,71,111,118,101,114,110,109,101,110,116,49,12,48,10,6,3,85,4,11,
                           19,3,78,83,83,49,12,48,10,6,3,85,4,11,19,3,68,111,68,49,34,48,32,6,3,85,4,11,
                           19,25,67,101,114,116,105,102,105,99,97,116,105,111,110,32,65,117,116,104,111,
                           114,105,116,105,101,115,49,30,48,28,6,3,85,4,3,19,21,77,97,107,111,32,83,117,
                           98,111,114,100,105,110,97,116,101,32,67,65,32,49>>,

    ExpectedIssuerKey = <<48,72,2,65,0,203,235,249,143,92,152,77,175,112,180,95,68,18,130,135,39,28,31,
                          212,187,179,130,135,183,254,174,68,29,110,247,195,239,152,205,24,145,74,14,
                          50,171,95,61,44,13,228,247,255,221,4,137,8,207,172,136,237,160,254,255,185,
                          165,126,223,100,9,2,3,1,0,1>>,

    ExpectedSerial = 4,

    ?assertEqual({ExpectedIssuerName, ExpectedIssuerKey, ExpectedSerial}, {IssuerName, IssuerKey, Serial}).

% bin_to_hexstr_(Bin) ->
%   lists:flatten([io_lib:format("~2.16.0B", [X]) ||
%     X <- binary_to_list(Bin)]).

get_crypto_nonce_should_return_unique_bitstring() ->
    Nonce1 = oc_request_data:generate_crypto_nonce(),
    Nonce2 = oc_request_data:generate_crypto_nonce(),
    Nonce3 = oc_request_data:generate_crypto_nonce(),

    ?assertEqual(20, size(Nonce1)),
    ?assertEqual(20, size(Nonce2)),
    ?assertEqual(20, size(Nonce3)),
    ?assert(is_bitstring(Nonce1)),
    ?assert(Nonce1 =/= Nonce2),
    ?assert(Nonce2 =/= Nonce3),
    ?assert(Nonce1 =/= Nonce3).



