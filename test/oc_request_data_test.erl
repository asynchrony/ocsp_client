-module(oc_request_data_test).

-include("test_helper.hrl").

-compile([export_all]).

?MOCK_FIXTURE.

get_request_data_should_return_issuer_issuer_key_peer_serial() ->
    {ok, PemBinary} = file:read_file("../test/data/client_0001.pem"),
    [{_, PeerCert, _}] = public_key:pem_decode(PemBinary),
    % PeerCert = public_key:pkix_decode_cert(PemEntry, plain),
    
    {ok, CAChainPem} = file:read_file("../test/data/cacerts.pem"),
    CAChainEntries = public_key:pem_decode(CAChainPem),

    fake(tls_certificate_repo, get_ca_chain, 0, CAChainEntries),

    {IssuerName, IssuerKey, Serial} = oc_request_data:get_request_data(PeerCert),

    ExpectedIssuerName = <<48,129,135,49,11,48,9,6,3,85,4,6,19,2,85,83,49,24,48,22,6,3,85,4,
                         10,19,15,85,46,83,46,32,71,111,118,101,114,110,109,101,110,116,
                         49,12,48,10,6,3,85,4,11,19,3,78,83,83,49,12,48,10,6,3,85,4,11,19,
                         3,68,111,68,49,34,48,32,6,3,85,4,11,19,25,67,101,114,116,105,102,
                         105,99,97,116,105,111,110,32,65,117,116,104,111,114,105,116,105,
                         101,115,49,30,48,28,6,3,85,4,3,19,21,77,97,107,111,32,83,117,98,
                         111,114,100,105,110,97,116,101,32,67,65,32,49>>,

    ExpectedIssuerKey = <<48,72,2,65,0,190,244,57,243,52,61,249,235,98,60,225,204,100,42,74,
                        3,149,182,57,147,211,230,58,24,81,250,40,233,41,83,24,252,67,108,
                        162,124,29,202,164,43,8,116,71,241,40,70,197,109,178,187,50,33,
                        109,11,92,107,97,92,6,221,33,120,87,185,2,3,1,0,1>>,
    ExpectedSerial = 1,

    ?assertEqual({ExpectedIssuerName, ExpectedIssuerKey, ExpectedSerial}, {IssuerName, IssuerKey, Serial}).

% bin_to_hexstr_(Bin) ->
%   lists:flatten([io_lib:format("~2.16.0B", [X]) ||
%     X <- binary_to_list(Bin)]).

