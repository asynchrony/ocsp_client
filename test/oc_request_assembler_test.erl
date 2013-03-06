-module(oc_request_assembler_test).
-compile([export_all]).
-include_lib("test_support/include/test_helper.hrl").
-include_lib("public_key/include/public_key.hrl").

?MOCK_FIXTURE.

-define(PEER_CERT_SERIAL, 4).
-define(ISSUER_NAME_HASH, <<127,48,50,119,249,107,26,46,118,236,
                            178,94,252,188,105,79,82,16,7,122>>).
-define(ISSUER_KEY_HASH,  <<86,1,201,90,16,122,198,164,214,153,55,
                            100,46,122,107,19,161,139,175,247>>).
-define(NONCE,            <<4,16,255,87,102,12,79,88,42,40,174,36,
                            68,64,180,151,170,21>>).
-define(SIGNATURE,        <<94,55,242,36,115,173,86,68,123,169,135,78,
                            62,128,75,17,175,214,38,143,74,88,74,216,74,
                            237,97,214,231,252,116,172,71,49,182,53,25,129,
                            213,251,198,174,245,168,92,248,133,124,7,138,
                            80,251,18,131,108,181,58,173,244,86,90,15,194,16>>).

assemble_request_returns_proper_request_with_nonce_in_bytes() ->
    ServerCert = test_support:decode_pem_file("servercert.pem"),
    RequestorName = oc_certificate:subject_name(ServerCert),

    stub(oc_certificate, find_issuer, 2, issuer_cert),
    stub(oc_certificate, subject_name, 1, RequestorName),
    stub(oc_certificate, serial_number, 1, ?PEER_CERT_SERIAL),
    stub(oc_certificate, hash_subject_name, 2, ?ISSUER_NAME_HASH),
    stub(oc_certificate, hash_subject_public_key, 2, ?ISSUER_KEY_HASH),
    stub(public_key, sign, 3, ?SIGNATURE),

    Result = oc_request_assembler:assemble_request(peer_cert, ca_chain,
                                                   ServerCert, server_key,
                                                   ?NONCE),

    ExpectedBytes = test_support:read_data("request.der"),

    ?assertEqual(ExpectedBytes, Result),
    ?assert(meck:called(oc_certificate, find_issuer, [peer_cert, ca_chain])),
    ?assert(meck:called(oc_certificate, subject_name, [ServerCert])),
    ?assert(meck:called(oc_certificate, serial_number, [peer_cert])),
    ?assert(meck:called(oc_certificate, hash_subject_name, [sha, issuer_cert])),
    ?assert(meck:called(oc_certificate, hash_subject_public_key, [sha, issuer_cert])).

