-module(oc_request_assembler_test).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-include_lib("hoax/include/hoax.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

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

?HOAX_FIXTURE.

assemble_request_returns_proper_request_with_nonce_in_bytes() ->
    ServerCert = test_support:decode_pem_entry("servercert.pem"),
    RequestorName = oc_certificate:subject_name(ServerCert),

    hoax:mock(oc_certificate, ?expect(subject_name, ?withArgs([ServerCert]), ?andReturn(RequestorName))),
    hoax:mock(public_key, ?expect(sign, ?withArgs([?any, sha, server_key]), ?andReturn(?SIGNATURE))),

    CertID = #'CertID'{
        hashAlgorithm  = #'AlgorithmIdentifier'{ algorithm = ?'id-sha1', parameters = <<5,0>> },
        issuerNameHash = ?ISSUER_NAME_HASH,
        issuerKeyHash  = ?ISSUER_KEY_HASH,
        serialNumber   = ?PEER_CERT_SERIAL
    },
    Result = oc_request_assembler:assemble_request(CertID, ServerCert, server_key, ?NONCE),

    ExpectedBytes = test_support:read_data("request.der"),

    ?assertEqual(ExpectedBytes, Result),
    ?verifyAll.

assemble_cert_id_returns_proper_record() ->
    hoax:mock(oc_certificate, [
        ?expect(find_issuer, ?withArgs([peer_cert, ca_chain]), ?andReturn(issuer_cert)),
        ?expect(serial_number, ?withArgs([peer_cert]), ?andReturn(peer_cert_serial)),
        ?expect(hash_subject_name, ?withArgs([sha, issuer_cert]), ?andReturn(issuer_name_hash)),
        ?expect(hash_subject_public_key, ?withArgs([sha, issuer_cert]), ?andReturn(issuer_key_hash))
    ]),

    Result = oc_request_assembler:assemble_cert_id(peer_cert, ca_chain),

    Expected = #'CertID'{
        hashAlgorithm  = #'AlgorithmIdentifier'{ algorithm = ?'id-sha1', parameters = <<5,0>> },
        issuerNameHash = issuer_name_hash,
        issuerKeyHash  = issuer_key_hash,
        serialNumber   = peer_cert_serial
    },
    ?assertEqual(Expected, Result),
    ?verifyAll.
