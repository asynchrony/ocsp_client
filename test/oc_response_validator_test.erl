-module(oc_response_validator_test).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

-define(GOOD_RESPONSE_NONCE, <<4,16,60,16,246,40,131,14,22,190,185,99,48,188,105,240,243,11>>).
-define(REVOKED_RESPONSE_NONCE, <<4,16,94,148,117,210,217,155,203,180,194,46,74,14,249,254,206,144>>).
-define(UNKNOWN_RESPONSE_NONCE, <<4,16,131,133,19,224,146,246,192,125,115,215,159,63,28,170,94,155>>).
-define(CERT_ID(Serial), #'CertID'{
        hashAlgorithm = #'AlgorithmIdentifier'{algorithm=?'id-sha1',parameters = <<5,0>>},
        issuerNameHash = <<127,48,50,119,249,107,26,46,118,236,178,94,252,188,105,79,82,16,7,122>>,
        issuerKeyHash  = <<86,1,201,90,16,122,198,164,214,153,55,100,46,122,107,19,161,139,175,247>>,
        serialNumber   = Serial}).

validate_should_return_ok_when_cert_status_is_good_test() ->
    Response = test_support:read_data("good_response.der"),
    ?assertMatch(ok, oc_response_validator:validate(Response, ?CERT_ID(12), ?GOOD_RESPONSE_NONCE)).

validate_should_return_error_when_response_status_not_successful_test() ->
    {ok, Response} = 'OCSP':encode('OCSPResponse', #'OCSPResponse'{responseStatus = internalError}),

    ?assertMatch({error, {ocsp, {responseStatus, internalError}}}, oc_response_validator:validate(Response, cert_id, nonce)).

validate_should_return_error_when_unhandled_response_type_test() ->
    Record = #'OCSPResponse'{
        responseStatus = successful,
        responseBytes = #'ResponseBytes'{ responseType = {0,0}, response = <<>> }
    },
    {ok, Response} = 'OCSP':encode('OCSPResponse', Record),

    ?assertMatch({error, {ocsp, unhandled_response_type}}, oc_response_validator:validate(Response, cert_id, nonce)).

validate_should_return_error_when_cert_status_is_revoked_test() ->
    Response = test_support:read_data("revoked_response.der"),
    ?assertMatch({error, certificate_revoked}, oc_response_validator:validate(Response, ?CERT_ID(4), ?REVOKED_RESPONSE_NONCE)).

validate_should_return_error_when_cert_status_is_unknown_test() ->
    Response = test_support:read_data("unknown_response.der"),
    ?assertMatch({error, certificate_unknown_by_ocsp}, oc_response_validator:validate(Response, ?CERT_ID(24), ?UNKNOWN_RESPONSE_NONCE)).

validate_should_return_error_when_nonce_does_not_match_test() ->
    Response = test_support:read_data("good_response.der"),
    ?assertMatch({error, {ocsp, nonce_mismatch}}, oc_response_validator:validate(Response, ?CERT_ID(12), ?UNKNOWN_RESPONSE_NONCE)).

validate_should_return_error_when_cert_id_does_not_match_test() ->
    Response = test_support:read_data("good_response.der"),
    ?assertMatch({error, {ocsp, cert_id_mismatch}}, oc_response_validator:validate(Response, ?CERT_ID(0), ?GOOD_RESPONSE_NONCE)).
