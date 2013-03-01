-module(oc_response_parser_test).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-include("OCSP.hrl").

parse_should_return_ok_when_cert_status_is_good_test() ->
    {ok, Response} = file:read_file("../test/data/good_response.der"),
    ?assertMatch(ok, oc_response_parser:parse(Response)).

parse_should_return_error_when_response_status_not_successful_test() ->
    {ok, Response} = 'OCSP':encode('OCSPResponse', #'OCSPResponse'{responseStatus = internalError}),

    ?assertMatch({error, {ocsp, {responseStatus, internalError}}}, oc_response_parser:parse(Response)).

parse_should_return_error_when_unhandled_response_type_test() ->
    Record = #'OCSPResponse'{
        responseStatus = successful,
        responseBytes = #'ResponseBytes'{
            responseType = {0,0},
            response = <<>>
        }
    },
    {ok, Response} = 'OCSP':encode('OCSPResponse', Record),

    ?assertMatch({error, {ocsp, unhandled_response_type}}, oc_response_parser:parse(Response)).

parse_should_return_error_when_cert_status_is_revoked_test() ->
    {ok, Response} = file:read_file("../test/data/revoked_response.der"),

    ?assertMatch({error, certificate_revoked}, oc_response_parser:parse(Response)).

parse_should_return_error_when_cert_status_is_unknown_test() ->
    {ok, Response} = file:read_file("../test/data/unknown_response.der"),

    ?assertMatch({error, certificate_unknown_by_ocsp}, oc_response_parser:parse(Response)).
