-module(oc_response_parser_test).
-compile([export_all]).
-include_lib("test_support/include/test_helper.hrl").
-include("OCSP.hrl").

?MOCK_FIXTURE.

-define(BodyResponse, #'OCSPResponse'{ 
        responseStatus = successful, 
        responseBytes = #'ResponseBytes'{
            responseType = ?'id-pkix-ocsp-basic',
            response = <<"BASICRESPONSE">>
        }}).
-define(BasicResponse(Status), #'BasicOCSPResponse'{
        tbsResponseData = #'ResponseData' { 
            responses = [ #'SingleResponse'{certStatus = Status} ]
        }
    }).

parse_should_return_ok_when_cert_status_is_good() ->
    Status = {good, 'NULL'},
    stub_sequence('OCSP', decode, 2, [
            {ok, ?BodyResponse},
            {ok, ?BasicResponse(Status)}
        ]),

    ?assertMatch(ok, oc_response_parser:parse(response_body)),
    ?assert(meck:called('OCSP', decode, ['OCSPResponse', response_body])),
    ?assert(meck:called('OCSP', decode, ['BasicOCSPResponse', <<"BASICRESPONSE">>])).

parse_should_return_error_when_cert_status_is_revoked() ->
    Status = {revoked, #'RevokedInfo'{}},
    stub_sequence('OCSP', decode, 2, [
            {ok, ?BodyResponse},
            {ok, ?BasicResponse(Status)}
        ]),

    ?assertMatch({error, certificate_revoked}, oc_response_parser:parse(response_body)),
    ?assert(meck:called('OCSP', decode, ['OCSPResponse', response_body])),
    ?assert(meck:called('OCSP', decode, ['BasicOCSPResponse', <<"BASICRESPONSE">>])).

parse_should_return_error_when_cert_status_is_unknown() ->
    Status = {unknown, 'NULL'},
    stub_sequence('OCSP', decode, 2, [
            {ok, ?BodyResponse},
            {ok, ?BasicResponse(Status)}
        ]),

    ?assertMatch({error, certificate_unknown_by_ocsp}, oc_response_parser:parse(response_body)),
    ?assert(meck:called('OCSP', decode, ['OCSPResponse', response_body])),
    ?assert(meck:called('OCSP', decode, ['BasicOCSPResponse', <<"BASICRESPONSE">>])).

