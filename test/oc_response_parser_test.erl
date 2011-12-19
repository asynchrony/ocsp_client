-module(oc_response_parser_test).
-compile([export_all]).
-include("test_helper.hrl").
-include("OCSP.hrl").

?MOCK_FIXTURE.

parse_accepts_response_body_and_returns_cert_status() ->
    BodyResponse = {ok, #'OCSPResponse'{ 
            responseStatus = successful, 
            responseBytes = #'ResponseBytes'{
                responseType = ?'id-pkix-ocsp-basic',
                response = <<"BASICRESPONSE">> }}},
    BasicResponse = {ok, #'BasicOCSPResponse'{
            tbsResponseData = #'ResponseData' { 
                responses = [ #'SingleResponse' {certStatus = "GOOD"}]}}},
    stub_sequence('OCSP', decode, 2, [BodyResponse, BasicResponse]),

    ?assertMatch("GOOD", oc_response_parser:parse(response_body)),
    ?assert(meck:called('OCSP', decode, ['OCSPResponse', response_body])),
    ?assert(meck:called('OCSP', decode, ['BasicOCSPResponse', <<"BASICRESPONSE">>])).
