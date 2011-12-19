-module(oc_validator_test).
-compile([export_all]).
-include("test_helper.hrl").
-include("OCSP.hrl").

?MOCK_FIXTURE.

validate_cert_returns_error_when_revoke_message_returned_from_provider() ->
    stub(oc_request_data, get_request_data, 1, {issuername, issuerkey, serialnumber}),
    stub(oc_request_assembler, assemble_request, 3, assembled_request),
    stub('OCSP', encode, 2, request_bytes),
    stub(httpc, request, 4, {ok, ocsp_response}),
    stub(oc_response_parser, parse, 1, {revoked, {'Reason', timestamp, asn1_NOVALUE}}),

    ?assertMatch({error, revoked}, oc_validator:validate_cert(peercert)),

    ?assert(meck:called(oc_request_data, get_request_data, [peercert])),
    ?assert(meck:called(oc_request_assembler, assemble_request, [issuername, issuerkey, serialnumber])),
    ?assert(meck:called('OCSP', encode, ['OCSPRequest', assembled_request])),
    ?assert(meck:called(httpc, request, [post, {"http://localhost:8088", "application/ocsp-request", [], request_bytes}, [], []])),
    ?assert(meck:called(oc_response_parser, parse, [ocsp_response])).

validate_cert_returns_ok_when_good_returned_from_provider() ->
    stub(oc_request_data, get_request_data, 1, {issuername, issuerkey, serialnumber}),
    stub(oc_request_assembler, assemble_request, 3, assembled_request),
    stub('OCSP', encode, 2, request_bytes),
    stub(httpc, request, 4, {ok, ocsp_response}),
    stub(oc_response_parser, parse, 1, {good, 'NULL'}),

    ?assertMatch(ok, oc_validator:validate_cert(peercert)),

    ?assert(meck:called(oc_request_data, get_request_data, [peercert])),
    ?assert(meck:called(oc_request_assembler, assemble_request, [issuername, issuerkey, serialnumber])),
    ?assert(meck:called('OCSP', encode, ['OCSPRequest', assembled_request])),
    ?assert(meck:called(httpc, request, [post, {"http://localhost:8088", "application/ocsp-request", [], request_bytes}, [], []])),
    ?assert(meck:called(oc_response_parser, parse, [ocsp_response])).

validate_cert_returns_ok_when_provider_request_returns_error() ->
    stub(oc_request_data, get_request_data, 1, {issuername, issuerkey, serialnumber}),
    stub(oc_request_assembler, assemble_request, 3, assembled_request),
    stub('OCSP', encode, 2, request_bytes),
    stub(httpc, request, 4, {error, "reason"}),

    ?assertMatch(ok, oc_validator:validate_cert(peercert)),

    ?assert(meck:called(oc_request_data, get_request_data, [peercert])),
    ?assert(meck:called(oc_request_assembler, assemble_request, [issuername, issuerkey, serialnumber])),
    ?assert(meck:called('OCSP', encode, ['OCSPRequest', assembled_request])),
    ?assert(meck:called(httpc, request, [post, {"http://localhost:8088", "application/ocsp-request", [], request_bytes}, [], []])).

