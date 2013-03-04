-module(oc_validator_test).
-compile([export_all]).
-include_lib("test_support/include/test_helper.hrl").
-include("OCSP.hrl").

?MOCK_FIXTURE.

validate_cert_returns_error_when_provider_request_returns_error() ->
    stub(oc_request_data, generate_crypto_nonce, 0, crypto_nonce),
    stub(oc_request_assembler, assemble_request, 5, assembled_request),
    stub(httpc, request, 4, {error, "reason"}),

    ?assertMatch({error, "reason"}, oc_validator:validate_cert(peercert, ca_chain, requestor_cert, requestor_key, "provider url")),

    ?assert(meck:called(httpc, request, [post, {"provider url", [], "application/ocsp-request", assembled_request}, [], []])),
    ?assert(meck:called(oc_request_assembler, assemble_request, [peercert, ca_chain, requestor_cert, requestor_key, crypto_nonce])).

validate_cert_returns_error_when_provider_request_returns_non_200_http_code() ->
    stub(oc_request_data, generate_crypto_nonce, 0, crypto_nonce),
    stub(oc_request_assembler, assemble_request, 5, assembled_request),
    stub(httpc, request, 4, {ok, {{version, 500, description}, headers, error_response}}),

    ?assertMatch({error, {500, description, error_response}}, oc_validator:validate_cert(peercert, ca_chain, requestor_cert, requestor_key, "provider url")),

    ?assert(meck:called(httpc, request, [post, {"provider url", [], "application/ocsp-request", assembled_request}, [], []])),
    ?assert(meck:called(oc_request_assembler, assemble_request, [peercert, ca_chain, requestor_cert, requestor_key, crypto_nonce])).

validate_cert_returns_parser_result_when_request_returns_200_http_code() ->
    stub(oc_request_data, generate_crypto_nonce, 0, crypto_nonce),
    stub(oc_request_assembler, assemble_request, 5, assembled_request),
    stub(httpc, request, 4, {ok, {{version, 200, description}, headers, ocsp_response}}),
    stub(oc_response_parser, parse, 2, parser_result),

    ?assertMatch(parser_result, oc_validator:validate_cert(peercert, ca_chain, requestor_cert, requestor_key, "provider url")),

    ?assert(meck:called(httpc, request, [post, {"provider url", [], "application/ocsp-request", assembled_request}, [], []])),
    ?assert(meck:called(oc_request_assembler, assemble_request, [peercert, ca_chain, requestor_cert, requestor_key, crypto_nonce])),
    ?assert(meck:called(oc_response_parser, parse, [ocsp_response, crypto_nonce])).

