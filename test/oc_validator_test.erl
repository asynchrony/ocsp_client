-module(oc_validator_test).
-compile([export_all]).
-include_lib("eunit/include/eunit.hrl").
-include_lib("hoax/include/hoax.hrl").
-include("OCSP.hrl").

?HOAX_FIXTURE(setup, teardown).

setup() ->
    mock(oc_request_assembler, [
            ?expect(assemble_cert_id,
                ?withArgs([peercert, ca_chain]),
                ?andReturn(cert_id)),
            ?expect(assemble_request,
                ?withArgs([cert_id, requestor_cert, requestor_key, crypto_nonce]),
                ?andReturn(assembled_request))
        ]),
    mock(oc_nonce, [
            ?expect(generate, ?withArgs([]), ?andReturn(crypto_nonce))
        ]),
    ok.

teardown(_) ->
    ok.

-define(expectHttpcToReturn(Result),
    mock(httpc, [
            ?expect(request,
                ?withArgs([post, {"provider url", [], "application/ocsp-request", assembled_request}, [], []]),
                ?andReturn(Result))
        ])
).

validate_cert_returns_error_when_provider_request_returns_error() ->
    ?expectHttpcToReturn({error, "reason"}),

    Result = oc_validator:validate_cert(peercert, ca_chain, requestor_cert, requestor_key, "provider url"),

    ?assertMatch({error, {ocsp, "reason"}}, Result),
    ?verifyAll.

validate_cert_returns_error_when_provider_request_returns_non_200_http_code() ->
    ?expectHttpcToReturn({ok, {{version, 500, description}, headers, error_response}}),

    Result = oc_validator:validate_cert(peercert, ca_chain, requestor_cert, requestor_key, "provider url"),

    ?assertMatch({error, {ocsp, {500, description, error_response}}}, Result),
    ?verifyAll.

validate_cert_returns_validator_result_when_request_returns_200_http_code() ->
    ?expectHttpcToReturn({ok, {{version, 200, description}, headers, ocsp_response}}),
    mock(oc_response_validator, [
            ?expect(validate, ?withArgs([ocsp_response, cert_id, crypto_nonce]), ?andReturn(validator_result))
        ]),

    Result = oc_validator:validate_cert(peercert, ca_chain, requestor_cert, requestor_key, "provider url"),

    ?assertMatch(validator_result, Result),
    ?verifyAll.
