-module(tls_certificate_repo_test).
-compile([export_all]).
-include("test_helper.hrl").

?MOCK_FIXTURE.

get_ca_chain_returns_pem_decoded_ca_chain_from_transport_config() ->
    CACertTestFileName = "../test/data/cacerts.pem",
    stub(application, get_env, 2, {ok, [{cacertfile, CACertTestFileName}]}),
    stub(public_key, pem_decode, 1, complete),

    ?assertMatch(complete, tls_certificate_repo:get_ca_chain()),

    ?assert(meck:called(application, get_env, [transport, tls_options])),
    {ok, PemBinary} = file:read_file(CACertTestFileName),
    ?assert(meck:called(public_key, pem_decode, [PemBinary])).
