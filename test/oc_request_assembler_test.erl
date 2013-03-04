-module(oc_request_assembler_test).
-compile([export_all]).
-include_lib("test_support/include/test_helper.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

assemble_request_returns_proper_request_with_nonce_in_bytes_test() ->
    Result = oc_request_assembler:assemble_request(peer_cert(), ca_chain(),
                                                  server_cert(), private_key(),
                                                  nonce()),

    {ok, ExpectedBytes} = file:read_file("../test/data/request.der"),

    ?assertEqual(ExpectedBytes, Result).

server_cert() ->
    {ok, Pem} = file:read_file("../test/data/servercert.pem"),
    [Entry] = public_key:pem_decode(Pem),
    public_key:pem_entry_decode(Entry).

private_key() ->
    {ok, Pem} = file:read_file("../test/data/serverkey.pem"),
    [Entry] = public_key:pem_decode(Pem),
    public_key:pem_entry_decode(Entry).

peer_cert() ->
    {ok, Pem} = file:read_file("../test/data/client_0001.pem"),
    [{'Certificate', Cert, not_encrypted}] = public_key:pem_decode(Pem),
    Cert.

ca_chain() ->
    {ok, Pem} = file:read_file("../test/data/cacerts.pem"),
    Entries = public_key:pem_decode(Pem),
    [ Cert || {'Certificate', Cert, not_encrypted} <- Entries ].

nonce() ->
    <<4,16,255,87,102,12,79,88,42,40,174,36,68,64,180,151,170,21>>.
