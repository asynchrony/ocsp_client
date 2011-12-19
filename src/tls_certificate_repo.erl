-module(tls_certificate_repo).

-export([get_ca_chain/0]).

-define(CACERTS_PATH, "../../certs/testing/ca/cacerts.pem").

get_ca_chain() ->
    {ok, PemBinary} = file:read_file(?CACERTS_PATH),
    public_key:pem_decode(PemBinary).
