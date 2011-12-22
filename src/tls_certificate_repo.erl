-module(tls_certificate_repo).

-export([get_ca_chain/0]).

get_ca_chain() ->
    {ok, TLSOptions} = application:get_env(transport, tls_options),
    CACertFileName = proplists:get_value(cacertfile, TLSOptions),
    {ok, PemBinary} = file:read_file(CACertFileName),
    public_key:pem_decode(PemBinary).
