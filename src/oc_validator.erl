-module(oc_validator).
-export([validate_cert/5]).
-include("OCSP.hrl").

validate_cert(PeerCert, CAChain, RequestorCert, RequestorPrivateKey, ProviderURL) ->
    Nonce = oc_request_data:generate_crypto_nonce(),
    RequestBytes = oc_request_assembler:assemble_request(PeerCert, CAChain, RequestorCert, RequestorPrivateKey, Nonce),
    case httpc:request(post, {ProviderURL, [], "application/ocsp-request", RequestBytes}, [], []) of
        {ok, {{_Version, HttpCode, Description}, _Headers, Response}} ->
            case HttpCode of
                200 -> oc_response_parser:parse(Response, Nonce);
                _   -> {error, {HttpCode, Description, Response}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

