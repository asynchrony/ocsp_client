-module(oc_validator).
-export([validate_cert/3]).
-include("OCSP.hrl").

validate_cert(PeerCert, CAChain, ProviderURL) ->
    {IssuerName, IssuerKey, SerialNumber} = oc_request_data:get_request_data(PeerCert, CAChain),
    Nonce = oc_request_data:generate_crypto_nonce(),
    AssembledRequest = oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber, Nonce),
    {ok, RequestBytes} = 'OCSP':encode('OCSPRequest', AssembledRequest),
    case httpc:request(post, {ProviderURL, [], "application/ocsp-request", RequestBytes}, [], []) of
        {ok, {{_Version, HttpCode, Description}, _Headers, Response}} ->
            case HttpCode of
                200 -> oc_response_parser:parse(Response, Nonce);
                _   -> {error, {HttpCode, Description, Response}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

