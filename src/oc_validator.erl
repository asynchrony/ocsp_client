-module(oc_validator).
-export([validate_cert/2]).
-include("OCSP.hrl").

validate_cert(PeerCert, ProviderURL) ->
    {IssuerName, IssuerKey, SerialNumber} = oc_request_data:get_request_data(PeerCert),
    AssembledRequest = oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber),
    {ok, RequestBytes} = 'OCSP':encode('OCSPRequest', AssembledRequest),
    case httpc:request(post, {ProviderURL, [], "application/ocsp-request", RequestBytes}, [], []) of
        {ok, {{_Version, HttpCode, Description}, _Headers, Response}} ->
            case HttpCode of
                200 -> oc_response_parser:parse(Response);
                _   -> {error, {HttpCode, Description, Response}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

