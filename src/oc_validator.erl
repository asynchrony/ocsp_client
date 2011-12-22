-module(oc_validator).
-export([validate_cert/1]).
-include("OCSP.hrl").

validate_cert(PeerCert) ->
    {IssuerName, IssuerKey, SerialNumber} = oc_request_data:get_request_data(PeerCert),
    AssembledRequest = oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber),
    {ok, RequestBytes} = 'OCSP':encode('OCSPRequest', AssembledRequest),
    {ok, ProviderURL} = application:get_env(ocsp_client, ocsp_provider_url),
    case httpc:request(post, {ProviderURL, "application/ocsp-request", [], RequestBytes}, [], []) of
        {ok, {{_Version, 200, _Description}, _Headers, Response}} ->
            case oc_response_parser:parse(Response) of
                {revoked, {_Reason, _, _}} ->
                    {error, revoked};
                _ ->
                    ok
            end;
        _Error ->
            ok
    end.

