-module(oc_validator).
-export([validate_cert/1]).
-include("OCSP.hrl").

-define(OCSP_URL, "http://localhost:8088").

validate_cert(PeerCert) ->
    {IssuerName, IssuerKey, SerialNumber} = oc_request_data:get_request_data(PeerCert),
    AssembledRequest = oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber),
    {ok, RequestBytes} = 'OCSP':encode('OCSPRequest', AssembledRequest),
    case httpc:request(post, {?OCSP_URL, "application/ocsp-request", [], RequestBytes}, [], []) of
        {ok, {{_Version, 200, _Description}, _Headers, Response}} ->
            case oc_response_parser:parse(Response) of
                {revoked, {_Reason, _, _}} ->
                    {error, revoked};
                _ ->
                    ok
            end;
        Error ->
            ok
    end.

