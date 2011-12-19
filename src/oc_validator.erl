-module(oc_validator).
-export([validate_cert/1]).
-include("OCSP.hrl").

-define(OCSP_URL, "http://localhost:8088").

validate_cert(PeerCert) ->
    {IssuerName, IssuerKey, SerialNumber} = oc_request_data:get_request_data(PeerCert),
    AssembledRequest = oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber),
    RequestBytes = 'OCSP':encode('OCSPRequest', AssembledRequest),
    case httpc:request(post, {?OCSP_URL, "application/ocsp-request", [], RequestBytes}, [], []) of
        {ok, Response} ->
            case oc_response_parser:parse(Response) of
                {revoked, {_Reason, _, _}} ->
                    {error, revoked};
                _ ->
                    ok
            end;
        _ ->
            ok
    end.

