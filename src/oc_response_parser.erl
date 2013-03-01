-module(oc_response_parser).
-export([parse/1]).
-include("OCSP.hrl").

parse(Body) ->
    {ok, OCSPResponse} = 'OCSP':decode('OCSPResponse', Body),
    case check_response_status(OCSPResponse) of
        {ok, Response} ->
            {ok, BasicOCSPResponse} = 'OCSP':decode_TBSResponseData_exclusive(Response),
            case validate_BasicOCSPResponse(BasicOCSPResponse) of
                {ok, #'SingleResponse'{certStatus = CertStatus}} ->
                    check_cert_status(CertStatus);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

check_response_status(#'OCSPResponse'{responseStatus = successful,
        responseBytes = ResponseBytes }) ->
    check_response_bytes(ResponseBytes);
check_response_status(#'OCSPResponse'{responseStatus = Error}) ->
    {error, {ocsp, {responseStatus, Error}}}.

check_response_bytes(#'ResponseBytes'{responseType = ?'id-pkix-ocsp-basic',
        response = Response }) ->
    {ok, list_to_binary(Response)};
check_response_bytes(_) ->
    {error, {ocsp, unhandled_response_type}}.

validate_BasicOCSPResponse(#'BasicOCSPResponse'{tbsResponseData = {Type, Binary}}) ->
    {ok, #'ResponseData'{ responses = [Response] }} = 'OCSP':decode_part(Type, Binary),
    {ok, Response}.

check_cert_status({good, _}) -> ok;
check_cert_status({revoked, _}) -> {error, certificate_revoked};
check_cert_status({unknown, _}) -> {error, certificate_unknown_by_ocsp}.
