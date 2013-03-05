-module(oc_response_parser).
-export([parse/2]).
-include("OCSP.hrl").
-include_lib("public_key/include/public_key.hrl").

parse(Body, Nonce) ->
    {ok, OCSPResponse} = 'OCSP':decode('OCSPResponse', Body),
    validate_responseStatus(OCSPResponse, Nonce).

validate_responseStatus(#'OCSPResponse'{responseStatus = successful,
        responseBytes = ResponseBytes }, Nonce) ->
    validate_ResponseBytes(ResponseBytes, Nonce);
validate_responseStatus(#'OCSPResponse'{responseStatus = Error}, _Nonce) ->
    {error, {ocsp, {responseStatus, Error}}}.

validate_ResponseBytes(#'ResponseBytes'{responseType = ?'id-pkix-ocsp-basic',
        response = Response }, Nonce) ->
    {ok, BasicOCSPResponse} = 'OCSP':decode_TBSResponseData_exclusive(list_to_binary(Response)),
    validate_BasicOCSPResponse(BasicOCSPResponse, Nonce);
validate_ResponseBytes(_, _) ->
    {error, {ocsp, unhandled_response_type}}.

validate_BasicOCSPResponse(#'BasicOCSPResponse'{tbsResponseData = {Type, Binary}}, Nonce) ->
    {ok, ResponseData} = 'OCSP':decode_part(Type, Binary),
    validate_ResponseData(ResponseData, Nonce).

validate_ResponseData(#'ResponseData'{ responses = [SingleResponse],
        responseExtensions = Extensions }, Nonce) ->
    validate_extensions(Extensions, Nonce, SingleResponse).

validate_extensions([ #'Extension'{extnID = ?'id-pkix-ocsp-nonce', extnValue = Actual} | _ ], Expected, SingleResponse) ->
    validate_nonce(Expected, list_to_binary(Actual), SingleResponse);
validate_extensions([ _Other | Rest ], Nonce, SingleResponse) ->
    validate_extensions(Rest, Nonce, SingleResponse);
validate_extensions([], _, _) ->
    {error, {ocsp, response_nonce_missing}}.

validate_nonce(Nonce, Nonce, SingleResponse) ->
    validate_certStatus(SingleResponse);
validate_nonce(_Expected, _Actual, _) ->
    {error, {ocsp, nonce_mismatch}}.


validate_certStatus(#'SingleResponse'{certStatus = {good, _}}) ->
    ok;
validate_certStatus(#'SingleResponse'{certStatus = {revoked, _}}) ->
    {error, certificate_revoked};
validate_certStatus(#'SingleResponse'{certStatus = {unknown, _}}) ->
    {error, certificate_unknown_by_ocsp}.
