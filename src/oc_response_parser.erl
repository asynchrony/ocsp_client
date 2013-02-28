-module(oc_response_parser).
-export([parse/1]).
-include("OCSP.hrl").

parse(Body) ->
    OCSPResponse = decode_basic_response(Body),
    check_status(OCSPResponse#'SingleResponse'.certStatus).

decode_basic_response(Body) ->
    {ok, #'BasicOCSPResponse'{tbsResponseData = #'ResponseData' { responses = [Response] }}} =
            'OCSP':decode('BasicOCSPResponse', decode_response_body(Body)),
    Response.

decode_response_body(Body) ->
    {ok, #'OCSPResponse'{
        responseStatus = successful,
        responseBytes =
            #'ResponseBytes'{
                responseType = ?'id-pkix-ocsp-basic',
                response = BasicResponseBytes }}} = 'OCSP':decode('OCSPResponse', Body),
    BasicResponseBytes.

check_status({good, _}) -> ok;
check_status({revoked, _}) -> {error, certificate_revoked};
check_status({unknown, _}) -> {error, certificate_unknown_by_ocsp}.
