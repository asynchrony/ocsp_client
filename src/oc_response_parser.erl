-module(oc_response_parser).
-export([parse/1]).
-include("OCSP.hrl").

parse(Body) ->
    OCSPResponse = decode_basic_response(Body),
    OCSPResponse#'SingleResponse'.certStatus.

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
