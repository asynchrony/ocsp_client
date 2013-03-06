-module(oc_response_validator).
-export([validate/2]).
-include("OCSP.hrl").
-include_lib("public_key/include/public_key.hrl").

-compile([{parse_transform, do}]).

validate(Body, Nonce) ->
    do([error_m ||
            OCSPResponse  <- 'OCSP':decode('OCSPResponse', Body),
            ResponseBytes <- response_bytes(OCSPResponse),
            BinaryResponse <- response(ResponseBytes),
            #'BasicOCSPResponse'{
                tbsResponseData = {Type, Binary}
            } <- 'OCSP':decode_TBSResponseData_exclusive(BinaryResponse),
            #'ResponseData'{
                responses = [ #'SingleResponse'{
                        certStatus = {CertStatus, _}
                    } ],
                responseExtensions = Extensions
            } <- 'OCSP':decode_part(Type, Binary),
            ResponseNonce = find_nonce(Extensions),
            compare_items(Nonce, ResponseNonce, {ocsp, nonce_mismatch}),
            validate_certStatus(CertStatus)
        ]).

response_bytes(#'OCSPResponse'{ responseStatus = successful,
        responseBytes = ResponseBytes } ) ->
    {ok, ResponseBytes};
response_bytes(#'OCSPResponse'{responseStatus = Error}) ->
    {error, {ocsp, {responseStatus, Error}}}.

response(#'ResponseBytes'{ responseType = ?'id-pkix-ocsp-basic',
        response = Response }) ->
    {ok, list_to_binary(Response)};
response(_) ->
    {error, {ocsp, unhandled_response_type}}.

find_nonce([]) ->
    {error, {ocsp, response_nonce_missing}};
find_nonce([ #'Extension'{extnID = ?'id-pkix-ocsp-nonce', extnValue = Value} | _ ]) ->
    list_to_binary(Value);
find_nonce([ _Other | Rest ]) ->
    find_nonce(Rest).

compare_items(Same, Same, _) -> ok;
compare_items(_, _, Error)   -> {error, Error}.

validate_certStatus(good)    -> ok;
validate_certStatus(revoked) -> {error, certificate_revoked};
validate_certStatus(unknown) -> {error, certificate_unknown_by_ocsp}.
