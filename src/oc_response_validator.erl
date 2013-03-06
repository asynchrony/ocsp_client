-module(oc_response_validator).
-export([validate/3]).
-include("OCSP.hrl").
-include_lib("public_key/include/public_key.hrl").

-compile([{parse_transform, do}]).
-import(error_m, [return/1, fail/1]).

validate(Body, CertID, Nonce) ->
    do([error_m ||
            OCSPResponse  <- 'OCSP':decode('OCSPResponse', Body),
            ResponseBytes <- response_bytes(OCSPResponse),
            BinaryResponse <- response(ResponseBytes),

            #'BasicOCSPResponse'{
                tbsResponseData = {Type, Binary}
            } <- 'OCSP':decode_TBSResponseData_exclusive(BinaryResponse),

            #'ResponseData'{
                responses = [ #'SingleResponse'{
                        certID     = ResponseCertID,
                        certStatus = {CertStatus, _}
                    } ],
                responseExtensions = Extensions
            } <- 'OCSP':decode_part(Type, Binary),

            compare_items(CertID,
                          normalize_cert_id(ResponseCertID),
                          {ocsp, cert_id_mismatch}),

            ResponseNonce <- find_nonce(Extensions),
            compare_items(Nonce, ResponseNonce, {ocsp, nonce_mismatch}),
            validate_certStatus(CertStatus)
        ]).

response_bytes(#'OCSPResponse'{ responseStatus = successful,
        responseBytes = ResponseBytes } ) ->
    return(ResponseBytes);
response_bytes(#'OCSPResponse'{responseStatus = Error}) ->
    fail({ocsp, {responseStatus, Error}}).

response(#'ResponseBytes'{ responseType = ?'id-pkix-ocsp-basic',
        response = Response }) ->
    return(list_to_binary(Response));
response(_) ->
    fail({ocsp, unhandled_response_type}).

find_nonce([]) ->
    fail({ocsp, response_nonce_missing});
find_nonce([ #'Extension'{extnID = ?'id-pkix-ocsp-nonce',
                          extnValue = Value} | _ ]) ->
    return(list_to_binary(Value));
find_nonce([ _Other | Rest ]) ->
    find_nonce(Rest).

compare_items(Same, Same, _) -> return(ok);
compare_items(_, _, Error)   -> fail(Error).

validate_certStatus(good)    -> return(ok);
validate_certStatus(revoked) -> fail({ocsp, certificate_revoked});
validate_certStatus(unknown) -> fail({ocsp, certificate_unknown}).

normalize_cert_id(CertID = #'CertID'{issuerNameHash = NameHash,
                                     issuerKeyHash = KeyHash}) ->
    CertID#'CertID'{
        issuerNameHash = list_to_binary(NameHash),
        issuerKeyHash  = list_to_binary(KeyHash)
    }.
