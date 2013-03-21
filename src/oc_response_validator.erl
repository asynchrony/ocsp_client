-module(oc_response_validator).
-export([validate/4]).
-include("OCSP.hrl").
-include_lib("public_key/include/public_key.hrl").

-compile([{parse_transform, do}]).
-import(error_m, [return/1, fail/1]).

validate(Body, VACerts, CertID, Nonce) ->
    do([error_m ||
            OCSPResponse  <- 'OCSP':decode('OCSPResponse', Body),
            ResponseBytes <- response_bytes(OCSPResponse),
            EncodedBasicResponse <- response(ResponseBytes),

            #'BasicOCSPResponse'{
                tbsResponseData = {PartType, Binary},
                signatureAlgorithm = Algorithm,
                signature = {_, Signature},
                certs = Certs
            } <- 'OCSP':decode_TBSResponseData_exclusive(EncodedBasicResponse),

            #'ResponseData'{
                responderID = ResponderID,
                responses = [ #'SingleResponse'{
                        certID     = ResponseCertID,
                        certStatus = {CertStatus, _}
                    } ],
                responseExtensions = Extensions
            } <- 'OCSP':decode_part(PartType, Binary),

            compare_items(CertID,
                          normalize_cert_id(ResponseCertID),
                          {ocsp, cert_id_mismatch}),
            ResponseNonce <- find_nonce(Extensions),
            compare_items(Nonce, ResponseNonce, {ocsp, nonce_mismatch}),

            SignerCert <- find_signer_cert(ResponderID, VACerts ++ Certs),

            %% TODO: pkix_path_validation of SignerCert
            %% TODO: ensure SignerCert is the peer's issuer -OR-
            %%       (SignerCert's issuer is peer's issuer -AND-
            %%        SignerCert has extendedKeyUsage of id-kp-ocspSigning

            verify_signature(Binary, Signature, Algorithm, SignerCert),

            validate_certStatus(CertStatus)
        ]).

response_bytes(#'OCSPResponse'{ responseStatus = successful,
        responseBytes = ResponseBytes }) ->
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

find_signer_cert(_, Certs) when not is_list(Certs) ->
    fail({ocsp, signer_cert_not_found});
find_signer_cert(_, []) ->
    fail({ocsp, signer_cert_not_found});
find_signer_cert(ResponderID, [ Cert | Rest ]) ->
    case is_responder_cert(ResponderID, Cert) of
        true  -> return(Cert);
        false -> find_signer_cert(ResponderID, Rest)
    end.

is_responder_cert({byName, Name}, Cert) ->
    Name == oc_certificate:subject_name(Cert);
is_responder_cert({byKey, KeyHash}, Cert) ->
    list_to_binary(KeyHash) == oc_certificate:hash_subject_public_key(sha, Cert).

-spec verify_signature( binary(), binary(), #'AlgorithmIdentifier'{},
                        #'Certificate'{} ) -> ok | {error, {ocsp, bad_signature}}.
verify_signature(Msg, Signature, AlgID, Signer) ->
    #'AlgorithmIdentifier'{ algorithm = Algorithm } = AlgID,
    Digest = pubkey_cert:digest_type(Algorithm),
    Key = oc_certificate:subject_public_key(Signer),
    case public_key:verify(Msg, Digest, Signature, Key) of
        true -> return(ok);
        false -> fail({ocsp, bad_signature})
    end.
