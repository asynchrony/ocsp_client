-module(oc_request_assembler).
-export([assemble_request/4, assemble_cert_id/2]).

-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

-define(DER_NULL, <<5,0>>). %% public_key defines this, but not in a HRL.

assemble_request(CertID, RequestorCert, RequestorPrivateKey, Nonce) ->
    TBSRequest = #'TBSRequest'{
        requestorName = {directoryName, oc_certificate:subject_name(RequestorCert)},
        requestList = [ #'Request'{ reqCert = CertID } ],
        requestExtensions = [ nonce_extension(Nonce) ]
    },
    Signature = sign(TBSRequest, RequestorCert, RequestorPrivateKey),
    encode(#'OCSPRequest'{
            tbsRequest = TBSRequest,
            optionalSignature = Signature
        }).

nonce_extension(Nonce) ->
    #'Extension'{
        extnID    = ?'id-pkix-ocsp-nonce',
        critical  = false,
        extnValue = Nonce
    }.

sign(TBSRequest, RequestorCert, PrivateKey) ->
    Msg = encode(TBSRequest),
    Signature = public_key:sign(Msg, sha, PrivateKey),
    #'Signature'{
        signatureAlgorithm = signature_algorithm(),
        signature = {0, Signature},
        certs = [ RequestorCert ]
    }.

hash_algorithm() ->
    #'AlgorithmIdentifier'{
        algorithm = ?'id-sha1',
        parameters = ?DER_NULL
    }.

signature_algorithm() ->
    #'AlgorithmIdentifier'{
        algorithm = ?'sha1WithRSAEncryption',
        parameters = ?DER_NULL
    }.

assemble_cert_id(PeerCert, CAChain) ->
    IssuerCert = oc_certificate:find_issuer(PeerCert, CAChain),
    #'CertID'{
        hashAlgorithm  = hash_algorithm(),
        issuerNameHash = oc_certificate:hash_subject_name(sha, IssuerCert),
        issuerKeyHash  = oc_certificate:hash_subject_public_key(sha, IssuerCert),
        serialNumber   = oc_certificate:serial_number(PeerCert)
    }.

encode(Record) ->
    {ok, IoData} = 'OCSP':encode(element(1, Record), Record),
    iolist_to_binary(IoData).
