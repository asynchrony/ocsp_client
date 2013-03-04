-module(oc_request_assembler).
-export([assemble_request/5]).

-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

-define(DER_NULL, <<5,0>>). %% public_key defines this, but not in a HRL.

assemble_request(PeerCert, CAChain, RequestorCert, RequestorPrivateKey, Nonce) ->
    {IssuerName, IssuerKey, SerialNumber} = oc_request_data:get_request_data(PeerCert, CAChain),
    TBSRequest = #'TBSRequest'{
        requestorName = {directoryName, RequestorCert#'Certificate'.tbsCertificate#'TBSCertificate'.subject},
        requestList = [ #'Request' {
                                        reqCert = populate_certificate_id(IssuerName, IssuerKey, SerialNumber)
                                    }],
                                requestExtensions = [nonce_extension(Nonce)] },
    Signature = do_sign(TBSRequest, RequestorPrivateKey),
    Req = #'OCSPRequest'{ tbsRequest = TBSRequest, optionalSignature = #'Signature'{
        signatureAlgorithm = algorithm(?'sha1WithRSAEncryption'),
        signature = {0, Signature},
        certs = [RequestorCert]
    } },
    {ok, IoData} = 'OCSP':encode('OCSPRequest', Req),
    iolist_to_binary(IoData).

populate_certificate_id(IssuerName, IssuerKey, SerialNumber) ->
    #'CertID'{ hashAlgorithm = algorithm(?'id-sha1'),
               issuerNameHash = crypto:sha(IssuerName),
               issuerKeyHash = crypto:sha(IssuerKey),
               serialNumber = SerialNumber }.

nonce_extension(Nonce) ->
    #'Extension'{ extnID = ?'id-pkix-ocsp-nonce',
                  critical = false,
                  extnValue = Nonce }.

do_sign(TBSRequest, PrivateKey) ->
    {ok, IoData} = 'OCSP':encode('TBSRequest', TBSRequest),
    Msg = iolist_to_binary(IoData),
    public_key:sign(Msg, sha, PrivateKey).

algorithm(Alg) ->
    #'AlgorithmIdentifier'{
        algorithm = Alg,
        parameters = ?DER_NULL
    }.
