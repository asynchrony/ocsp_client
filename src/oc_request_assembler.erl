-module(oc_request_assembler).
-export([assemble_request/4]).

-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

-define(DER_NULL, <<5,0>>). %% public_key defines this, but not in a HRL.
-define(SHA_ALGORITHM_ID, #'AlgorithmIdentifier'{ algorithm = ?'id-sha1', parameters = ?DER_NULL }).

assemble_request(IssuerName, IssuerKey, SerialNumber, Nonce) ->
    #'OCSPRequest'{ tbsRequest = #'TBSRequest'{ 
                                requestList = [ #'Request' { reqCert = populate_certificate_id(IssuerName, IssuerKey, SerialNumber) } ],
                                requestExtensions = [populate_nonce_extension(Nonce)] } }.

populate_certificate_id(IssuerName, IssuerKey, SerialNumber) ->
    #'CertID'{ hashAlgorithm = ?SHA_ALGORITHM_ID,
               issuerNameHash = crypto:sha(IssuerName),
               issuerKeyHash = crypto:sha(IssuerKey),
               serialNumber = SerialNumber }.

populate_nonce_extension(Nonce) ->
    #'Extension'{ extnID = ?'id-pkix-ocsp-nonce',
                  critical = false,
                  extnValue = Nonce }.
