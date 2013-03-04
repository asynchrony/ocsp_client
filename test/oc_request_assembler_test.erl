-module(oc_request_assembler_test).
-compile([export_all]).
-include_lib("test_support/include/test_helper.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

assemble_request_returns_proper_request_with_nonce_in_bytes_test() ->
    Nonce = <<"NONCE">>,
    IssuerName = <<"Test Issuer">>,
    IssuerKey = <<"Test Key">>,
    SerialNumber = 1,
    CertId = #'CertID'{ hashAlgorithm = #'AlgorithmIdentifier'{ algorithm = ?'id-sha1', parameters = <<5,0>> },
                        issuerNameHash = crypto:sha(IssuerName),
                        issuerKeyHash = crypto:sha(IssuerKey),
                        serialNumber = SerialNumber },
    NonceExtension = #'Extension'{ extnID = ?'id-pkix-ocsp-nonce',
                                   critical = false,
                                   extnValue = Nonce },
    ExpectedRequest = #'OCSPRequest'{ tbsRequest = #'TBSRequest'{ requestList = [ #'Request' { reqCert = CertId } ],
                                 requestExtensions = [NonceExtension] } },

    ?assertMatch(ExpectedRequest, oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber, Nonce)).
