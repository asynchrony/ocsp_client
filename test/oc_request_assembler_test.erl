-module(oc_request_assembler_test).
-compile([export_all]).
-include("test_helper.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

?MOCK_FIXTURE.

assemble_request_returns_proper_request_with_nonce_in_bytes() ->
    Nonce = <<"NONCE">>,
    stub(oc_request_data, generate_crypto_nonce, 0, Nonce),
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

    ?assertMatch(ExpectedRequest, oc_request_assembler:assemble_request(IssuerName, IssuerKey, SerialNumber)).
