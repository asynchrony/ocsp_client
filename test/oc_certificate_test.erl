-module(oc_certificate_test).

-compile([export_all]).
-include_lib("test_support/include/test_helper.hrl").
-include_lib("public_key/include/public_key.hrl").


subject_name_when_cert_is_binary_test() ->
    ExpectedSubject = subject_name([ {'C',"US"}, {'O',"U.S. Government"},
            {'OU',"NSS"}, {'OU',"DoD"}, {'OU',"USN"}, {'CN',"localhost"} ]),
    [{_,Cert,_}] = test_support:read_pem_data("servercert.pem"),
    Result = oc_certificate:subject_name(Cert),
    ?assertEqual(ExpectedSubject, Result).

subject_public_key_when_cert_is_binary_test() ->
    ExpectedPublicKey = #'RSAPublicKey'{
        modulus = list_to_integer("C4753637864761AE9CC328AD412EC44536F31A55716"
                                  "490158BCE0A3748508ACDF0EFAD122D86896411B3F9"
                                  "47D1A2A4D0DDDFAA4948C8F60F8B2028235933F9FF",
                                  16),
        publicExponent = 65537
    },
    [{_,Cert,_}] = test_support:read_pem_data("servercert.pem"),
    Result = oc_certificate:subject_public_key(Cert),
    ?assertEqual(ExpectedPublicKey, Result).

serial_number_when_cert_is_binary_test() ->
    ExpectedSerial = 0,
    [{_,Cert,_}] = test_support:read_pem_data("servercert.pem"),
    Result = oc_certificate:serial_number(Cert),
    ?assertEqual(ExpectedSerial, Result).

find_issuer_should_return_record_when_issuer_found_test() ->
    [{_,PeerCert,_}] = test_support:read_pem_data("client_0001.pem"),
    ExpectedIssuer = test_support:decode_pem_entry("issuer.pem"),
    CAChain = [CA || {_,CA,_} <- test_support:read_pem_data("cacerts.pem")],

    Result = oc_certificate:find_issuer(PeerCert, CAChain),

    ?assertEqual(ExpectedIssuer, Result).

find_issuer_should_return_error_when_issuer_not_found_test() ->
    [{_,PeerCert,_}] = test_support:read_pem_data("client_0001.pem"),

    Result = oc_certificate:find_issuer(PeerCert, [PeerCert]),

    ?assertEqual({error, issuer_not_found}, Result).

hash_subject_name_test() ->
    ExpectedHash = <<134,75,228,227,251,240,172,74,112,226,223,165,
                     231,203,13,103,207,133,223,103>>,
    Cert = test_support:decode_pem_entry("servercert.pem"),
    Result = oc_certificate:hash_subject_name(sha, Cert),
    ?assertEqual(ExpectedHash, Result).

hash_subject_public_key_test() ->
    ExpectedHash = <<185,230,105,219,172,23,75,64,168,22,166,179,182,
                     78,232,113,150,101,223,126>>,
    Cert = test_support:decode_pem_entry("servercert.pem"),
    Result = oc_certificate:hash_subject_public_key(sha, Cert),
    ?assertEqual(ExpectedHash, Result).


%% Support functions for subject name
subject_name(Values) ->
    {rdnSequence, [ subject_attr(V) || V <- Values ]}.

subject_attr({ID, Value}) ->
    {OID, Type} = attribute_types(ID),
    {ok, Enc} = 'OTP-PUB-KEY':encode(Type, {printableString, Value}),
    [#'AttributeTypeAndValue'{
            type=OID,
            value=iolist_to_binary(Enc)
        }].

attribute_types('CN') ->
    {?'id-at-commonName', 'X520CommonName'};
attribute_types('O') ->
    {?'id-at-organizationName', 'X520OrganizationName'};
attribute_types('OU') ->
    {?'id-at-organizationalUnitName', 'X520OrganizationalUnitName'};
attribute_types('C') ->
    {?'id-at-countryName', 'X520countryName'}.
