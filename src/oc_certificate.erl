-module(oc_certificate).

-export([
        subject_name/1,
        subject_public_key/1,
        serial_number/1,
        find_issuer/2,
        hash_subject_name/2,
        hash_subject_public_key/2
    ]).
-include_lib("public_key/include/public_key.hrl").

-type certificate()    :: binary() | #'Certificate'{} | #'TBSCertificate'{} .
-type directory_name() :: {rdnSequence, [[#'AttributeTypeAndValue'{}]]}.
-type hash_algorithm() :: sha. % Just sha for now.

-spec subject_name( certificate() ) -> directory_name().
subject_name(Certificate) when is_binary(Certificate) ->
    subject_name(public_key:pkix_decode_cert(Certificate, plain));
subject_name(#'Certificate'{tbsCertificate = TBSCertificate}) ->
    subject_name(TBSCertificate);
subject_name(#'TBSCertificate'{subject = Subject}) ->
    Subject.

-spec subject_public_key( certificate() ) -> rsa_public_key() | dsa_public_key().
subject_public_key(Certificate) when is_binary(Certificate) ->
    subject_public_key(public_key:pkix_decode_cert(Certificate, plain));
subject_public_key(#'Certificate'{tbsCertificate = TBSCertificate}) ->
    subject_public_key(TBSCertificate);
subject_public_key(#'TBSCertificate'{subjectPublicKeyInfo = Info}) ->
    subject_public_key(Info);
subject_public_key(#'SubjectPublicKeyInfo'{
        algorithm = #'AlgorithmIdentifier'{ algorithm = Algo },
        subjectPublicKey = {0, BinaryPublicKey}
    }) ->
    Type = pubkey_cert_records:supportedPublicKeyAlgorithms(Algo),
    {ok, PublicKey} = 'OTP-PUB-KEY':decode(Type, BinaryPublicKey),
    PublicKey.

-spec serial_number( certificate() ) -> integer().
serial_number(Certificate) when is_binary(Certificate) ->
    serial_number(public_key:pkix_decode_cert(Certificate, plain));
serial_number(#'Certificate'{tbsCertificate = TBSCertificate}) ->
    serial_number(TBSCertificate);
serial_number(#'TBSCertificate'{serialNumber = Serial}) ->
    Serial.

-spec find_issuer( binary(), CAChain::[binary()] ) -> #'Certificate'{} | {error, issuer_not_found}.
find_issuer(_, []) ->
    {error, issuer_not_found};
find_issuer(Cert, [CA | Rest]) ->
    case public_key:pkix_is_issuer(Cert, CA) of
        true ->
            public_key:pkix_decode_cert(CA, plain);
        false ->
            find_issuer(Cert, Rest)
    end.

-spec hash_subject_name( hash_algorithm(), certificate() ) -> binary().
hash_subject_name(Alg, Certificate) ->
    hash(Alg, public_key:der_encode('Name', subject_name(Certificate))).

-spec hash_subject_public_key( hash_algorithm(), certificate() ) -> binary().
hash_subject_public_key(Alg, Certificate) when is_binary(Certificate) ->
    hash_subject_public_key(Alg, public_key:pkix_decode_cert(Certificate, plain));
hash_subject_public_key(Alg, #'Certificate'{tbsCertificate = TBSCertificate}) ->
    hash_subject_public_key(Alg, TBSCertificate);
hash_subject_public_key(Alg, #'TBSCertificate'{subjectPublicKeyInfo = Info}) ->
    hash_subject_public_key(Alg, Info);
hash_subject_public_key(Alg, #'SubjectPublicKeyInfo'{subjectPublicKey = {_, Key}}) ->
    hash(Alg, Key).

hash(sha, Binary) when is_binary(Binary) ->
    crypto:sha(Binary).
