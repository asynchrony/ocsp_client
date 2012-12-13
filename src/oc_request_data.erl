-module(oc_request_data).

-export([get_request_data/1, generate_crypto_nonce/0]).

-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

get_request_data(PeerCert) ->
    PemBinary = mp_certificate_files:read(trust_chain),
    CAChain = public_key:pem_decode(PemBinary),
    {IssuerName, IssuerKey} = get_issuer_info(PeerCert, CAChain),

    Serial = read_serial_number(PeerCert),

    {IssuerName, IssuerKey, Serial}.

generate_crypto_nonce() ->
    crypto:sha(crypto:rand_bytes(20)).

read_serial_number(PeerCert) ->
    ClientCert = public_key:pkix_decode_cert(PeerCert, plain),
    SerialNumber = ClientCert#'Certificate'.tbsCertificate#'TBSCertificate'.serialNumber,
    SerialNumber.

find_issuer(Cert, CAChain) ->
    [IssuerCert] = [public_key:pkix_decode_cert(PotentialIssuer, plain) || 
        {_, PotentialIssuer, _} <- CAChain, public_key:pkix_is_issuer(Cert, PotentialIssuer)],
    IssuerCert.

get_issuer_info(Cert, CAChain) ->
    IssuerCert = find_issuer(Cert, CAChain),
    IssuerName = IssuerCert#'Certificate'.tbsCertificate#'TBSCertificate'.subject,
    {_, IssuerKey} = IssuerCert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo#'SubjectPublicKeyInfo'.subjectPublicKey,
    {public_key:der_encode('Name', IssuerName), IssuerKey}.
