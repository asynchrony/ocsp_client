-module(oc_request_data).

-export([get_request_data/1]).

-include_lib("public_key/include/public_key.hrl").
-include("OCSP.hrl").

get_request_data(PeerCert) ->
    CAChain = tls_certificate_repo:get_ca_chain(),
    {IssuerName, IssuerKey} = get_issuer_info(PeerCert, CAChain),

    Serial = read_serial_number(PeerCert),

    {IssuerName, IssuerKey, Serial}.

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
