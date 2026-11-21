"""Closed owned-app TLS negative BUILD preparation, no device/network execution.

Negative APKs are never positive-product inputs. Each case requires a separate
reviewed disposable run, fresh APK identity, original app socket/handshake logs,
zero native request/origin ledgers, and independent teardown evidence. Merely
preparing source/certificates establishes none of those observations.
"""
import hashlib

SCENARIOS=('positive','untrusted-ca','wrong-hostname')
PEER='createSocket(tunnel, "127.0.0.1", ORIGIN_PORT, true)'
WRONG_PEER='createSocket(tunnel, "owned-name-mismatch.invalid", ORIGIN_PORT, true)'


def prepare(source,public_ca_der,*,scenario='positive',negative_public_ca_der=None):
    if scenario not in SCENARIOS:raise ValueError('closed fixed TLS build scenario required')
    if source.count(PEER)!=1 or WRONG_PEER in source:raise ValueError('exact original owned app TLS peer source required')
    if scenario!='untrusted-ca' and negative_public_ca_der is not None:raise ValueError('unexpected alternate public CA')
    embedded=public_ca_der
    if scenario=='untrusted-ca':
        if negative_public_ca_der is None or negative_public_ca_der==public_ca_der:
            raise ValueError('distinct independently generated disposable public CA required')
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        keys=[]
        for data in (public_ca_der,negative_public_ca_der):
            cert=x509.load_der_x509_certificate(data)
            if cert.public_bytes(Encoding.DER)!=data or not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError('canonical public CA certificate required')
            keys.append(cert.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo))
        if keys[0]==keys[1]:raise ValueError('negative anchor must use a different public key, not only different DER')
        embedded=negative_public_ca_der
    if scenario=='wrong-hostname':
        # A TLS interception proxy can issue a leaf for client SNI. Suppress SNI
        # only in this negative so the fixed CONNECT IP still determines the
        # presented leaf; HTTPS endpoint verification remains enabled against
        # the deliberately different fixed peer name. Runtime evidence is owed.
        marker='                tls.setSSLParameters(parameters);'
        if source.count(marker)!=1:raise ValueError('exact original TLS parameters source required')
        source=source.replace(PEER,WRONG_PEER).replace(marker,
            '                parameters.setServerNames(java.util.Collections.emptyList());\n'+marker)

    return source,embedded,{'tls_scenario':scenario,
        'embedded_public_ca_sha256':hashlib.sha256(embedded).hexdigest(),
        'expected_tls_peer':'owned-name-mismatch.invalid' if scenario=='wrong-hostname' else '127.0.0.1',
        'tcp_and_connect_destination_unchanged':True,
        'negative_runtime_not_executed':scenario!='positive'}
