import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Produces the committed Bouncy Castle interoperability fixtures, or verifies
 * cryptomsg output. Every key is generated here and written in PEM next to the
 * CMS objects, so the Go tests can decrypt and verify without a JVM.
 */
public final class Fixtures {
    static final byte[] CONTENT = repeat("bouncycastle interop content line\n", 400);
    static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);

    record Identity(String name, KeyPair keys, X509Certificate cert) {}

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        if (args.length == 2 && args[0].equals("generate")) {
            generate(Paths.get(args[1]));
        } else if (args.length == 2 && args[0].equals("verify")) {
            verify(Paths.get(args[1]));
        } else {
            System.err.println("usage: Fixtures generate <outdir> | verify <dir>");
            System.exit(1);
        }
    }

    static void generate(Path out) throws Exception {
        Files.createDirectories(out);
        Files.write(out.resolve("content.bin"), CONTENT);
        Identity rsa = identity("rsa2048", "RSA", 2048, null, "SHA256withRSA");
        Identity p256 = identity("p256", "EC", 0, "P-256", "SHA256withECDSA");
        Identity p384 = identity("p384", "EC", 0, "P-384", "SHA384withECDSA");
        Identity ed = identity("ed25519", "Ed25519", 0, null, "Ed25519");
        for (Identity id : List.of(rsa, p256, p384, ed)) {
            writePem(out.resolve(id.name + ".crt"), "CERTIFICATE", id.cert.getEncoded());
            writePem(out.resolve(id.name + ".key"), "PRIVATE KEY", id.keys.getPrivate().getEncoded());
        }
        List<Identity> recipients = List.of(rsa, p256, p384);

        // AuthEnvelopedData, both ciphers, both recipient identifiers, DER and BER.
        Files.write(out.resolve("authenv-aes256gcm-ias.der"),
                authEnveloped(recipients, CMSAlgorithm.AES256_GCM, false).toASN1Structure().getEncoded(ASN1Encoding.DER));
        Files.write(out.resolve("authenv-aes128gcm-ski.der"),
                authEnveloped(recipients, CMSAlgorithm.AES128_GCM, true).toASN1Structure().getEncoded(ASN1Encoding.DER));
        Files.write(out.resolve("authenv-aes256gcm-ski.ber"),
                authEnveloped(recipients, CMSAlgorithm.AES256_GCM, true).toASN1Structure().getEncoded(ASN1Encoding.BER));
        // Legacy EnvelopedData with AES-CBC.
        Files.write(out.resolve("env-aes256cbc-ias.der"),
                enveloped(recipients, CMSAlgorithm.AES256_CBC).toASN1Structure().getEncoded(ASN1Encoding.DER));

        // SignedData for every signing row, attached and detached, with ESSCertIDv2.
        Map<Identity, String> sigAlg = new LinkedHashMap<>();
        sigAlg.put(p256, "SHA256withECDSA");
        sigAlg.put(p384, "SHA384withECDSA");
        sigAlg.put(rsa, "SHA256withRSAandMGF1");
        sigAlg.put(ed, "Ed25519");
        for (Map.Entry<Identity, String> e : sigAlg.entrySet()) {
            Files.write(out.resolve("signed-" + e.getKey().name + "-detached.der"),
                    signed(e.getKey(), e.getValue(), false).getEncoded(ASN1Encoding.DER));
            Files.write(out.resolve("signed-" + e.getKey().name + "-attached.der"),
                    signed(e.getKey(), e.getValue(), true).getEncoded(ASN1Encoding.DER));
        }
        Files.write(out.resolve("signed-p256-attached.ber"), signed(p256, "SHA256withECDSA", true).getEncoded());
        System.out.println("fixtures written to " + out);
    }

    static Identity identity(String name, String alg, int bits, String curve, String sigAlg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
        if (curve != null) kpg.initialize(new ECGenParameterSpec(curve));
        else if (bits > 0) kpg.initialize(bits);
        KeyPair kp = kpg.generateKeyPair();
        X500Name dn = new X500Name("CN=" + name + " fixture,O=cryptomsg interop");
        Date notBefore = new Date(1767225600000L); // 2026-01-01
        Date notAfter = new Date(2082758400000L);  // 2036-01-01
        BigInteger serial = BigInteger.valueOf(Math.abs(name.hashCode()) + 1000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(dn, serial, notBefore, notAfter, dn, kp.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(kp.getPublic()));
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
        return new Identity(name, kp, cert);
    }

    static byte[] ski(X509Certificate cert) throws Exception {
        return new JcaX509CertificateHolder(cert).getExtension(Extension.subjectKeyIdentifier)
                .getParsedValue().toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    static byte[] skiBytes(X509Certificate cert) throws Exception {
        return SubjectKeyIdentifier.getInstance(new JcaX509CertificateHolder(cert)
                .getExtension(Extension.subjectKeyIdentifier).getParsedValue()).getKeyIdentifier();
    }

    static AlgorithmIdentifier oaepSha256() {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP,
                new RSAESOAEPparams(SHA256, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, SHA256),
                        RSAESOAEPparams.DEFAULT_P_SOURCE_ALGORITHM));
    }

    static void addRecipients(CMSEnvelopedGenerator gen, List<Identity> recipients, ASN1ObjectIdentifier contentAlg, boolean ski) throws Exception {
        boolean aes256 = contentAlg.equals(CMSAlgorithm.AES256_GCM) || contentAlg.equals(CMSAlgorithm.AES256_CBC);
        ASN1ObjectIdentifier wrap = aes256 ? CMSAlgorithm.AES256_WRAP : CMSAlgorithm.AES128_WRAP;
        for (Identity r : recipients) {
            if (r.keys.getPublic().getAlgorithm().equals("RSA")) {
                JceKeyTransRecipientInfoGenerator ktri = ski
                        ? new JceKeyTransRecipientInfoGenerator(skiBytes(r.cert), oaepSha256(), r.keys.getPublic())
                        : new JceKeyTransRecipientInfoGenerator(r.cert, oaepSha256());
                gen.addRecipientInfoGenerator(ktri.setProvider("BC"));
            } else {
                String curve = r.name.equals("p384") ? "P-384" : "P-256";
                ASN1ObjectIdentifier kdf = r.name.equals("p384") ? CMSAlgorithm.ECDH_SHA384KDF : CMSAlgorithm.ECDH_SHA256KDF;
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
                kpg.initialize(new ECGenParameterSpec(curve));
                KeyPair eph = kpg.generateKeyPair();
                JceKeyAgreeRecipientInfoGenerator kari = new JceKeyAgreeRecipientInfoGenerator(kdf, eph.getPrivate(), eph.getPublic(), wrap).setProvider("BC");
                if (ski) kari.addRecipient(skiBytes(r.cert), r.keys.getPublic());
                else kari.addRecipient(r.cert);
                gen.addRecipientInfoGenerator(kari);
            }
        }
    }

    static CMSAuthEnvelopedData authEnveloped(List<Identity> recipients, ASN1ObjectIdentifier alg, boolean ski) throws Exception {
        CMSAuthEnvelopedDataGenerator gen = new CMSAuthEnvelopedDataGenerator();
        addRecipients(gen, recipients, alg, ski);
        OutputAEADEncryptor enc = (OutputAEADEncryptor) new JceCMSContentEncryptorBuilder(alg).setProvider("BC").build();
        return gen.generate(new CMSProcessableByteArray(CONTENT), enc);
    }

    static CMSEnvelopedData enveloped(List<Identity> recipients, ASN1ObjectIdentifier alg) throws Exception {
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        addRecipients(gen, recipients, alg, false);
        OutputEncryptor enc = new JceCMSContentEncryptorBuilder(alg).setProvider("BC").build();
        return gen.generate(new CMSProcessableByteArray(CONTENT), enc);
    }

    static CMSSignedData signed(Identity signer, String sigAlg, boolean attached) throws Exception {
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        byte[] certHash = MessageDigest.getInstance("SHA-256").digest(signer.cert.getEncoded());
        X509CertificateHolder holder = new JcaX509CertificateHolder(signer.cert);
        IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(holder.getIssuer())), holder.getSerialNumber());
        ESSCertIDv2 essId = new ESSCertIDv2(certHash, issuerSerial); // SHA-256 default, omitted
        Hashtable<ASN1ObjectIdentifier, org.bouncycastle.asn1.cms.Attribute> table = new Hashtable<>();
        table.put(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new org.bouncycastle.asn1.cms.Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(new SigningCertificateV2(new ESSCertIDv2[]{essId}))));
        ContentSigner cs = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(signer.keys.getPrivate());
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(table)))
                .build(cs, signer.cert));
        gen.addCertificates(new JcaCertStore(List.of(signer.cert)));
        return gen.generate(new CMSProcessableByteArray(CONTENT), attached);
    }

    /** Verifies cryptomsg output written by the Go test: envelopes decrypt for each fixture recipient, signatures verify. */
    static void verify(Path dir) throws Exception {
        Map<String, Identity> ids = new LinkedHashMap<>();
        for (String name : List.of("rsa2048", "p256", "p384", "ed25519")) {
            ids.put(name, load(dir, name));
        }
        byte[] content = Files.readAllBytes(dir.resolve("content.bin"));
        int checked = 0;
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, "go-*.der")) {
            for (Path f : files) {
                String n = f.getFileName().toString();
                byte[] data = Files.readAllBytes(f);
                if (n.startsWith("go-authenv")) {
                    CMSAuthEnvelopedData aed = new CMSAuthEnvelopedData(data);
                    for (Identity r : List.of(ids.get("rsa2048"), ids.get("p256"), ids.get("p384"))) {
                        byte[] got = decryptFor(aed.getRecipientInfos(), r);
                        if (!Arrays.equals(got, content)) throw new IllegalStateException(n + ": wrong plaintext for " + r.name);
                        checked++;
                    }
                } else if (n.startsWith("go-signed")) {
                    CMSSignedData sd = n.contains("detached")
                            ? new CMSSignedData(new CMSProcessableByteArray(content), data)
                            : new CMSSignedData(data);
                    for (SignerInformation si : sd.getSignerInfos().getSigners()) {
                        X509CertificateHolder c = (X509CertificateHolder) sd.getCertificates().getMatches(si.getSID()).iterator().next();
                        if (!si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(c))) {
                            throw new IllegalStateException(n + ": signature does not verify");
                        }
                        if (si.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) == null) {
                            throw new IllegalStateException(n + ": no signingCertificateV2");
                        }
                        checked++;
                    }
                }
                System.out.println("ok " + n);
            }
        }
        if (checked == 0) throw new IllegalStateException("nothing verified in " + dir);
        System.out.println(checked + " checks passed");
    }

    static byte[] decryptFor(RecipientInformationStore store, Identity r) throws Exception {
        for (RecipientInformation ri : store.getRecipients()) {
            if (!ri.getRID().match(new JcaX509CertificateHolder(r.cert))) continue;
            if (r.keys.getPublic().getAlgorithm().equals("RSA")) {
                return ri.getContent(new JceKeyTransEnvelopedRecipient(r.keys.getPrivate()).setProvider("BC"));
            }
            return ri.getContent(new JceKeyAgreeEnvelopedRecipient(r.keys.getPrivate()).setProvider("BC"));
        }
        throw new IllegalStateException("no RecipientInfo for " + r.name);
    }

    static Identity load(Path dir, String name) throws Exception {
        byte[] certDER = readPem(dir.resolve(name + ".crt"));
        byte[] keyDER = readPem(dir.resolve(name + ".key"));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(new X509CertificateHolder(certDER));
        String alg = cert.getPublicKey().getAlgorithm();
        PrivateKey key = KeyFactory.getInstance(alg, "BC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyDER));
        return new Identity(name, new KeyPair(cert.getPublicKey(), key), cert);
    }

    static byte[] readPem(Path p) throws IOException {
        try (org.bouncycastle.util.io.pem.PemReader r = new org.bouncycastle.util.io.pem.PemReader(Files.newBufferedReader(p))) {
            return r.readPemObject().getContent();
        }
    }

    static void writePem(Path p, String type, byte[] der) throws IOException {
        try (PemWriter w = new PemWriter(Files.newBufferedWriter(p))) {
            w.writeObject(new PemObject(type, der));
        }
    }

    static byte[] repeat(String s, int n) {
        return s.repeat(n).getBytes(StandardCharsets.UTF_8);
    }
}
