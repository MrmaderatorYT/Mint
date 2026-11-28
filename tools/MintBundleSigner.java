import java.nio.file.Path;
import java.security.CodeSigner;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Verifies each AAB payload entry against its JAR signature before returning the signer fingerprint. */
class MintBundleSigner {
    public static void main(String[] args) throws Exception {
        String signer = null;
        byte[] buffer = new byte[65536];
        var seen = new HashSet<String>();
        try (var bundle = new JarFile(Path.of(args[0]).toFile(), true)) {
            var entries = bundle.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!seen.add(name)) {
                    throw new SecurityException("Duplicate bundle entry");
                }
                if (entry.isDirectory() || signatureMetadata(name)) {
                    continue;
                }

                // JarFile exposes the CodeSigners only after reading the full entry.
                try (var input = bundle.getInputStream(entry)) {
                    while (input.read(buffer) != -1) {
                        // Reading validates the signature digest.
                    }
                }
                CodeSigner[] signedBy = entry.getCodeSigners();
                if (signedBy == null || signedBy.length != 1) {
                    throw new SecurityException("Each bundle payload entry must have one signer");
                }
                byte[] certificate = signedBy[0].getSignerCertPath().getCertificates().get(0).getEncoded();
                String fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate));
                if (signer != null && !signer.equals(fingerprint)) {
                    throw new SecurityException("Bundle payload entries have different signers");
                }
                signer = fingerprint;
            }
        }
        if (signer == null) {
            throw new SecurityException("Bundle has no signed payload");
        }
        System.out.println(signer);
    }

    private static boolean signatureMetadata(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String basename = name.substring("META-INF/".length()).toUpperCase(Locale.ROOT);
        if (basename.contains("/")) return false;
        return basename.equals("MANIFEST.MF") || basename.startsWith("SIG-")
                || basename.endsWith(".SF") || basename.endsWith(".RSA")
                || basename.endsWith(".DSA") || basename.endsWith(".EC");
    }
}
