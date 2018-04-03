import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Map;

import org.wildfly.extension.elytron.Configurable;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

public class MyRealm implements SecurityRealm, Configurable {

    private String myAttribute;

    // receiving configuration from subsystem
    public void initialize(Map<String, String> configuration) {
        myAttribute = configuration.get("myAttribute");
        System.out.println("MyRealm initialized with myAttribute = " + myAttribute);
    }

    // this realm does not allow acquiring credentials
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
            AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    // this realm will be able to verify password evidences only
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
            throws RealmUnavailableException {
        return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {

        if ("myadmin".equals(principal.getName())) { // identity "myadmin" will have password "mypassword"
            return new RealmIdentity() {
                public Principal getRealmIdentityPrincipal() {
                    return principal;
                }

                public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType,
                        String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                    return SupportLevel.UNSUPPORTED;
                }

                public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                    return null;
                }

                public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)
                        throws RealmUnavailableException {
                    return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
                }

                // evidence will be accepted if it is password "mypassword"
                public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                    if (evidence instanceof PasswordGuessEvidence) {
                        PasswordGuessEvidence guess = (PasswordGuessEvidence) evidence;
                        try {
                            return Arrays.equals("mypassword".toCharArray(), guess.getGuess());

                        } finally {
                            guess.destroy();
                        }
                    }
                    return false;
                }

                public boolean exists() throws RealmUnavailableException {
                    return true;
                }
            };
        }

        return RealmIdentity.NON_EXISTENT;
    }
}
