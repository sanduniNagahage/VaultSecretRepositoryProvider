package org.wso2.securevault.provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

import java.util.HashMap;
import java.util.Properties;

public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {

    private static Log log = LogFactory.getLog(VaultSecretRepositoryProvider.class);

    /* Property string for external vault secret repositories */
    private final static String PROP_EXTERNAL_VAULT_SECRET_REPOSITORIES = "externalvaultsecretRepositories";
    /* Property string for Secret Repository Providers */
    private final static String SECRET_REPOSITORY_PROVIDERS = "secretRepositoryProviders";
    /* Dot String */
    private final static String DOT = ".";
    /* To get initialized external secret repository */
    private SecretRepository vaultRepository;
    /* Contains all initialized external secret repositories */
    private HashMap<String,SecretRepository> vaultRepositoryMap = new HashMap<>();

    /**
     *
     * @see org.wso2.securevault.secret.SecretRepositoryProvider
     */
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                                TrustKeyStoreWrapper trustKeyStoreWrapper) { return null; }

    /**
     *
     * @param configurationProperties   All the properties under secret configuration file
     * @param providerType              Type of the VaultSecretRepositoryProvider class
     * @return                          Initialized secret repository map
     */
    public HashMap<String, SecretRepository> initProvider(Properties configurationProperties, String providerType) {

        Properties repositoryProperties;

        String externalrepositoriesString = MiscellaneousUtil.getProperty(
                configurationProperties, PROP_EXTERNAL_VAULT_SECRET_REPOSITORIES, null);
        if (externalrepositoriesString == null || "".equals(externalrepositoriesString)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return null;
        }

        String[] externalrepositoriesArr = externalrepositoriesString.split(",");
        if (externalrepositoriesArr == null || externalrepositoriesArr.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return null;
        }

        for (String externalRepo : externalrepositoriesArr){

            StringBuffer sb = new StringBuffer();
            sb.append(PROP_EXTERNAL_VAULT_SECRET_REPOSITORIES);
            sb.append(DOT);
            sb.append(externalRepo);

            String externalRepository = MiscellaneousUtil.getProperty(
                    configurationProperties, sb.toString(), null);
            if (externalRepository == null || "".equals(externalRepository)) {
                handleException("Repository provider cannot be null ");
            }

            try {
               Class aClass = getClass().getClassLoader().loadClass(externalRepository.trim());
                Object instance = aClass.newInstance();

                if (instance instanceof SecretRepository) {
                    repositoryProperties = filterConfigurations(configurationProperties, providerType, externalRepo);
                    vaultRepository = (SecretRepository) instance;
                    vaultRepository.init(repositoryProperties, providerType);
                    vaultRepositoryMap.put(vaultRepository.getType(), vaultRepository);

                }

            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            } catch (InstantiationException e) {
                e.printStackTrace();
            }
        }
        return vaultRepositoryMap;
    }

    /**
     *
     * @param properties   All the properties under secret configuration file
     * @param provider     Type of the VaultSecretRepositoryProvider class
     * @param repository   Repository type retrieved from externalvaultsecretRepositories property
     * @return             Filtered properties
     */
    public Properties filterConfigurations(Properties properties, String provider, String repository) {

        String propertyString = SECRET_REPOSITORY_PROVIDERS+DOT+provider+DOT+repository;
        new Properties();
        Properties filteredProps;
        filteredProps = (Properties) properties.clone();
        properties.forEach((k, v) ->{
            if(!(k.toString().contains(propertyString))){
                filteredProps.remove(k);
            }
        });
        return filteredProps;
    }

    /**
     *
     * @param msg  error message to be displayed
     */
    private static void handleException(String msg) {
        log.error(msg);
        throw new SecureVaultException(msg);
    }
}
