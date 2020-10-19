package org.wso2.securevault.provider;

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.ServiceLoader;

public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {

    SecretRepository vaultRepository;
    HashMap<String,SecretRepository> vaultRepositoryMap = new HashMap<String, SecretRepository>();

    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                                TrustKeyStoreWrapper trustKeyStoreWrapper) {

        return null;
    }

    public HashMap<String, SecretRepository> initProvider(String[] externalRepositoriesArr,
                                                          Properties configurationProperties, String providerType) {

        Properties repositoryProperties;
        ServiceLoader<SecretRepository> loader = ServiceLoader.load(SecretRepository.class);

        for (SecretRepository secretRepository : loader) {
            vaultRepository = secretRepository;
            String repoType = vaultRepository.getType();
            if (Arrays.asList(externalRepositoriesArr).contains(repoType)) {
                repositoryProperties = filterConfigurations(configurationProperties, providerType, repoType);
                vaultRepository.init(repositoryProperties, providerType);
                vaultRepositoryMap.put(vaultRepository.getType(), vaultRepository);
            }
        }
        return vaultRepositoryMap;
    }

    public Properties filterConfigurations(Properties properties, String provider, String repository) {

        String propertyString = "secretRepositories."+provider+"."+repository;
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
}
