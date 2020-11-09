/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */

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

    /* Property String for secretProviders. */
    private final static String PROP_SECRET_PROVIDERS = "secretProviders";

    /* Property String for repositories. */
    private final static String PROP_REPOSITORIES = "repositories";

    /* Property String for properties. */
    private final static String PROP_PROPERTIES = "properties";

    /* Dot String. */
    private final static String DOT = ".";

    /* Contains all initialized secret repositories under provider type vault. */
    private HashMap<String, SecretRepository> vaultRepositoryMap = new HashMap<>();

    /**
     * @see org.wso2.securevault.secret.SecretRepositoryProvider
     */
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                                TrustKeyStoreWrapper trustKeyStoreWrapper) {

        return null;
    }

    /**
     * Returns a map containing initialized secret repositories corresponds to a give provider type.
     *
     * @param configurationProperties All the properties under secret configuration file.
     * @param providerType            Type of the VaultSecretRepositoryProvider class.
     * @return Initialized secret repository map.
     */
    public HashMap<String, SecretRepository> initProvider(Properties configurationProperties, String providerType) {

        //Get the list of repositories from the secret configurations.
        String repositoriesStringPropKey = PROP_SECRET_PROVIDERS + DOT + providerType + DOT + PROP_REPOSITORIES;
        String repositoriesString = getPropertiesFromSecretConfigurations(configurationProperties,
                repositoriesStringPropKey);

        if (validatePropValue(repositoriesString)) {
            // Add the list of repositories to an array.
            String[] repositoriesArr = repositoriesString.split(",");

            for (String repo : repositoriesArr) {
                // Get the property contains the fully qualified class name of the repository.
                String repositoryClassNamePropKey =
                        PROP_SECRET_PROVIDERS + DOT + providerType + DOT + PROP_REPOSITORIES + DOT + repo;
                String repositoryClassName = getPropertiesFromSecretConfigurations(configurationProperties,
                        repositoryClassNamePropKey);

                if (validatePropValue(repositoryClassName)) {
                    try {
                        // Create a new instance of the class.
                        Class repositoryClass = getClass().getClassLoader().loadClass(repositoryClassName.trim());
                        Object repositoryImpl = repositoryClass.newInstance();

                        if (repositoryImpl instanceof SecretRepository) {
                            Properties repositoryProperties = filterConfigurations(configurationProperties, repo);
                            ((SecretRepository) repositoryImpl).init(repositoryProperties, providerType);
                            vaultRepositoryMap.put(repo, (SecretRepository) repositoryImpl);
                        }
                    } catch (ClassNotFoundException e) {
                        handleException("A Secret Provider cannot be found for class name : " + repositoryClassName);
                    } catch (IllegalAccessException e) {
                        handleException("Error creating an instance, Method does not have access to the class : " +
                                repositoryClassName);
                    } catch (InstantiationException e) {
                        handleException("Error creating an instance from class : " + repositoryClassName);
                    }
                }
            }
        }
        return vaultRepositoryMap;
    }

    /**
     * Return the properties for a provided repository.
     *
     * @param configProperties All the properties under secret configuration file.
     * @param repository       Repository listed under the vault provider.
     * @return Filtered properties.
     */
    public Properties filterConfigurations(Properties configProperties, String repository) {

        Properties filteredProps = new Properties();
        String propertyKeyPrefix = repository + DOT + PROP_PROPERTIES;

        configProperties.forEach((propKey, propValue) -> {
            if (propKey.toString().contains(propertyKeyPrefix)) {
                filteredProps.put(propKey, propValue);
            }
        });
        return filteredProps;
    }

    /**
     * Helper method for handle errors.
     *
     * @param msg error message to be displayed.
     */
    private static void handleException(String msg) {

        log.error(msg);
        throw new SecureVaultException(msg);
    }

    /**
     * Util method for getting property values from the secret-conf file.
     *
     * @param secretConfigProps All the properties under secret configuration file.
     * @param propName          Name of the property.
     * @return Returns the value for the give property.
     */
    private String getPropertiesFromSecretConfigurations(Properties secretConfigProps, String propName) {

        return MiscellaneousUtil.getProperty(secretConfigProps, propName, null);
    }

    /**
     * Validate the property value to avoid the processing of null values.
     *
     * @param propValue Value of the required property.
     * @return Return true if not null.
     */
    private boolean validatePropValue(String propValue) {

        if (propValue == null || "".equals(propValue)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repository has been configured.");
            }
            return false;
        }
        return true;
    }
}
