package org.wso2.securevault.provider;

import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.Properties;

public class VaultSecretRepositoryProviderTest {

    private VaultSecretRepositoryProvider vaultSecretRepositoryProvider;

    @BeforeClass
    public void setUp() {

        vaultSecretRepositoryProvider = new VaultSecretRepositoryProvider();
    }

    private Properties getConfigProperties() {

        Properties configProperties = new Properties();
        configProperties
                .setProperty("secretRepositories.file.location", "repository/conf/security/cipher-text.properties");

        configProperties.setProperty("secretProviders", "vault");

        configProperties.setProperty("secretProviders.vault.provider",
                "org.wso2.securevault.provider.VaultSecretRepositoryProvider");

        configProperties.setProperty("secretProviders.vault.repositories", "hashicorp,samplerepository1");

        configProperties.setProperty("secretProviders.vault.repositories.hashicorp",
                "org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepository");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1",
                "org.wso2.carbon.securevault.repository.SampleRepository1");

        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.1",
                "samplerepository1prop1");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.2",
                "samplerepository1prop2");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.3",
                "samplerepository1prop3");

        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.address",
                "http://127.0.0.1:8200");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.namespace", "wso2is");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.path.prefix", "wso2is");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.engineVersion", "2");

        return configProperties;
    }

    @Test
    public void testFilterConfigurations() throws Exception {

        Properties actual = Whitebox.invokeMethod(vaultSecretRepositoryProvider, "filterConfigurations",
                getConfigProperties(), "hashicorp");
        Assert.assertEquals(4, actual.size());
    }

    @Test
    public void testFilterConfigurationsNegative() throws Exception {

        Properties actual = Whitebox.invokeMethod(vaultSecretRepositoryProvider, "filterConfigurations",
                getConfigProperties(), "aws");
        Assert.assertEquals(0, actual.size());
    }

    @Test
    public void testIsPropValueValidated() throws Exception {

        Properties configProps = getConfigProperties();
        configProps.forEach((key, value) -> {
            Boolean actual;
            try {
                actual = Whitebox.invokeMethod(vaultSecretRepositoryProvider, "isPropValueValidated", value);
                Assert.assertTrue(actual);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

    }
}


