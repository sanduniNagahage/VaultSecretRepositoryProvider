# VaultSecretRepositoryProvider

Wso2 Identity Server can accomadate mutiple secret repositories other than the inbuilt FilebaseSecretrepository.

- **Secret Repository** - the component responsible to fetch the secrets from the external vaults by taking the alias of that secret as an argument.
- **Secret Repository Provider** - initialize the Secret Repositories given under that specific Secret Provider in the configuration properties by passing the relevant properties and returns an initialized Secret repositories array.

Secret Repositories can fall into various categories,Vault Secret Repository Provider will contains all types of secret repositories which fall into the category of vault.
