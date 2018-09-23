# Keycloak Registration Page with invalid username check

This module contains the project extension and theme for the registration page with invalid username check.

## Getting Started

### Prerequisites
* Keycloak 4.4.0-Final

### Installation
Click [here](https://www.keycloak.org/docs/latest/getting_started/index.html) for guidelines on how to install keycloak.

## Deployment
### Packaging
Package the project by running the command below

```
$ mvn clean package
```

### Deploying

Deploy the packaged jar and the theme located inside the theme folder to keycloak.

### Applying extension

1. Login to Admin Console.
2. Select realm.
3. Go to Authentication page.
4. Copy Registration authentication.
5. Delete Profile Validation execution.
6. Add Profile Validation with Invalid Usernames.
7. Change requirement to REQUIRED.
8. Add Username Pattern, and Invalid Usernames in configuration.