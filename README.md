# demo-golang-msal-multitenant

Example of using Entra ID (formerly Azure AD) authentication to grant an application access to another tenant.

The [src](src) directory is a very simple Go web application which allows a user tenant to grant access for the application to their tenant, and select a subscription to grant the Azure Reader RBAC role to the application.

Within the Azure directory there will exist an App Registration in the source tenant as well as an Enterprise Application.

In the user tenant's directory there will only exist the Enterprise Application, aka Service Principal. All of the authentication secrets are managed in the source tenant.

I have also built a similar example in Python which includes a backend service authenticating unattended: https://github.com/ChrisRomp/demo-python-msal-multitenant
