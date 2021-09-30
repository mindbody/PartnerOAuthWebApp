# Getting Started

## PartnerOAuthWebApp

You'll need to follow these processes in the order given.

**OAuth**

OAuth is another way to authorize endpoints by obtaining access token. The OAuth 2.0 authorization is a framework that allows user to grant a third party website or application access to the user's protected resources, without necessarily revealing their credentials or even identity.

In OAuth, the client request access to resources controlled by the resource owner and hosted by the resource server and is issued a different set of credentials than those of the resource owner. Instead of using the resource owner's credentials to access protected resources, the partner obtains an access token i.e. a string denoting a specific scope, lifetime and other attributes.

Access tokens are issued to the third party clients by an authorization server with the approval of the resource owner, then the client uses the access token to access the protected resources. Access tokens are in Json Web Token (JWT) format. The permissions represented by the access token in OAuth terms are known as scopes.

For OAuth client creation, please [Contact API Support](https://support.mindbodyonline.com/s/contactapisupport). OAuth 2.0 uses below two endpoints to get bearer access token to call Public API.


Go to  **Account**.


![](/img/Oauth_1.png)

![](/img/Oauth_2.png)


Go to **API Credentials** and click on **Create new OAuth Client** and select **Web**.

![](/img/Oauth_3.png)

![](/img/Oauth_4.png)


Click on **CREATE CLIENT** and copy the secret.

![](/img/Oauth_5.png)

![](/img/Oauth_6.PNG)


Click on **Manage**. You will be able to see **Configurations** and **Oauth Credentials**.

![](/img/Oauth_7.png)

![](/img/Oauth_8.png)


Once Oauth Client is created you can use the endpoint for Authorization.



**Authorize**


[https://signin.mindbodyonline.com/connect/authorize"](https://signin.mindbodyonline.com/connect/authorize)

This endpoint initiates a sign in workflow.  An OAuth Client will need to be provisioned for your account in order to use this endpoint.

** Parameters**

**Name** | **Type** | **Description**
--- | --- | ---
**response_mode** | string | Use the value `form_post`.
**response_type** | string | Determines the authorization processing flow to be used.  Clients created as type web will be assigned the OpenID Connect hybrid flow and should use `code id_token`.  Clients created as type native or SPA will use OpenID Connect code flow with PKCE and should use `code`.
**client_id** | string | Your OAuth Client ID.
**redirect_uri** | string | Redirection URI to which the response will be sent.
**scope** | string | Use the value `email profile openid offline_access Mindbody.Api.Public.v6`.  Your OAuth Client would need to have been provisioned with this scope. `offline_access` scope is mandatory to pass if you want refresh token back in response.
**nonce** | string | Value used to associate a Client session with an ID Token.
**subscriberId** | string | The Subscriber ID.

**get-authorize-response**

After a consumer navigates to the authorize endpoint, they will be redirected to a sign in page to complete the workflow.  This is where they will enter their username and password.

**Status Code** | **Description**
--- | ---
**200** | Redirect to OAuth provider



![](/img/Oauth_9.png)


```C#
var client = new RestClient("https://signin.mindbodyonline.com/connect/authorize?response_mode=form_post&client_id={yourClientId}&redirect_uri={yourRedirectUri}&scope=email profile openid offline_access Mindbody.Api.Public.v6.Dev&response_type=code id_token&nonce=nonce&subscriberId={subscriberId}");
client.Timeout = -1;
var request = new RestRequest(Method.GET);
IRestResponse response = client.Execute(request);
Console.WriteLine(response.Content);
```
Copy the url and paste in Browser.

Copy the Code from network tab in developer tool.

![](/img/Oauth_10.png)



![](/img/Oauth_15.PNG)


**Token**

[https://signin.mindbodyonline.com/connect/token](https://signin.mindbodyonline.com/connect/token)

This endpoint is used to request an access token in exchange for an authorization code or a refresh token.  An OAuth Client will need to be provisioned for your account in order to use this endpoint.

** Form Data**

**Name** | **Type** | **Description**
--- | --- | ---
**grant_type** | string | Specifies the workflow that the client application is using to authenticate and authorize a user against the token server.  Possible values are `authorization_code` and `refresh_token`.
**client_id** | string | Your OAuth Client ID.
**client_secret** | string | Your OAuth Client Secret.
**code** | string | Required when `grant_type` is `authorization_code`
**redirect_uri** | string | Required when `grant_type` is `authorization_code`
**refresh_token** | string | Required when `grant_type` is `refresh_token`
**scope** | string | Use the value `email profile openid offline_access Mindbody.Api.Public.v6`.  Your OAuth Client would need to have been provisioned with this scope. `offline_access` scope is mandatory to pass if you want refresh token back in response.
**nonce**<br><span class="optional">*Optional*</span> | string | Value used to associate a Client session with an ID Token.
**subscriberId** | string | The Subscriber ID.

**Response**

>Example Response

```json
{
    "id_token": "id_token",
    "access_token": "access_token",
    "refresh_token": "refresh_token",
    "token_type": "Bearer",
    "expires_in": 3600,
}
```

**Name** | **Type** | **Description**
--- | --- | ---
**id_token** | string | The ID Token is a security token that contains Claims about the Authentication of an End-User by an authorization server.
**access_token** | string | A JSON Web Token, used for authorization, that contains information about the token provider, client application, target API resource, etc.
**refresh_token** | string | Present when the scope parameter includes `offline_access`. A token that can be used to obtain a new set of tokens from the token server.
**token_type** | string | Type of the token is set to "Bearer".
**expires_in** | number | The lifetime in seconds of the access token.

Hit the  Get Token api and copy the access token

![](/img/Oauth_11.png)

```C#
var client = new RestClient("https://signin.mindbodyonline.com/connect/token");
client.Timeout = -1;
var request = new RestRequest(Method.POST);
request.AddHeader("accept", "application/json");
request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
request.AddParameter("client_secret", "{yourClientSecret}");
request.AddParameter("client_id", "{yourClientId}");
request.AddParameter("scope", "email profile openid offline_access Mindbody.Api.Public.v6.Dev");
request.AddParameter("grant_type", "authorization_code");
request.AddParameter("redirect_uri", "{yourRedirectUri}");
request.AddParameter("subscriberId", "{subscriberId}");
request.AddParameter("code", "{authorizationCode}");
IRestResponse response = client.Execute(request);
Console.WriteLine(response.Content);
```


This can be used to access the public api.

Refresh token can be generated as below:

![](/img/Oauth_12.png)


```C#
var client = new RestClient("https://signin.mindbodyonline.com/connect/token");
client.Timeout = -1;
var request = new RestRequest(Method.POST);
request.AddHeader("accept", "application/json");
request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
request.AddParameter("client_secret", "{yourClientSecret}");
request.AddParameter("client_id", "{yourClientId}");
request.AddParameter("scope", "email profile openid offline_access Mindbody.Api.Public.v6.Dev");
request.AddParameter("grant_type", "refresh_token");
request.AddParameter("redirect_uri", "{yourRedirectUri}");
request.AddParameter("subscriberId", "{subscriberId}");
request.AddParameter("refresh_token", "{{refreshTokenOAuth}}");
IRestResponse response = client.Execute(request);
Console.WriteLine(response.Content);
```


