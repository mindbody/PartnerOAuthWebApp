using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;

namespace PartnerWebApp.Helpers
{
    public class TokenHelper
    {
        /// <summary>
        /// Generates a cryptographically secure GUID.
        /// </summary>
        /// <returns>A <code>Guid</code></returns>
        public static Guid GenerateSecureGuid()
        {
            using (var provider = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[16];
                provider.GetBytes(bytes);
                return new Guid(bytes);
            }
        }

        /// <summary>
        /// Validates the given token based on the authority and audience.
        /// </summary>
        /// <param name="token">The token to validate</param>
        /// <param name="authorityUrl">The base URL of the identity provider that issued the token</param>
        /// <param name="validAudience">The audience parameter to use for validation</param>
        /// <param name="nonce">Optional nonce for validating id_token</param>
        /// <returns></returns>
        public static bool ValidateToken(string token, string authorityUrl, string validAudience, string nonce)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var identityResult = new HttpClient().GetStringAsync($"{authorityUrl}/.well-known/openid-configuration/jwks")
                                                .GetAwaiter()
                                                .GetResult();

            var keys = JsonConvert.DeserializeObject<JsonWebKeySet>(identityResult).GetSigningKeys();

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = keys,
                    ValidateAudience = false,
                    ValidateIssuer = true,
                    ValidIssuer = authorityUrl,
                    ValidAudience = validAudience,
                    ValidateLifetime = true,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var tokenNonce = jwtToken.Claims.First(x => x.Type == "nonce").Value;
                return nonce.Equals(tokenNonce);
            }
            catch
            {
                // return false if validation fails
                return false;
            }
        }
    }
}
