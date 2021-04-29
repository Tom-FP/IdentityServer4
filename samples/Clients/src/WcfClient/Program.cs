using IdentityModel.Client;
using IdentityModel.Constants;
using IdentityModel.Extensions;
using System;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.ServiceModel;
using System.Xml.Linq;
using WcfService;

namespace WcfClient
{
    public static class Constants
    {
        public const string BaseAddress = "https://localhost:5001";

        public const string AuthorizeEndpoint = BaseAddress + "/connect/authorize";
        public const string LogoutEndpoint = BaseAddress + "/connect/endsession";
        public const string TokenEndpoint = BaseAddress + "/connect/token";
        public const string UserInfoEndpoint = BaseAddress + "/connect/userinfo";
        public const string IdentityTokenValidationEndpoint = BaseAddress + "/connect/identitytokenvalidation";
        public const string TokenRevocationEndpoint = BaseAddress + "/connect/revocation";

    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("WCfClient Welcome");

            var jwt = GetJwt();
            Console.WriteLine("Token created: " + jwt);

            var xmlToken = WrapJwt(jwt);

            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            binding.HostNameComparisonMode = HostNameComparisonMode.Exact;
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;

            var factory = new ChannelFactory<IService>(
                binding,
                new EndpointAddress("https://localhost:44335/token"));

            var channel = factory.CreateChannelWithIssuedToken(xmlToken);
            
            Console.WriteLine(channel.Ping());

            Console.WriteLine("Done!");
        }

        static GenericXmlSecurityToken WrapJwt(string jwt)
        {
            var subject = new ClaimsIdentity("saml");
            subject.AddClaim(new Claim("jwt", jwt));

            var descriptor = new SecurityTokenDescriptor
            {
                TokenType = TokenTypes.Saml2TokenProfile11,
                TokenIssuerName = "urn:wrappedjwt",
                Subject = subject
            };

            var handler = new Saml2SecurityTokenHandler();
            var token = handler.CreateToken(descriptor);

            var xmlToken = new GenericXmlSecurityToken(
                XElement.Parse(token.ToTokenXmlString()).ToXmlElement(),
                null,
                DateTime.Now,
                DateTime.Now.AddHours(1),
                null,
                null,
                null);

            return xmlToken;
        }

        static string GetJwt()
        {
            var a = Constants.TokenEndpoint;
            var oauth2Client = new TokenClient(
                Constants.TokenEndpoint,
                "client", //"ro.client",
                "secret");

            var tokenResponse =
                //oauth2Client.RequestResourceOwnerPasswordAsync("bob", "bob", "write").Result;
                oauth2Client.RequestResourceOwnerPasswordAsync("bob", "bob", "resource2.scope1").Result;

            if (tokenResponse.IsHttpError)
            {
                Console.Error.WriteLine("HTTP Statuscode: " + tokenResponse.HttpErrorStatusCode );
                Console.Error.WriteLine(tokenResponse.HttpErrorReason);
            }
            if (tokenResponse.IsError)
            {
                Console.Error.WriteLine(tokenResponse.Error);
                if (tokenResponse.Json != null) Console.Error.WriteLine(tokenResponse.Json.ToString());
            }

            return tokenResponse.AccessToken;
        }
    }
}