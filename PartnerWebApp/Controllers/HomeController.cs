using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using PartnerWebApp.Models;
using RestSharp;

namespace PartnerWebApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly string authErrorMessage = "You are not authorized to use this page.";
        private readonly string clientId = "100000001";

        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Dashboard()
        {
            return View();
        }

        public IActionResult LoginForm()
        {
            var studioId = "";
            Request.Cookies.TryGetValue("StudioId", out studioId);
            if (string.IsNullOrWhiteSpace(studioId))
            {
                return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
            }

            ViewData["StudioId"] = studioId;

            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult MindbodyLogin()
        {
            var mindbodyAuth = _configuration.GetSection("Authentication:Mindbody");

            var studioId = "";
            Request.Cookies.TryGetValue("StudioId", out studioId);

            if (string.IsNullOrWhiteSpace(studioId))
            {
                return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
            }

            var authUrl = $"{mindbodyAuth["AuthorizationEndpoint"]}?response_mode={mindbodyAuth["ResponceMode"]}" +
                        $"&client_id={mindbodyAuth["ClientId"]}&redirect_uri={mindbodyAuth["RedirectUrl"]}" +
                        $"&scope={mindbodyAuth["Scopes"]}&response_type={mindbodyAuth["ResponceType"]}" +
                        $"&nonce={mindbodyAuth["Nonce"]}&subscriberId={studioId}";

            return Redirect(authUrl);
        }

        [Route("signin-mindbody")]
        public IActionResult SigninMindbody()
        {
            StringValues code;
            Request.Form.TryGetValue("code", out code);

            if (string.IsNullOrWhiteSpace(code))
            {
                return View("Dashboard");
            }

            var mindbodyAuth = _configuration.GetSection("Authentication:Mindbody");

            RestClient client = new RestClient(mindbodyAuth["TokenEndpoint"]);
            RestRequest req = new RestRequest(Method.POST);
            req.AddHeader("accept", "application/json");
            req.AddHeader("Content-Type", "application/x-www-form-urlencoded");

            req.AddParameter("client_secret", mindbodyAuth["ClientSecret"]);
            req.AddParameter("client_id", mindbodyAuth["ClientId"]);
            req.AddParameter("scope", mindbodyAuth["Scopes"]);
            req.AddParameter("grant_type", mindbodyAuth["GrantType"]);
            req.AddParameter("redirect_uri", mindbodyAuth["RedirectUrl"]);
            req.AddParameter("subscriberId", mindbodyAuth["SubscriberId"]);
            req.AddParameter("code", code);

            var mindbodyResponse = client.Execute(req);

            if (mindbodyResponse.IsSuccessful)
            {
                var authModel = JsonConvert.DeserializeObject<AuthViewModel>(mindbodyResponse.Content);

                Response.Cookies.Append("AccessToken", authModel.access_token, new CookieOptions()
                {
                    Expires = DateTime.UtcNow.AddSeconds(authModel.expires_in)
                });
                Response.Cookies.Append("RefreshToken", authModel.refresh_token, new CookieOptions()
                {
                    Expires = DateTime.UtcNow.AddSeconds(authModel.expires_in)
                });

                return View("Dashboard", authModel);
            }

            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        [HttpPost]
        public IActionResult GetActivationData(ActivationDataModel activationData)
        {
            if (!ModelState.IsValid)
            {
                return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
            }

            var mindbodyResponse = GetRestResponse("/site/activationcode", "", activationData.StudioId, activationData.ApiKey, false);

            if (mindbodyResponse.IsSuccessful)
            {
                var activationDataModel = JsonConvert.DeserializeObject<ActivationDataModel>(mindbodyResponse.Content);

                Response.Cookies.Append("StudioId", activationData.StudioId, new CookieOptions()
                {
                    Expires = DateTime.UtcNow.AddSeconds(3600)
                });

                Response.Cookies.Append("APIKey", activationData.ApiKey, new CookieOptions()
                {
                    Expires = DateTime.UtcNow.AddSeconds(3600)
                });

                return View("Index", activationDataModel);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        private IRestResponse GetRestResponse(string url, string accessToken, string studioId, string apiKey, bool isTokenRequired)
        {
            var publicApiAuth = _configuration.GetSection("PublicApi");

            RestClient client = new RestClient(publicApiAuth["ApiUrl"] + url);
            RestRequest req = new RestRequest(Method.GET);
            req.AddHeader("accept", "application/json");
            req.AddHeader("Content-Type", "application/json");
            req.AddHeader("siteId", studioId);
            if (isTokenRequired)
            {
                req.AddHeader("Authorization", $"Bearer {accessToken}");
            }
            req.AddHeader("API-Key", apiKey);

            return client.Execute(req);
        }

        private ErrorViewModel ValidateRequest(string accessToken, string studioId, string apiKey)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return new ErrorViewModel() { ErrorMessage = authErrorMessage };
            }

            if (string.IsNullOrWhiteSpace(studioId) || string.IsNullOrWhiteSpace(apiKey))
            {
                return new ErrorViewModel() { ErrorMessage = authErrorMessage };
            }

            return null;
        }

        #region Public API Endpoints

        public IActionResult GetActiveClientsMemberships()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse($"/client/activeclientmemberships?ClientId={clientId}", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<ClientMembershipsModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET ActiveClientsMemberships", ClientMemberships = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult GetClientCompleteInfo()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse($"/client/clientcompleteinfo?ClientId={clientId}", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<ClientCompleteInfosModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET ClientCompleteInfo", ClientCompleteInfos = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }


        public IActionResult GetSales()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse("/sale/sales?StartSaleDateTime=2021-07-17", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<SalesModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET Sales", Sales = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult GetClientVisits()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse($"/client/clientvisits?ClientId={clientId}&StartDate=2021-01-17", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<ClientVisitsModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET ClientVisits", ClientVisits = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult GetClients()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse("/client/clients", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<ClientsModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET Clients", Clients = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult GetCategories()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse("/site/categories", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<CategoriesModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET Categories", Categories = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult GetTransactions()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse("/sale/transactions?TransactionStartDateTime=2021-07-07", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<TransactionsModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET Transactions", Transactions = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        public IActionResult GetPaymentTypes()
        {
            var studioId = ""; var accessToken = ""; var apiKey = "";

            Request.Cookies.TryGetValue("AccessToken", out accessToken);
            Request.Cookies.TryGetValue("StudioId", out studioId);
            Request.Cookies.TryGetValue("APIKey", out apiKey);

            var errorModel = ValidateRequest(accessToken, studioId, apiKey);

            if (errorModel != null)
            {
                return View("Error", errorModel);
            }

            var mindbodyResponse = GetRestResponse("/site/paymenttypes", accessToken, studioId, apiKey, true);

            if (mindbodyResponse.IsSuccessful)
            {
                var contentModel = JsonConvert.DeserializeObject<PaymentTypesModel>(mindbodyResponse.Content);
                var model = new ResponseModel() { Content = mindbodyResponse.Content, Title = "GET PaymentTypes", PaymentTypes = contentModel };
                return View("GetData", model);
            }
            return View("Error", new ErrorViewModel { ErrorMessage = authErrorMessage });
        }

        #endregion
    }
}
