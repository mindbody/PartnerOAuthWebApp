using Newtonsoft.Json;
using System.Collections.Generic;

namespace PartnerWebApp.Models
{
    public class ResponseModel
    {
        public string beautifyContent;
        public string Content { get { return BeautifyContent(beautifyContent); } set { beautifyContent = value; } }
        public string Title { get; set; }
        public CategoriesModel Categories { get; set; }
        public SalesModel Sales { get; set; }
        public ClientVisitsModel ClientVisits { get; set; }
        public ClientsModel Clients { get; set; }
        public TransactionsModel Transactions { get; set; }
        public PaymentTypesModel PaymentTypes { get; set; }
        public ClientMembershipsModel ClientMemberships { get; set; }
        public ClientCompleteInfosModel ClientCompleteInfos { get; set; }

        private string BeautifyContent(string jsonData)
        {
            dynamic parsedJson= JsonConvert.DeserializeObject(jsonData);
            return JsonConvert.SerializeObject(parsedJson, Formatting.Indented);
        }
    }

    public class PaginationModel
    {
        public int RequestedLimit { get; set; }
        public int RequestedOffset { get; set; }
        public int PageSize { get; set; }
        public int TotalResults { get; set; }
    }

    #region Categories

    public class CategoriesModel
    {
        public PaginationModel PaginationResponse { get; set; }
        public List<Category> Categories { get; set; } = new List<Category>();
    }

    public class Category
    {
        public int Id { get; set; }
        public string CategoryName { get; set; }
    }

    #endregion

    #region Sales

    public class SalesModel
    {
        public PaginationModel PaginationResponse { get; set; }
        public List<Sale> Sales { get; set; } = new List<Sale>();
    }

    public class Sale
    {
        public int Id { get; set; }
        public string SaleDateTime { get; set; }
        public string ClientId { get; set; }
        public int LocationId { get; set; }
        public int? SalesRepId { get; set; }
        public List<PurchasedItem> PurchasedItems { get; set; } = new List<PurchasedItem>();
        public List<Payment> Payments { get; set; } = new List<Payment>();
    }

    public class PurchasedItem
    {
        public int Id { get; set; }
        public int CategoryId { get; set; }
        public int Quantity { get; set; }
        public decimal? UnitPrice { get; set; }
        public decimal? DiscountPercent { get; set; }
        public decimal? TaxAmount { get; set; }
        public decimal? TotalAmount { get; set; }
        public bool Returned { get; set; }
    }

    public class Payment
    {
        public int Id { get; set; }
        public string Type { get; set; }
        public int? TransactionId { get; set; }
    }

    #endregion

    #region Client Visits

    public class ClientVisitsModel
    {
        public PaginationModel PaginationResponse { get; set; }
        public List<ClientVisit> ClientVisits { get; set; } = new List<ClientVisit>();
    }

    public class ClientVisit
    {
        public int Id { get; set; }
        public int AppointmentId { get; set; }
        public string AppointmentStatus { get; set; }
        public int ClassId { get; set; }
        public string ClientId { get; set; }
        public string StartDateTime { get; set; }
        public string EndDateTime { get; set; }
        public int SiteId { get; set; }
        public int LocationId { get; set; }
    }

    #endregion

    #region Clients

    public class ClientsModel
    {
        public PaginationModel PaginationResponse { get; set; }
        public List<Client> Clients { get; set; } = new List<Client>();
    }

    public class Client
    {
        public string Id { get; set; }
        public string UniqueId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public decimal AccountBalance { get; set; }
        public string Email { get; set; }
        public string City { get; set; }
        public string PostalCode { get; set; }
        public bool Active { get; set; }
        public string Status { get; set; }
    }

    #endregion

    #region Transactions

    public class TransactionsModel
    {
        public PaginationModel PaginationResponse { get; set; }
        public List<Transaction> Transactions { get; set; } = new List<Transaction>();
    }

    public class Transaction
    {
        public int TransactionId { get; set; }
        public int? SaleId { get; set; }
        public string ClientId { get; set; }
        public decimal? Amount { get; set; }
        public string Status { get; set; }
        public string TransactionTime { get; set; }
        public int LocationId { get; set; }
    }

    #endregion

    #region Payment Types

    public class PaymentTypesModel
    {
        public List<PaymentType> PaymentTypes { get; set; } = new List<PaymentType>();
    }

    public class PaymentType
    {
        public int Id { get; set; }
        public string PaymentTypeName { get; set; }
        public bool Active { get; set; }
        public decimal? Fee { get; set; }
    }

    #endregion

    #region Client Memberships

    public class ClientMembershipsModel
    {
        public PaginationModel PaginationResponse { get; set; }
        public List<ClientMembership> ClientMemberships { get; set; } = new List<ClientMembership>();
    }

    public class ClientMembership
    {
        public int MembershipId { get; set; }
        public string ActiveDate { get; set; }
        public int Count { get; set; }
        public string ExpirationDate { get; set; }
        public string PaymentDate { get; set; }
        public string Name { get; set; }
        public string SiteId { get; set; }
        public Program Program { get; set; } = new Program();
    }

    public class Program
    {
        public string Name { get; set; }
        public string ScheduleType { get; set; }
    }

    #endregion

    #region Client Complete Info

    public class ClientCompleteInfosModel
    {
        public Client Client { get; set; }
    }

    #endregion
}
