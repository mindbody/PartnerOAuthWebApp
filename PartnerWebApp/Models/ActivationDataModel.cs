using System.ComponentModel.DataAnnotations;

namespace PartnerWebApp.Models
{
    public class ActivationDataModel
    {
        public string ActivationCode { get; set; }
        public string ActivationLink { get; set; }
        [Required]
        public string StudioId { get; set; }
        [Required]
        public string ApiKey { get; set; }
    }
}
