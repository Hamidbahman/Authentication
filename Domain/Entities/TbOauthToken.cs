using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication.Domain.Entities;

    [Table("tbOauthToken")]
    public class OauthToken : BaseEntity
    {
        [StringLength(50)]
        public string ClientId { get; private set; }

        [StringLength(50)]
        public string UserName { get; private set; }

        [StringLength(255)]
        public string AccessToken { get; set; }  

        [StringLength(255)]
        public string RefreshToken { get; set; }  

        public short TokenType { get; set; }  

        public OauthToken (){}

        public OauthToken(string clientId, string userName, string accessToken, string refreshToken, short tokenType)
        {
            ClientId = clientId;
            UserName = userName;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            TokenType = tokenType;
        }
    }

