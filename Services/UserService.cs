using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NET_Core_Role_Based_Authorization.Entities;
using NET_Core_Role_Based_Authorization.Helpers;

namespace NET_Core_Role_Based_Authorization.Services
{
    public interface IUserService
    {
        User Authenticate(string username, string password);
        IEnumerable<User> GetAll();
        User GetById(int id);
    }

    public class UserService : IUserService
    {
        private List<User> _users = new List<User>
        {
            new User{ Id = 1, FirstName = "Fatih", LastName = "Güler", Username = "admin", Password = "admin", Role = Role.Admin},
            new User{ Id = 2, FirstName = "Ensar", LastName = "Güler", Username = "user", Password = "user", Role = Role.User}
        };

        private readonly AppSettings _appSettings;
        
        public UserService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }
        public User Authenticate(string username, string password)
        {
            var user = _users.SingleOrDefault(x => x.Username == username && x.Password == password);

            // kullanıcı yoksa null döndür
            if(user == null)
                return null;
            
            // authentication başarılı, jwt token oluştur
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                 {
                     new Claim(ClaimTypes.Name, user.Id.ToString()),
                     new Claim(ClaimTypes.Role, user.Role)
                 }),
                 Expires = DateTime.UtcNow.AddDays(7),
                 SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            user.Token = tokenHandler.WriteToken(token);

            // return öncesinde parola silinmeli
            user.Password = null;
            return user;
        }
        

        public IEnumerable<User> GetAll()
        {
            return _users.Select(x => {
                x.Password = null;
                return x;
            });
        }

        public User GetById(int id)
        {
            var user = _users.FirstOrDefault(x => x.Id == id);

            // kullanıcıların parolalarını gizleyerek döndür
            if(user != null)
                user.Password = null;
            return user;
        }
    }
}