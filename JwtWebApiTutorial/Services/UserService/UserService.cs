using System.Security.Claims;

namespace JwtWebApiTutorial.Services.UserService
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpAccessor;

        public UserService(IHttpContextAccessor httpAccessor)
        {
            _httpAccessor = httpAccessor;
        }

        public string GetUserName()
        {
            var userName = string.Empty;

            if (_httpAccessor.HttpContext != null)
            {
                userName = _httpAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }

            return userName;
        }
    }
}
