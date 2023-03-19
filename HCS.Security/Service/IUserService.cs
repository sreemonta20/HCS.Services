using HCS.Security.Models.Base;
using HCS.Security.Models.Configuration;
using HCS.Security.Models.Request;
using HCS.Security.Models.Response;
using Microsoft.AspNetCore.Identity;

namespace HCS.Security.Service
{
    /// <summary>
    /// It define all the methods for user operations incuding the user login. Where <see cref="UserService"/> implements this methods.
    /// </summary>
    public interface IUserService
    {
        Task<DataResponse> GetUserAsync(string id);
        Task<PageResult<UserInfo>> GetAllUserAsync(PaginationFilter paramRequest);
        Task<DataResponse> AuthenticateUserAsync(LoginRequest request);
        Task<DataResponse> RegisterUserAsync(UserRegisterRequest request);
        Task<DataResponse> DeleteUserAsync(string id);
    }
}
