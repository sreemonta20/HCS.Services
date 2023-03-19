using Azure;
using Azure.Core;
using HCS.EmailService;
using HCS.Security.Helper;
using HCS.Security.Models.Base;
using HCS.Security.Models.Configuration;
using HCS.Security.Models.Request;
using HCS.Security.Models.Response;
using HCS.Security.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Serilog;
using System;
using System.Drawing.Printing;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using BCryptNet = BCrypt.Net.BCrypt;

namespace HCS.Security.Service
{
    /// <summary>
    /// includes all the methods for user operation incuding the user login. It implements  <see cref="IUserService"/>.
    /// </summary>
    public class UserService : IUserService
    {
        #region Variable declaration & constructor initialization
        private readonly AppSettings _appSettings;
        public IConfiguration _configuration;
        private readonly HCSSecurityDBContext _context;
        private readonly IEmailSender _emailService;
        public UserService(IConfiguration config, HCSSecurityDBContext context, IOptions<AppSettings> options, IEmailSender emailService)
        {
            _configuration = config;
            _context = context;
            this._appSettings = options.Value;
            _emailService = emailService;
        }
        #endregion

        #region All service methods

        /// <summary>
        /// This service method used to get a specific user details by supplying user id.
        /// </summary>
        /// <param name="id"></param>
        /// <returns>DataResponse</returns>
        public async Task<DataResponse> GetUserAsync(string id)
        {
            var user = await _context.UserInfos.FirstOrDefaultAsync(u => u.Id == new Guid(id));
            if (user != null)
            {
                return new DataResponse { Success = true, Message = ConstantSupplier.GET_USER_SUCCESS, MessageType = Enum.EnumResponseType.Success, ResponseCode = (int)HttpStatusCode.OK, Result = user };
            }
            return new DataResponse { Success = false, Message = ConstantSupplier.GET_USER_FAILED, MessageType = Enum.EnumResponseType.Error, ResponseCode = (int)HttpStatusCode.BadRequest, Result = null };
        }

        /// <summary>
        /// This service method used to get a list users based on the supplied page number and page size.
        /// </summary>
        /// <param name="paramRequest"></param>
        /// <returns>PageResult<![CDATA[<T>]]></returns>
        public async Task<PageResult<UserInfo>> GetAllUserAsync(PaginationFilter paramRequest)
        {
            var count = await _context.UserInfos.CountAsync();
            var Items = await _context.UserInfos.OrderByDescending(x => x.CreatedDate).Skip(((int)paramRequest.PageNumber - 1) * (int)paramRequest.PageSize).Take((int)paramRequest.PageSize).ToListAsync();
            var result = new PageResult<UserInfo>
            {
                Count = count,
                PageIndex = paramRequest.PageNumber >0 ? paramRequest.PageNumber: 1,
                PageSize = 10,
                Items = Items
            };
            return result;


        }

        /// <summary>
        /// This method authenticate user credential. It checks user name and then password. In between the checking, if client attempts consecutive 
        /// 3 failed request then this method will block the any further request for authentication of the user. Where, It update the datetime
        /// of the failed attempts and count of failed attempts. So threshold(appsettings.json) says after 3 failed attempts, user get blocked for the 
        /// next 1 min. This method ensures the unique username for all the user records.
        /// </summary>
        /// <param name="request"></param>
        /// <returns>DataResponse</returns>
        public async Task<DataResponse> AuthenticateUserAsync(LoginRequest request)
        {
            if (request != null)
            {

                var user = await _context.UserInfos.FirstOrDefaultAsync(u => u.UserName == request.UserName);
                if (user != null)
                {
                    if (user.LoginFailedAttemptsCount > Convert.ToInt32(_configuration["AppSettings:MaxNumberOfFailedAttempts"]) 
                        && user.LastLoginAttemptAt.HasValue
                        && DateTime.Now < user.LastLoginAttemptAt.Value.AddMinutes(Convert.ToInt32(_configuration["AppSettings:BlockMinutes"])))
                    {
                        
                        //var message = new Message(new string[] { "sreemonta.bhowmik@gmail.com" }, "Test email async", "This is the content from our async email.", null);
                        //await _emailService.SendEmailAsync(message);
                        return new DataResponse { Success = false, 
                            Message = String.Format(ConstantSupplier.AUTH_FAILED_ATTEMPT, Convert.ToInt32(_configuration["AppSettings:BlockMinutes"])), 
                            MessageType = Enum.EnumResponseType.Error, ResponseCode = (int)HttpStatusCode.BadRequest, Result = null };
                    }
                    
                    bool verified = BCryptNet.Verify(request.Password, user.Password);
                    if (verified)
                    {
                        user.LoginFailedAttemptsCount = 0;
                        user.LastLoginAttemptAt = DateTime.Now;
                        await TrackAndUpdateLoginAttempts(user);
                        JwtSecurityToken token;
                        DateTime expires;
                        var TokenResult = GetToken(user);
                        return new DataResponse { Success = true, Message = ConstantSupplier.AUTH_SUCCESS, MessageType = Enum.EnumResponseType.Success, ResponseCode = (int)HttpStatusCode.OK, Result = TokenResult };
                    }
                    else
                    {
                        user.LastLoginAttemptAt = DateTime.Now; 
                        user.LoginFailedAttemptsCount++;
                        await TrackAndUpdateLoginAttempts(user);

                        return new DataResponse { Success = false, Message = ConstantSupplier.AUTH_INVALID_CREDENTIAL, MessageType = Enum.EnumResponseType.Warning, ResponseCode = (int)HttpStatusCode.BadRequest, Result = null };
                    }


                }
                
                return new DataResponse { Success = false, Message = ConstantSupplier.AUTH_INVALID_CREDENTIAL, MessageType = Enum.EnumResponseType.Warning, ResponseCode = (int)HttpStatusCode.BadRequest, Result = null };

            }
            return new DataResponse { Success = false, Message = ConstantSupplier.AUTH_FAILED, MessageType = Enum.EnumResponseType.Error, ResponseCode = (int)HttpStatusCode.BadRequest, Result = null };
        }


        /// <summary>
        /// This method saves and update the user details. It tracks the action name (save or update). Based on this it send the request for saving or
        /// updating the user credential. In Update method, no user password can be updated by Admin due to data protection policy in general. Password 
        /// is being encrypted using the Bcrypt during the registration.
        /// </summary>
        /// <param name="request"></param>
        /// <returns>DataResponse</returns>
        public async Task<DataResponse> RegisterUserAsync(UserRegisterRequest request)
        {
            if (request != null)
            {
                
                switch (request.ActionName)
                {
                    case ConstantSupplier.SAVE_KEY:
                        string saltKey = BCryptNet.GenerateSalt(13);
                        UserInfo oSaveUserInfo = new()
                        {
                            Id = Guid.NewGuid(),
                            FullName = request.FullName,
                            UserName = request.UserName,
                            Password = BCryptNet.HashPassword(request.Password, saltKey),
                            //Password = BCryptNet.HashPassword(request.Password),
                            SaltKey = saltKey,
                            Email = request.Email,
                            UserRole = request.UserRole,
                            CreatedBy = Convert.ToString(_context.UserInfos.FirstOrDefault(s => s.UserRole.Equals(ConstantSupplier.ADMIN)).Id),
                            CreatedDate = DateTime.UtcNow
                        };

                        var user = await _context.UserInfos.FirstOrDefaultAsync(u => u.UserName == request.UserName);
                        if (user != null && !String.IsNullOrEmpty(Convert.ToString(user.Id)))
                        {
                            return new DataResponse { Success = false, Message = ConstantSupplier.EXIST_USER, MessageType = Enum.EnumResponseType.Warning, ResponseCode = (int)HttpStatusCode.BadRequest, Result = request };
                        }

                        await _context.UserInfos.AddAsync(oSaveUserInfo);
                        await _context.SaveChangesAsync();

                        request.Id = Convert.ToString(oSaveUserInfo.Id);
                        return new DataResponse { Success = true, Message = ConstantSupplier.REG_USER_SAVE_SUCCESS, MessageType = Enum.EnumResponseType.Success, ResponseCode = (int)HttpStatusCode.OK, Result = request };

                    case ConstantSupplier.UPDATE_KEY:
                        
                        var oldUser = await _context.UserInfos.FirstOrDefaultAsync(u => u.UserName == (request.UserName));

                        if ((oldUser != null) && (oldUser.Id != new Guid(request.Id)))
                        {
                            return new DataResponse { Success = false, Message = ConstantSupplier.EXIST_USER, MessageType = Enum.EnumResponseType.Warning, ResponseCode = (int)HttpStatusCode.BadRequest, Result = request };
                        }


                        var dbUserInfo = _context.UserInfos.FirstOrDefault(s => s.Id.Equals(new Guid(request.Id)));
                        dbUserInfo.FullName = request.FullName;
                        dbUserInfo.UserName = request.UserName;
                        dbUserInfo.Email = request.Email;
                        dbUserInfo.UserRole = request.UserRole;
                        dbUserInfo.UpdatedBy = Convert.ToString(_context.UserInfos.FirstOrDefault(s => s.UserRole.Equals(ConstantSupplier.ADMIN)).Id);
                        dbUserInfo.UpdatedDate = DateTime.UtcNow;
                        var isFullNameModified = _context.Entry(dbUserInfo).Property("FullName").IsModified;
                        var isUserNameModified = _context.Entry(dbUserInfo).Property("UserName").IsModified;
                        var isEmailModified = _context.Entry(dbUserInfo).Property("Email").IsModified;
                        var isUserRoleModified = _context.Entry(dbUserInfo).Property("UserRole").IsModified;
                        var isUpdatedByModified = _context.Entry(dbUserInfo).Property("UpdatedBy").IsModified;
                        var isUpdatedDateModified = _context.Entry(dbUserInfo).Property("UpdatedDate").IsModified;
                        _context.SaveChanges();

                        return new DataResponse { Success = true, Message = ConstantSupplier.REG_USER_UPDATE_SUCCESS, MessageType = Enum.EnumResponseType.Success, ResponseCode = (int)HttpStatusCode.OK, Result = request };

                }

            }

            return new DataResponse { Success = false, Message = ConstantSupplier.REG_USER_SAVE_FAILED, MessageType = Enum.EnumResponseType.Error, ResponseCode = (int)HttpStatusCode.BadRequest, Result = null };
        }

        /// <summary>
        /// This method simply delete the user details from the database.
        /// </summary>
        /// <param name="id"></param>
        /// <returns>DataResponse</returns>
        public async Task<DataResponse> DeleteUserAsync(string id)
        {
            UserInfo? oUserInfo = await _context.UserInfos.FindAsync(new Guid(id));

            if (oUserInfo != null)
            {
                _context.UserInfos.Remove(oUserInfo);
                await _context.SaveChangesAsync();
                return new DataResponse { Success = true, Message = ConstantSupplier.DELETE_SUCCESS, MessageType = Enum.EnumResponseType.Success, ResponseCode = (int)HttpStatusCode.OK, Result = oUserInfo };
            }
            return new DataResponse { Success = false, Message = ConstantSupplier.DELETE_FAILED, MessageType = Enum.EnumResponseType.Error, ResponseCode = (int)HttpStatusCode.BadRequest, Result = id };
        }

        /// <summary>
        /// This private method is being used for generating token after user credential found ok.
        /// </summary>
        /// <param name="user"></param>
        /// <returns>Token</returns>
        private Token? GetToken(UserInfo user)
        {
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["AppSettings:JWT:Key"]);

            //DateTime expiryTime = DateTime.UtcNow.AddMinutes(10);
            DateTime expiryTime = DateTime.Now.AddSeconds(Convert.ToDouble(_configuration["AppSettings:AccessTokenExpireTime"]));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                        new Claim(JwtRegisteredClaimNames.Sub, _configuration["AppSettings:JWT:Subject"]),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                        new Claim("UserId", user.Id.ToString()),
                        new Claim("FullName", user.FullName),
                        new Claim("UserName", user.UserName),
                        new Claim("Email", user.Email)
                }),
                Expires = expiryTime,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
           
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            if( tokenString != null)
            {
                return new Token()
                {
                    access_token = tokenString,
                    expires_in = Convert.ToInt32(Convert.ToDouble(_configuration["AppSettings:AccessTokenExpireTime"])),
                    token_type = ConstantSupplier.AUTHORIZATION_TOKEN_TYPE,
                    error = string.Empty,
                    error_description = string.Empty,
                    user = new User() { Id= Convert.ToString(user.Id), FullName = user.UserName, UserName = user.UserName, Email = user.Email, UserRole= user.UserRole }
                    
                };
            }
            return null;


        }

        /// <summary>
        /// It update the "LastLoginAttemptAt" and "LoginFailedAttemptsCount" database table columns.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task TrackAndUpdateLoginAttempts(UserInfo? user)
        {
            var dbUserInfo = await _context.UserInfos.FirstOrDefaultAsync(u => u.Id == user.Id);
            dbUserInfo.LastLoginAttemptAt = user.LastLoginAttemptAt;
            dbUserInfo.LoginFailedAttemptsCount = user.LoginFailedAttemptsCount;
            var isLastLoginAttemptAtModified = _context.Entry(dbUserInfo).Property("LastLoginAttemptAt").IsModified;
            var isLoginFailedAttemptsCountModified = _context.Entry(dbUserInfo).Property("LoginFailedAttemptsCount").IsModified;
            _context.SaveChanges();
        }
        #endregion
    }
}
