namespace HCS.Security.Models.Request
{
    /// <summary>
    /// LoginRequest is extension of  <see cref="UserInfo"/>.
    /// </summary>
    public class LoginRequest
    {
        public string? UserName { get; set; }
        public string? Password { get; set; }
    }
}
