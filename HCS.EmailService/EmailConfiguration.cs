using System;
using System.Collections.Generic;
using System.Text;

namespace HCS.EmailService
{
    /// <summary>
    /// Email configuration class which is used to track the <see cref="AppSettings"/>'s Email configuration.
    /// </summary>
    public class EmailConfiguration
    {
        public string? From { get; set; }
        public string? SmtpServer { get; set; }
        public int Port { get; set; }
        public string? UserName { get; set; }
        public string? Password { get; set; }
    }
}
