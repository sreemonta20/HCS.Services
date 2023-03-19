using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace HCS.EmailService
{
    /// <summary>
    /// It defines send email related methods and  <see cref="EmailSender"/> implements these methods.
    /// </summary>
    public interface IEmailSender
    {
        void SendEmail(Message message);
        Task SendEmailAsync(Message message);
    }
}
