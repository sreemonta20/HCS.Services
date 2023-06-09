﻿using FluentEmail.Core;
using FluentEmail.Core.Models;
using FluentEmail.Smtp;
using HCS.EmailService.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Web;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Hosting;

namespace HCS.EmailService.Service
{
    public class EmailSender : IEmailService
    {
        private readonly IHostingEnvironment _environment;
        public EmailSender(IHostingEnvironment environment)
        {
            this._environment = environment;
        }
        

        // smtp.mail.yahoo.com	25, 587	TLS
        // smtp.mail.yahoo.com	465	SSL

        //////"EmailConfiguration": {
        //////"From": "sreemonta.bhowmik@yahoo.com",
        //////"Host": "localhost",
        //////"Port": 25,
        //////"Username": "sreemonta.bhowmik",
        //////"Password": "xasutzrityoeggzq"
        //////}
        public async Task<SendResponse> TestSendEmailAsync(EmailConfiguration emailConfig, Message message)
        {
            var sender = new SmtpSender(() => new SmtpClient(host: emailConfig.Host)
            {
                EnableSsl = false,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Port = 25,
            });
            Email.DefaultSender = sender;

            var email = await Email
                .From(emailAddress: emailConfig.From)
                .To(emailAddress: message.To, name: message.Name)
                .Subject(subject: message.Subject)
                .Body(body: message.Body)
                .SendAsync();

            return email;
        }

        public async Task<SendResponse> SendEmailAsync(EmailConfiguration emailConfig, Message message)
        {
            var sender = new SmtpSender(() => new SmtpClient(emailConfig.Host)
            {
                UseDefaultCredentials = false,
                Port = 587,
                Credentials = new NetworkCredential(emailConfig.UserName, emailConfig.Password),
                EnableSsl = true,
            });

            Email.DefaultSender = sender;
            var email = Email
                .From(emailConfig.From, emailConfig.Name)
                .To(message.To, message.Name)
                .Subject(message.Subject)
                .Body(message.Body, true);


            var response = await email.SendAsync();
            return response;
        }

        public string PopulateBody(string path, string userName, string title, string url, string description)
        {
            string body = string.Empty;
            var combinePath = Path.Combine(_environment.ContentRootPath, "EmailTemplates/emailblocknotice.html");
            using (StreamReader reader = new(combinePath))
            {
                body = reader.ReadToEnd();
            }
            //var html = System.IO.File.ReadAllText(@"~/EmailTemplates/emailblocknotice.htm");
            body = body.Replace("{Name}", userName);
            body = body.Replace("{Title}", title);
            body = body.Replace("{Url}", url);
            body = body.Replace("{Description}", description);
            return body;
        }


    }
}
