using System.Net;
using System.Net.Mail;
using System.Text;

namespace JwtIdentity.Services;

public class MailService
{
    public string SendVerification(string from, string password, string to, string verificationLink)
    {
        var otp = (OtpRandom.NextInt() % 1000000).ToString("000000");

        using (MailMessage mail = new MailMessage())
        {
            mail.From = new MailAddress(from);
            
            mail.To.Add(to);
            
            mail.Subject = "OTP verification";
            
            mail.Body = $"<h3>Please use the following One Time Password (OTP) to register: <code>{otp}</code>. Do not share this OTP with anyone.</h3><br/><div><h3>Thank you!</h3></div>";
            
            mail.IsBodyHtml = true;

            mail.BodyEncoding = Encoding.UTF8;

            mail.DeliveryNotificationOptions = DeliveryNotificationOptions.OnFailure;

            using (SmtpClient client = new SmtpClient("smtp.gmail.com", 587))
            {
                client.EnableSsl = true;

                client.UseDefaultCredentials = false;

                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                
                client.Credentials = new NetworkCredential(from, password);
                
                client.Send(mail);
            }
        }

        return otp;
    }
}
