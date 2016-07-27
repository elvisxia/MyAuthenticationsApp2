using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Facebook;
using Windows.Security.Authentication.Web;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Windows.Security.ExchangeActiveSyncProvisioning;
using Windows.ApplicationModel.Activation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace MyAuthenticationsApp.Pages
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class FacebookAuthentication : Page, IWebAuthenticationContinuable
    {
       
        bool IsPhone
        { get
            {
                return (bool)Application.Current.Resources["isphone"];
            }
        }
        String AccessToken { get; set; }
        DateTime TokenExpiry { get; set; }
        public FacebookAuthentication()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = NavigationCacheMode.Required;
        }

        private void btnLogin_Click(object sender, RoutedEventArgs e)
        {
            Login();
        }

        private async Task Login()
        {
            //face book app id
            String clientId = "1792144857688910";
            //face book permission
            String scope = "public_profile, email";
            var redirectUri = WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString();
            var fb = new FacebookClient();
            Uri loginUrl = fb.GetLoginUrl(new
            {
                client_id = clientId,
                redirect_uri = redirectUri,
                response_type = "token",
                scope = scope
            });
            Uri startUri = loginUrl;
            Uri endUri = new Uri(redirectUri, UriKind.Absolute);

            if (!IsPhone)
            {
                WebAuthenticationResult result = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri, endUri);
                await ParseAuthenticationResult(result);
            }
            else
            {
                WebAuthenticationBroker.AuthenticateAndContinue(startUri, endUri, null, WebAuthenticationOptions.None);
            }

        }


        public async Task ParseAuthenticationResult(WebAuthenticationResult result)
        {
            switch (result.ResponseStatus)
            {
                case WebAuthenticationStatus.ErrorHttp:
                    Debug.WriteLine("Error");
                    break;
                case WebAuthenticationStatus.Success:
                    var pattern = string.Format("{0}#access_token={1}&expires_in={2}", WebAuthenticationBroker.GetCurrentApplicationCallbackUri(), "(?<access_token>.+)", "(?<expires_in>.+)");
                    var match = Regex.Match(result.ResponseData, pattern);

                    var access_token = match.Groups["access_token"];
                    var expires_in = match.Groups["expires_in"];

                    AccessToken = access_token.Value;
                    TokenExpiry = DateTime.Now.AddSeconds(double.Parse(expires_in.Value));
                    tbOutput.Text = "Got Access Token Successfully";
                    break;
                case WebAuthenticationStatus.UserCancel:
                    Debug.WriteLine("Operation aborted");
                    break;
                default:
                    break;
            }
        }

        private async void btnGetInfo_Click(object sender, RoutedEventArgs e)
        {
            FacebookClient client = new FacebookClient(AccessToken);
            dynamic user = await client.GetTaskAsync("me");
            tbOutput.Text = user.name;
        }

        private async void btnLogout_Click(object sender, RoutedEventArgs e)
        {
            String clientId = "1792144857688910";
            //face book permission
            String scope = "public_profile, email";
            var redirectUri = WebAuthenticationBroker.GetCurrentApplicationCallbackUri().ToString();
            var fb = new FacebookClient();
            var loginUrl = fb.GetLogoutUrl(new
            {
                client_id = clientId,
                redirect_uri = redirectUri,
                response_type = "token",
                scope = scope
            });
            var logOutUrl = fb.GetLogoutUrl(new
            {
                next = loginUrl,
                access_token = AccessToken
            });
            
            Uri startUri = logOutUrl;
            Uri endUri = new Uri(redirectUri, UriKind.Absolute);

            if (!IsPhone)
            {
                //WebAuthenticationBroker.AuthenticateAndContinue(startUri);
                var result = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri);
                //await WebAuthenticationBroker.AuthenticateSilentlyAsync(startUri,WebAuthenticationOptions.SilentMode);
                await ParseAuthenticationResult(result);
            }
            else
            {
                //WebAuthenticationBroker.AuthenticateAndContinue(logOutUrl);
                //await ParseAuthenticationResult(result);
                WebAuthenticationBroker.AuthenticateAndContinue(startUri);
                AccessToken = null;
            }
        }

        public async void ContinueWebAuthentication(WebAuthenticationBrokerContinuationEventArgs args)
        {
            await ParseAuthenticationResult(args.WebAuthenticationResult);
        }
    }
}
