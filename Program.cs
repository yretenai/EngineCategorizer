using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using SteamKit2;

namespace EngineCategorizer
{
    public class Program
    {
        private string SteamDirectory;
        private string SteamUsername;
        private string SteamPassword;

        private SteamClient Client;
        private SteamUser User;
        private bool Running;

        private int Timeout = 5;

        private string SteamAuthCode;
        private string Steam2FACode;

        private bool SteamShouldRemember;

        private static void Main()
        {
            var unused = new Program();
        }

        public Program()
        {
            while (string.IsNullOrWhiteSpace(SteamDirectory))
            {
                Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                    "Steam Directory: ");
                SteamDirectory = Logger.ReadLine(Console.Out, false);
            }

            Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty, "Username: ");
            SteamUsername = Logger.ReadLine(Console.Out, false);
            if (!string.IsNullOrWhiteSpace(SteamUsername))
            {
                if (!File.Exists("login.key"))
                {
                    while (string.IsNullOrWhiteSpace(SteamPassword))
                    {
                        Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                            "Password: ");
                        SteamPassword = Logger.ReadLine(Console.Out, true);
                    }

                    Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                        "Remember Password (Y/N): ");
                    SteamShouldRemember = Logger.ReadLine(Console.Out, false).ToLowerInvariant().StartsWith("y");
                }
                else
                {
                    SteamShouldRemember = true;
                }
            }

            Client = new SteamClient();
            var manager = new CallbackManager(Client);
            User = Client.GetHandler<SteamUser>();

            manager.Subscribe<SteamClient.ConnectedCallback>(OnConnected);
            manager.Subscribe<SteamClient.DisconnectedCallback>(OnDisconnected);
            manager.Subscribe<SteamUser.LoggedOnCallback>(OnLoggedOn);
            manager.Subscribe<SteamUser.LoggedOffCallback>(OnLoggedOff);
            manager.Subscribe<SteamUser.UpdateMachineAuthCallback>(OnMachineAuth);
            manager.Subscribe<SteamUser.LoginKeyCallback>(OnLoginKey);

            Running = true;

            Logger.Log24Bit(ConsoleSwatch.XTermColor.Aquamarine, true, Console.Out, string.Empty,
                "Connecting to Steam...");

            Client.Connect();

            while (Running)
            {
                manager.RunWaitCallbacks(TimeSpan.FromSeconds(1));
            }
        }

        private void OnLoginKey(SteamUser.LoginKeyCallback obj)
        {
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Pink, false, Console.Out, string.Empty,
                "Updating login key file... ");
            if (File.Exists("login.key"))
            {
                File.Delete("login.key");
            }

            File.WriteAllText("login.key", obj.LoginKey);
            User.AcceptNewLoginKey(obj);
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Pink, true, Console.Out, string.Empty, "Done!");
        }

        private void OnMachineAuth(SteamUser.UpdateMachineAuthCallback obj)
        {
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Pink, false, Console.Out, string.Empty,
                "Updating sentry file... ");

            int fileSize;
            byte[] sentryHash;
            using (var fs = File.Open("sentry.bin", FileMode.OpenOrCreate, FileAccess.ReadWrite))
            {
                fs.Seek(obj.Offset, SeekOrigin.Begin);
                fs.Write(obj.Data, 0, obj.BytesToWrite);
                fileSize = (int) fs.Length;

                fs.Seek(0, SeekOrigin.Begin);
                using (var sha = SHA1.Create())
                {
                    sentryHash = sha.ComputeHash(fs);
                }
            }

            // inform the steam servers that we're accepting this sentry file
            User.SendMachineAuthResponse(new SteamUser.MachineAuthDetails
            {
                JobID = obj.JobID,
                FileName = obj.FileName,
                BytesWritten = obj.BytesToWrite,
                FileSize = fileSize,
                Offset = obj.Offset,
                Result = EResult.OK,
                LastError = 0,
                OneTimePassword = obj.OneTimePassword,
                SentryFileHash = sentryHash
            });

            Logger.Log24Bit(ConsoleSwatch.XTermColor.Pink, true, Console.Out, string.Empty, "Done!");
        }

        private static void OnLoggedOff(SteamUser.LoggedOffCallback obj)
        {
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Red, true, Console.Out, string.Empty,
                $"Logged out of Steam: {obj.Result}");
        }

        private void OnLoggedOn(SteamUser.LoggedOnCallback obj)
        {
            bool isSteamGuard = obj.Result == EResult.AccountLogonDenied;
            bool is2FA = obj.Result == EResult.AccountLoginDeniedNeedTwoFactor;

            if (isSteamGuard || is2FA)
            {
                Timeout = 0;

                Logger.Log24Bit(ConsoleSwatch.XTermColor.Pink, true, Console.Out, string.Empty,
                    "This account is SteamGuard protected!");

                if (is2FA)
                {
                    while (string.IsNullOrWhiteSpace(Steam2FACode))
                    {
                        Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                            "Two Factor Auth Code: ");
                        Steam2FACode = Logger.ReadLine(Console.Out, false);
                    }
                }
                else
                {
                    Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, true, Console.Out, string.Empty,
                        $"Please enter the auth code sent to the email at {obj.EmailDomain}");
                    while (string.IsNullOrWhiteSpace(SteamAuthCode))
                    {
                        Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                            "Auth Code: ");
                        SteamAuthCode = Logger.ReadLine(Console.Out, false);
                    }
                }

                return;
            }

            if (obj.Result != EResult.OK)
            {
                Logger.Log24Bit(ConsoleSwatch.XTermColor.Red, true, Console.Out, string.Empty,
                    $"Unable to logon to Steam: {obj.Result} / {obj.ExtendedResult}");

                Running = false;
                return;
            }

            Logger.Log24Bit(ConsoleSwatch.XTermColor.Green, true, Console.Out, string.Empty, "Successfully logged on!");
        }

        private void OnDisconnected(SteamClient.DisconnectedCallback obj)
        {
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Red, true, Console.Out, string.Empty,
                $"Disconnected from Steam, reconnecting{(Timeout > 0 ? $" in {Timeout} seconds" : string.Empty)}...");

            if (Timeout > 0)
            {
                Thread.Sleep(TimeSpan.FromSeconds(Timeout));
            }

            Timeout = 5;

            Client.Connect();
        }

        private void OnConnected(SteamClient.ConnectedCallback obj)
        {
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Aquamarine, true, Console.Out, string.Empty,
                $"Connected to Steam! Logging in with {(string.IsNullOrWhiteSpace(SteamUsername) ? "anonymous dedicated server user" : $"user {SteamUsername}")}");

            byte[] sentryHash = null;

            if (File.Exists("sentry.bin"))
            {
                sentryHash = CryptoHelper.SHAHash(File.ReadAllBytes("sentry.bin"));
            }

            string loginKey = null;
            if (File.Exists("login.key"))
            {
                loginKey = File.ReadAllText("login.key");
            }

            if (string.IsNullOrWhiteSpace(SteamUsername))
            {
                User.LogOnAnonymous();
            }
            else
            {
                User.LogOn(new SteamUser.LogOnDetails
                {
                    Username = SteamUsername,
                    Password = SteamPassword,
                    AuthCode = SteamAuthCode,
                    TwoFactorCode = Steam2FACode,
                    SentryFileHash = sentryHash,
                    ClientOSType = EOSType.Windows10,
                    ShouldRememberPassword = SteamShouldRemember,
                    LoginKey = loginKey
                });
            }
        }
    }
}
