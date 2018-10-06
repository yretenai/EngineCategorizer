using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Newtonsoft.Json;
using SteamKit2;

namespace EngineCategorizer
{
    public class Program
    {
        private string SteamDirectory;
        private string TagPrefix;
        private string SteamUsername;
        private string SteamPassword;

        private SteamClient Client;
        private SteamUser User;
        private SteamApps Apps;
        private bool Running;

        private int Timeout = 5;

        private string SteamAuthCode;
        private string Steam2FACode;

        private bool SteamShouldRemember;

        private static void Main()
        {
            var unused = new Program();
        }

        [SuppressMessage("ReSharper", "StringLiteralTypo")]
        public Dictionary<string, Func<List<string>, float>> EngineTest =
            new Dictionary<string, Func<List<string>, float>>
            {
                {
                    "Unity", (fileList) => { return fileList.Any(x => x.Contains("UnityEngine")) ? 1.0f : 0.0f; }
                },
                {
                    "Source", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        var amount = 0.0f;
                        if (fileNames.Contains("hl2.exe")) amount += 0.6f;
                        if (fileNames.Contains("engine.dll")) amount += 0.4f;
                        if (fileNames.Contains("materialsystem.dll")) amount += 0.1f;
                        if (fileNames.Contains("vphysics.dll")) amount += 0.1f;
                        return amount;
                    }
                },
                {
                    "Source 2", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        var amount = 0.0f;
                        if (fileNames.Contains("engine2.dll")) amount += 0.35f;
                        if (fileNames.Contains("vconsole.exe")) amount += 0.35f;
                        if (fileNames.Contains("materialsystem2.dll")) amount += 0.2f;
                        if (fileNames.Contains("vphysics2.dll")) amount += 0.1f;
                        return amount;
                    }
                },
                {
                    "Unreal Engine 4", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        if (fileNames.Any(x => x.StartsWith("ue4prereqsetup"))) return 1.0f;
                        var amount = 0.0f;
                        if (fileList.Any(x => x.Contains("CookedPC"))) amount += 0.3f;
                        if (fileNames.Contains("crashreportclient.exe")) amount += 0.1f;
                        return amount;
                    }
                },
                {
                    "Unreal Engine 2/3", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        if (fileNames.Any(x => x.StartsWith("ue3redist"))) return 1.0f;
                        var amount = 0.0f;
                        if (fileList.Any(x => x.Contains("CookedPC"))) amount += 0.5f;
                        if (fileNames.Contains("crashreportclient.exe")) amount += 0.1f;
                        return amount;
                    }
                },
                {
                    "RPG Maker (HTML)", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        var amount = 0.0f;
                        if (fileNames.Contains("nw.pak")) amount += 0.1f;
                        if (fileNames.Contains("credits.html")) amount += 0.1f;
                        if (fileNames.Contains("main.js")) amount += 0.1f;
                        if (fileNames.Contains("plugins.js")) amount += 0.1f;
                        if (fileNames.Contains("rpg_core.js")) amount += 0.1f;
                        if (fileNames.Contains("rpg_managers.js")) amount += 0.1f;
                        if (fileNames.Contains("rpg_objects.js")) amount += 0.1f;
                        if (fileNames.Contains("rpg_scenes.js")) amount += 0.1f;
                        if (fileNames.Contains("rpg_sprites.js")) amount += 0.1f;
                        if (fileNames.Contains("rpg_windows.js")) amount += 0.1f;
                        return amount;
                    }
                },
                {
                    "OGRE", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        return fileNames.Contains("ogremain.dll") ? 1.0f : 0.0f;
                    }
                },
                {
                    "Panda3D", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        var amount = 0.0f;
                        if (fileList.Any(x => x.Contains("panda3d"))) amount += 0.05f;
                        if (fileNames.Contains("p3dpython.exe")) amount += 0.10f;
                        if (fileNames.Contains("p3dpythonw.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpanda.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandabullet.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandadx9.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandadx11.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandaegg.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandaexpress.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandagl.exe")) amount += 0.10f;
                        if (fileNames.Contains("libpandasteam.exe")) amount += 0.10f;
                        return amount;
                    }
                },
                {
                    "Frostbyte", (fileList) =>
                    {
                        var fileNames = fileList.Select(x => Path.GetFileName(x).ToLower()).ToList();
                        return (float) fileNames.Count(x => x.EndsWith(".fbrb")) / fileNames.Count;
                    }
                },
            };

        public static string GetSteamDirectory()
        {
            try
            {
                return (string)Registry.GetValue(
                    RegistryPathToSteam,
                    "InstallPath",
                    null);
            }
            catch
            {
                // ignored
            }
            return null;
        }

        private static string RegistryPathToSteam => Environment.Is64BitProcess ? @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Valve\Steam" : @"HKEY_LOCAL_MACHINE\Software\Valve\Steam";

        public Program()
        {
            SteamDirectory = GetSteamDirectory();
            
            if(!string.IsNullOrWhiteSpace(SteamDirectory) &&
               Directory.Exists(Path.Combine(SteamDirectory, "userdata")))
            {
                Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                    "Auto detected Steam Directory: ");
                Logger.Log24Bit(ConsoleSwatch.XTermColor.White, true, Console.Out, string.Empty,
                    SteamDirectory);
            }
            else
            {
                while (string.IsNullOrWhiteSpace(SteamDirectory) ||
                       !Directory.Exists(Path.Combine(SteamDirectory, "userdata")))
                {
                    Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                        "Steam Directory: ");
                    SteamDirectory = Logger.ReadLine(Console.Out, false);
                }
            }

            while (string.IsNullOrWhiteSpace(TagPrefix))
            {
                Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                    "Tag Prefix: ");
                TagPrefix = Logger.ReadLine(Console.Out, false);
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
            Apps = Client.GetHandler<SteamApps>();

            manager.Subscribe<SteamClient.ConnectedCallback>(OnConnected);
            manager.Subscribe<SteamClient.DisconnectedCallback>(OnDisconnected);
            manager.Subscribe<SteamUser.LoggedOnCallback>(OnLoggedOn);
            manager.Subscribe<SteamUser.LoggedOffCallback>(OnLoggedOff);
            manager.Subscribe<SteamUser.UpdateMachineAuthCallback>(OnMachineAuth);
            manager.Subscribe<SteamUser.LoginKeyCallback>(OnLoginKey);
            manager.Subscribe<SteamApps.LicenseListCallback>(OnLicenseList);

            Running = true;

            Logger.Log24Bit(ConsoleSwatch.XTermColor.Aquamarine, true, Console.Out, string.Empty,
                "Connecting to Steam...");

            Client.Connect();

            while (Running)
            {
                manager.RunWaitCallbacks(TimeSpan.FromSeconds(1));
            }

            User.LogOff();
            Client.Disconnect();
        }

        private void OnLicenseList(SteamApps.LicenseListCallback obj)
        {
            new Thread(() => { OnLicenseListAsync(obj.LicenseList).GetAwaiter().GetResult(); }).Start();
        }

        private Dictionary<uint, HashSet<string>> DetectedTags = new Dictionary<uint, HashSet<string>>();

        private Dictionary<uint, Dictionary<string, float>> DepotConfidence =
            new Dictionary<uint, Dictionary<string, float>>();

        private async Task OnLicenseListAsync(IEnumerable<SteamApps.LicenseListCallback.License> licenseList)
        {
            Thread.Sleep(TimeSpan.FromSeconds(1)); // Let some events run.

            var steamVDFPath = Path.Combine(SteamDirectory, "userdata", User.SteamID.AccountID.ToString(),
                "7", "remote", "sharedconfig.vdf");

            if (!File.Exists(steamVDFPath))
            {
                Logger.Log24Bit(ConsoleSwatch.XTermColor.Red, true, Console.Out, string.Empty,
                    $"Can't find VDF at path {steamVDFPath}");
                return;
            }

            var packageIds = licenseList.Select(x => x.PackageID);

            if (!Directory.Exists("Manifests"))
            {
                Directory.CreateDirectory("Manifests");
            }

            var packagePICS = await Apps.PICSGetProductInfo(Array.Empty<uint>(), packageIds, false);
            var appIds = new HashSet<uint>();
            var depotIds = new HashSet<uint>();
            foreach (var package in packagePICS.Results.SelectMany(x => x.Packages))
            {
                foreach (var appIdStr in package.Value.KeyValues["appids"].Children)
                {
                    if (uint.TryParse(appIdStr.Value, out var appid))
                    {
                        appIds.Add(appid);
                    }
                }

                foreach (var depotIdStr in package.Value.KeyValues["depotids"].Children)
                {
                    if (uint.TryParse(depotIdStr.Value, out var depotid))
                    {
                        depotIds.Add(depotid);
                    }
                }
            }

            var appPICS = await Apps.PICSGetProductInfo(appIds, Array.Empty<uint>(), false);

            var appPICSSane = appPICS.Results.SelectMany(x => x.Apps)
                .Where(x => x.Value.KeyValues["common"]["type"].Value?.ToLower() == "game" && x.Value.KeyValues["depots"].Children.Count > 0);

            var appPICSArray = appPICSSane as KeyValuePair<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>[] ??
                               appPICSSane.ToArray();

            var appsDepots =
                new Dictionary<KeyValuePair<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>,
                    Dictionary<uint, ulong>>();

            foreach (var appData in appPICSArray)
            {
                var appDepots = new Dictionary<uint, ulong>();
                var appInfo = appData.Value.KeyValues;
                if (appInfo["depots"].Children.Count > 0)
                {
                    foreach (var depot in appInfo["depots"].Children)
                    {
                        if (depot["manifests"]["public"].Value == null) continue;
                        if (depot["config"]["oslist"].Value?.Length > 0)
                        {
                            if (!depot["config"]["oslist"].Value.ToLower().Contains("win"))
                            {
                                continue;
                            }
                        }

                        if (uint.TryParse(depot.Name, out var depotId) && depotIds.Contains(depotId) &&
                            ulong.TryParse(depot["manifests"]["public"].Value, out var manifestId))
                        {
                            appDepots[depotId] = manifestId;
                        }
                    }
                }

                if (appDepots.Count == 0) continue;

                appsDepots[appData] = appDepots;
            }

            Logger.Log24Bit(ConsoleSwatch.XTermColor.Orange, true, Console.Out, string.Empty,
                $"{appsDepots.Select(x => x.Value.Count).Sum()} depots");

            foreach (var appDataDepots in appsDepots)
            {
                var appData = appDataDepots.Key;
                var appDepots = appDataDepots.Value;
                KeyValuePair<CDNClient, CDNClient.Server> cdnPair = new KeyValuePair<CDNClient, CDNClient.Server>();
                try
                {
                    if (!DetectedTags.ContainsKey(appData.Key))
                    {
                        DetectedTags[appData.Key] = new HashSet<string>();
                    }

                    foreach (var depotId in appDepots.Keys)
                    {
                        if (!DepotConfidence.TryGetValue(depotId, out Dictionary<string, float> Confidence))
                        {
                            IEnumerable<string> ManifestData = null;
                            var manifestFn = Path.Combine("Manifests", $"{depotId:X8}-{appDepots[depotId]:X16}.json");
                            if (File.Exists(manifestFn))
                            {
                                try
                                {
                                    ManifestData =
                                        JsonConvert.DeserializeObject<List<string>>(
                                            File.ReadAllText(manifestFn));
                                }
                                catch
                                {
                                    File.Delete(manifestFn);
                                }
                            }

                            if (ManifestData == null)
                            {
                                try
                                {
                                    if (cdnPair.Key == null)
                                    {
                                        cdnPair = await GetConnectionForAppAsync(appData.Key);
                                    }

                                    await AuthenticateDepot(cdnPair, depotId, appData.Key);

                                    var manifest = await cdnPair.Key.DownloadManifestAsync(depotId, appDepots[depotId]);
                                    ManifestData = manifest.Files.Select(x => x.FileName);
                                    File.WriteAllText(manifestFn, JsonConvert.SerializeObject(ManifestData));
                                }
                                catch
                                {
                                    ManifestData = Array.Empty<string>();
                                    File.WriteAllText(manifestFn, JsonConvert.SerializeObject(ManifestData));
                                }
                            }

                            var manifestData = ManifestData.ToList();

                            if (manifestData.Count == 0)
                            {
                                continue;
                            }

                            Confidence = new Dictionary<string, float>();

                            foreach (var pair in EngineTest)
                            {
                                if (Confidence.ContainsKey(pair.Key))
                                {
                                    continue;
                                }

                                Confidence[pair.Key] = Math.Min(1.0f, pair.Value(manifestData));
                            }
                        }

                        DepotConfidence[depotId] = Confidence;

                        // ReSharper disable once CompareOfFloatsByEqualityOperator
                        if (Confidence.Count == 0 || Confidence.Values.Sum() == 0.0) continue;

                        Logger.Log24Bit(ConsoleSwatch.XTermColor.Orange, false, Console.Out, string.Empty,
                            "Confidence Rating for ");
                        Logger.Log24Bit(ConsoleSwatch.XTermColor.Orchid, true, Console.Out, string.Empty,
                            $"{appData.Value.KeyValues["common"]["name"].Value} ({appData.Key})");
                        bool hasValid = false;
                        foreach (var pair in Confidence)
                        {
                            // ReSharper disable once CompareOfFloatsByEqualityOperator
                            if (pair.Value == 0.0)
                            {
                                continue;
                            }

                            var color = ConsoleSwatch.XTermColor.Green;
                            if (pair.Value < 0.5)
                            {
                                color = ConsoleSwatch.XTermColor.Red;
                            }

                            Logger.Log24Bit(ConsoleSwatch.XTermColor.Blue, false, Console.Out, string.Empty,
                                $"{pair.Key}: ");
                            Logger.Log24Bit(color, true, Console.Out, string.Empty,
                                ((int) (pair.Value * 10000) / 100) + "%");

                            if (pair.Value < 0.5)
                            {
                                continue;
                            }

                            if (!DetectedTags.ContainsKey(appData.Key))
                            {
                                DetectedTags[appData.Key] = new HashSet<string>();
                            }

                            DetectedTags[appData.Key].Add(pair.Key);

                            hasValid = true;
                        }

                        if (hasValid)
                        {
                            break;
                        }
                    }
                }
                catch
                {
                    // ignored
                }
                finally
                {
                    cdnPair.Key?.Dispose();
                }

                Thread.Sleep(TimeSpan.FromSeconds(1));
            }

            File.WriteAllBytes($"{steamVDFPath}_ecbak", File.ReadAllBytes(steamVDFPath));
            var steamSharedConfig = KeyValue.LoadAsText(steamVDFPath);
            var configSteam = steamSharedConfig["Software"]["valve"]["steam"]["apps"];

            foreach (var pair in DetectedTags)
            {
                var configApp = configSteam[pair.Key.ToString()];

                var configAppTags = configApp["tags"].Children.Select(x => x.Value).ToHashSet();

                foreach (var tag in pair.Value)
                {
                    var finalTag = (TagPrefix + tag).Trim();
                    configAppTags.Add(finalTag);
                }

                configApp["tags"] = new KeyValue("tags");

                for (int i = 0; i < configAppTags.Count; ++i)
                {
                    configApp["tags"][i.ToString()] = new KeyValue(i.ToString(), configAppTags.ElementAt(i));
                }

                configSteam[pair.Key.ToString()] = configApp;
            }

            steamSharedConfig["Software"]["valve"]["steam"]["apps"] = configSteam;
            
            steamSharedConfig.SaveToFile(steamVDFPath, false);

            Running = false;
        }

        public Dictionary<uint, byte[]> AppTickets { get; } = new Dictionary<uint, byte[]>();
        public Dictionary<uint, byte[]> DepotKeys { get; } = new Dictionary<uint, byte[]>();
        public Dictionary<string, string> CDNAuthKeys { get; } = new Dictionary<string, string>();

        public async Task<byte[]> RequestAppTicket(uint appId)
        {
            if (!AppTickets.ContainsKey(appId))
            {
                AppTickets[appId] = (await Apps.GetAppOwnershipTicket(appId)).Ticket;
            }

            return AppTickets[appId];
        }

        public async Task<byte[]> RequestDepotKey(uint appId, uint depotId)
        {
            if (!DepotKeys.ContainsKey(depotId))
            {
                DepotKeys[depotId] = (await Apps.GetDepotDecryptionKey(depotId, appId)).DepotKey;
            }

            return DepotKeys[depotId];
        }

        public async Task<string> RequestCDNAuthToken(uint appId, uint depotId, string host)
        {
            var dKey = depotId + "-" + appId + "-" + host;
            if (!CDNAuthKeys.ContainsKey(dKey))
            {
                CDNAuthKeys[dKey] = (await Apps.GetCDNAuthToken(appId, depotId, host)).Token;
            }

            return CDNAuthKeys[dKey];
        }

        public async Task<KeyValuePair<CDNClient, CDNClient.Server>> GetConnectionForAppAsync(uint appId)
        {
            CDNClient client = new CDNClient(Client, await RequestAppTicket(appId));

            var serverList = await client.FetchServerListAsync();

            var server = serverList.Where(x => x.Type == "CDN").OrderBy(x => x.WeightedLoad).First();

            await client.ConnectAsync(server);

            return new KeyValuePair<CDNClient, CDNClient.Server>(client, server);
        }

        public async Task AuthenticateDepot(KeyValuePair<CDNClient, CDNClient.Server> pair, uint depotId, uint appId)
        {
            await pair.Key.AuthenticateDepotAsync(depotId, await RequestDepotKey(appId, depotId),
                await RequestCDNAuthToken(appId, depotId, pair.Value.Host));
        }

        private void OnLoginKey(SteamUser.LoginKeyCallback obj)
        {
            Logger.Log24Bit(ConsoleSwatch.XTermColor.Pink, false, Console.Out, string.Empty,
                "Updating login key file... ");
            if (File.Exists("login.key"))
            {
                File.Delete("login.key");
            }

            User.AcceptNewLoginKey(obj);
            File.WriteAllText("login.key", obj.LoginKey);
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

                Timeout = 0;

                SteamPassword = null;

                while (string.IsNullOrWhiteSpace(SteamPassword))
                {
                    Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                        "Password: ");
                    SteamPassword = Logger.ReadLine(Console.Out, true);
                }

                Logger.Log24Bit(ConsoleSwatch.XTermColor.OrangeRed, false, Console.Out, string.Empty,
                    "Remember Password (Y/N): ");
                SteamShouldRemember = Logger.ReadLine(Console.Out, false).ToLowerInvariant().StartsWith("y");

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
