#include <iostream>

#include <CertStore.hpp>
#include <console.hpp>
#include <HttpRequestTask.hpp>
#include <IrcServer.hpp>
#include <json.hpp>
#include <pem.hpp>
#include <ServerWebService.hpp>
#include <Socket.hpp>
#include <urlenc.hpp>
#include <X509Certchain.hpp>

using namespace soup;

static std::string http_host;
static int16_t http_port;
static bool http_use_tls;

static int16_t mgmt_port;
static bool mgmt_loopback_only;

struct AuthPendingTag {};

struct AuthenticatedUserData
{
	std::string accountId;
	std::string nonce;
	std::string guildId;
	bool guildChatModerator;
	bool administrator;
};

struct VerifyCredsTask final : public soup::Task
{
	SharedPtr<Worker> s;
	HttpRequestTask hrt;
	std::string accountId;
	std::string nonce;

	VerifyCredsTask(Socket& _s, std::string&& accountId, std::string&& nonce)
		: s(Scheduler::get()->getShared(_s)), hrt(buildRequest(accountId, nonce)), accountId(std::move(accountId)), nonce(std::move(nonce))
	{
	}

	static HttpRequest buildRequest(const std::string& accountId, const std::string& nonce)
	{
		std::string path = "/custom/getAccountInfo?accountId=";
		path.append(accountId);
		path.append("&nonce=");
		path.append(nonce);
		path.append("&ct=IRC");

		HttpRequest hr(http_host, std::move(path));
		hr.port = http_port;
		hr.use_tls = http_use_tls;
		return hr;
	}

	void onTick() final
	{
		if (static_cast<Socket*>(s.get())->isWorkDoneOrClosed())
		{
			setWorkDone();
		}
		else if (hrt.tickUntilDone())
		{
			if (hrt.result.has_value())
			{
				if (hrt.result->status_code == 200)
				{
					AuthenticatedUserData aud{ std::move(accountId), std::move(nonce) };
					if (auto jr = json::decode(hrt.result->body); jr && jr->isObj())
					{
						if (auto GuildId = jr->reinterpretAsObj().find("GuildId"))
						{
							aud.guildId = GuildId->asStr();
							aud.guildChatModerator = (jr->reinterpretAsObj().at("GuildPermissions").asInt() & 512);
						}
						if (auto IsAdministrator = jr->reinterpretAsObj().find("IsAdministrator"))
						{
							aud.administrator = IsAdministrator->asBool();
						}
					}
					std::cout << "Successful auth, guildId=" << aud.guildId << std::endl;
					static_cast<Socket*>(s.get())->custom_data.addStructToMap(AuthenticatedUserData, std::move(aud));
				}
				else
				{
					static_cast<Socket*>(s.get())->send(":Soup WALLOPS :Failed to validate your credentials (accountId-nonce pair).\r\n");
				}
			}
			static_cast<Socket*>(s.get())->custom_data.removeStructFromMap(AuthPendingTag);
			setWorkDone();
		}
	}
};

struct ReportDropTask final : public soup::Task
{
	HttpRequestTask hrt;

	ReportDropTask(const AuthenticatedUserData& aud)
		: hrt(buildRequest(aud.accountId, aud.nonce))
	{
	}

	static HttpRequest buildRequest(const std::string& accountId, const std::string& nonce)
	{
		std::string path = "/custom/ircDropped?accountId=";
		path.append(accountId);
		path.append("&nonce=");
		path.append(nonce);
		path.append("&ct=IRC");

		HttpRequest hr(http_host, std::move(path));
		hr.port = http_port;
		hr.use_tls = http_use_tls;
		return hr;
	}

	void onTick() final
	{
		if (hrt.tickUntilDone())
		{
			setWorkDone();
		}
	}
};

struct HandleChannelJoinTask final : public soup::Task
{
	SharedPtr<Worker> s;
	std::string channel_name;

	HandleChannelJoinTask(Socket& _s, const std::string& channel_name)
		: s(Scheduler::get()->getShared(_s)), channel_name(channel_name)
	{
	}

	void onTick() final
	{
		if (static_cast<Socket*>(s.get())->custom_data.isStructInMap(AuthPendingTag))
		{
			return;
		}
		if (static_cast<Socket*>(s.get())->custom_data.isStructInMap(AuthenticatedUserData))
		{
			bool op;
			if (channel_name.substr(0, 2) == "#C")
			{
				op = (static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(AuthenticatedUserData).guildId == channel_name.substr(2)
					&& static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(AuthenticatedUserData).guildChatModerator
					);
			}
			else
			{
				op = static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(AuthenticatedUserData).administrator;
			}
			if (op)
			{
				auto& cd = static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(IrcClientData);
				if (auto membership = cd.getMembership(channel_name))
				{
					std::cout << "Giving " << cd.nick << " oper in " << channel_name << std::endl;

					membership->op = true;

					std::string msg = ":Soup MODE ";
					msg.append(channel_name);
					msg.append(" +o ");
					msg.append(cd.nick);
					msg.append("\r\n");
					for (const auto& member : static_cast<IrcServer*>(Scheduler::get())->getChannelMembers(channel_name))
					{
						member.socket->send(msg);
					}
				}
			}
		}
		setWorkDone();
	}
};

struct LoggingIrcServer : public soup::IrcServer
{
	void onClientConnected(Socket& s) final
	{
		std::cout << s.toString() << " has connected\n";
		s.send("NOTICE * :Auth AAAAAAA:*** skipping identd (disabled by server administrator)\r\n");
	}

	void onClientDisconnected(Socket& s) final
	{
		std::cout << s.toString() << " has disconnected\n";
		if (s.custom_data.isStructInMap(AuthenticatedUserData))
		{
			this->add<ReportDropTask>(s.custom_data.getStructFromMapConst(AuthenticatedUserData));
		}
	}

	void onClientLineReceived(Socket& s, const std::string& line) final
	{
		std::cout << s.toString() << " | " << line << "\n";
		if (line.substr(0, 4) == "USER" && line.size() > 42
			&& line.substr(36, 6) == "nonce=" // Boostrapper 0.10.4 and above
			)
		{
			s.custom_data.addStructToMap(AuthPendingTag, AuthPendingTag{});
			this->add<VerifyCredsTask>(s, line.substr(5, 24), line.substr(42));
		}
	}

	void onClientJoinedChannel(Socket& s, const std::string& channel_name, IrcChannelMembershipData& md) final
	{
		this->add<HandleChannelJoinTask>(s, channel_name);
		md.op = false;
	}
};

int main()
{
	try
	{
		soup::console.init(false);

		if (!std::filesystem::exists("irc_config.json"))
		{
			JsonObject config;
			config.add("http_host", "localhost");
			config.add("http_port", 80);
			config.add("http_use_tls", false);
			config.add("mgmt_port", 6688);
			config.add("mgmt_loopback_only", true);
			soup::string::toFile("irc_config.json", config.encodePretty());
		}

		{
			auto jr = json::decode(string::fromFile("irc_config.json"));
			SOUP_ASSERT(jr);
			http_host = jr->asObj().at("http_host").asStr().value;
			http_port = jr->asObj().at("http_port").asInt().value;
			http_use_tls = jr->asObj().at("http_use_tls").asBool().value;
			mgmt_port = jr->asObj().at("mgmt_port").asInt().value;
			mgmt_loopback_only = jr->asObj().at("mgmt_loopback_only").asBool().value;
		}

		LoggingIrcServer serv;
		auto certstore = soup::make_shared<soup::CertStore>();
		soup::X509Certchain certchain;
		certchain.fromDer({
			soup::pem::decode(R"EOC(
-----BEGIN CERTIFICATE-----
MIIFEjCCA/qgAwIBAgISAzO1ak1tzkSo99OqAn2x+OfMMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMjAzMDcwMjM0MzdaFw0yMjA2MDUwMjM0MzZaMBIxEDAOBgNVBAMT
B3NvdXAuZG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYbeJly69N
d+bPEnzCEAJZzqp/xsGr2YTgisYGyBKqp0ubWfl4ItRx7a50siEVy57oNBc4AGhQ
6/A1+IFQ2n/kGvvY0sTLs4Pv1yRD1Qs2VkDS6Jcor5O+tzvOomHko7mJ5cvxIq15
rocdKsJGhFY7k3S+iY0pXk5niEDMts6JMrXOja9oDt5pWoDNDECfIN7D1THB+v1i
8tsS5ScFCgVpFf9fLW8sW0weeEp0mpAIO5LUdQWWRFd7csMtVorJauYy5b0qKKZV
6eUWy04OrhZL+Adqg1KT/LBvO69oZNBoCOehoVJnoqgMTfTweUTPpNGYmlNanG7J
Qu++GqrcfzRzAgMBAAGjggJAMIICPDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFE7Q
uqEvBJXbxPcOKhxv6fZHEMchMB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52L
FMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVu
Y3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMBIGA1Ud
EQQLMAmCB3NvdXAuZG8wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMB
AQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEC
BgorBgEEAdZ5AgQCBIHzBIHwAO4AdQDfpV6raIJPH2yt7rhfTj5a6s2iEqRqXo47
EsAgRFwqcwAAAX9icXU+AAAEAwBGMEQCIGn3bY2k5A2Bm6Vj/MJzsu37VR7VgCK9
DGlZE1uIiJmlAiB03bP3Yzi2IMq7kZ7iTyN73jX5BjN/1nSdG10jHOP35gB1ACl5
vvCeOTkh8FZzn2Old+W+V32cYAr4+U1dJlwlXceEAAABf2JxdTAAAAQDAEYwRAIg
UpJu1XNFarHUfzbjAhb0+dZA9VlB/soZ51BJq/bIXkYCIFqCNaaLy8mXfS9E+pGs
wnHTvAAzIVZhbZc/+rzH+JY0MA0GCSqGSIb3DQEBCwUAA4IBAQBSfR9b4Wt17a8l
g1PMh0d2m7B5WMYuovOwd1A8KEOavYe2QqIQ1olS1vPKPFwtp1dk4qhqWd3vCCGf
84cCfwpnwrk1bSeT4PBy3z1hOHaZ+iFH/GXRC6B18MWueRMmM9k4McKUTjQzRatm
Am+yUiq0BvgST2Ctf/LZbKsecvTnkLPzUededMfO3s631JIFu/8Uh0gvE+daucdV
CFz9GEwFTtBOZVm2pXQa7WJZkkas2CEp8OaE1uTi0dNsjsmoucx5NjnAVIJsZYjl
fSAiz4aov7Yb7NyFQqfMAhjYQIxkoJSHwhTWRTlccEiwtPvOU+e3lYQVemWlHw7W
eG23qKPg
-----END CERTIFICATE-----
)EOC"),
soup::pem::decode(R"EOC(
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
)EOC"),
			});
		auto private_key = soup::RsaPrivateKey::fromPem(R"EOC(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDYbeJly69Nd+bP
EnzCEAJZzqp/xsGr2YTgisYGyBKqp0ubWfl4ItRx7a50siEVy57oNBc4AGhQ6/A1
+IFQ2n/kGvvY0sTLs4Pv1yRD1Qs2VkDS6Jcor5O+tzvOomHko7mJ5cvxIq15rocd
KsJGhFY7k3S+iY0pXk5niEDMts6JMrXOja9oDt5pWoDNDECfIN7D1THB+v1i8tsS
5ScFCgVpFf9fLW8sW0weeEp0mpAIO5LUdQWWRFd7csMtVorJauYy5b0qKKZV6eUW
y04OrhZL+Adqg1KT/LBvO69oZNBoCOehoVJnoqgMTfTweUTPpNGYmlNanG7JQu++
GqrcfzRzAgMBAAECggEBAKGQLfClw6CGAFPWTjGkN80I3PhzzAHYaDwi/D71vhGM
v4EiAnvvLD48Gv5cNxyJG3/l2utgSn8WEgSIFSjhY5VJm3W5qVUTFkvFg/nrIOqY
Kt4G6UhjAVzedhQD3iYLHqdVVxAUPgHXCl/4mnx/r8vbgMv37NvT3Z2l9hGb6cQ6
KThWdtse2/cG7bwnQQWQI/5gd/3technnzYtPh47s2Z0fj0CUp8oA9eZa2oZhmFd
5wNnX5Sy5OSZQlOJHEg/9kN9GkahtyjTQ6IGiocuU0Fb788ZF0QEZuB2ddc87lAB
hiAd1TgbieU+11idqh1C5wCLCPtAevXRhQNhdKeubSECgYEA/uOtO0jmRT6jFf1A
XtUPaJ6kWyjSA6fu/HoAsGYzxz1yiUDM0PWyXWQ8dUYe41pd6QDu++l4fkJLB6LC
Ks7hewsCqZIRw8w3ebbABqWBFW4RT3w+nYOdaJwrHUbwg+YoLrC6iJwOusC/FKr5
p6USYp38O5RE2Xb12j9F8dcJl2MCgYEA2V9OaFb+PTKCL6PHZYoeTg4ElVLHEq5E
H77dJYAd2A75amEKC3L5WqYiLTrOdBqIOhXXSUSMNd2pEecw6u50A5vI0ezJP40/
bEYQDwpQDhdtvhWPtLJ1C0GsCyjgHwpmcEAD3rNB6M0nIROD/BKIaABePD7KoOu8
yEbdWJeZI7ECgYBEaWt3fAuCDlvLbRu32Eu4csv+Q6iKnqpATaadsfC3y0BQonnW
o/tpoZuwhk+IChsmjL+YEYPrr3Nf60leIATY942RYcku2kMRggFsR0OsMsymntxX
fpnjF/didkXbwQyL65dFT02MxmsC6xjy7BVRLsIiY5tPGuTF3TGyxVqnrQKBgQC6
82IvEOq2XXNkX7rFlMW9ogbFGp2GboS+vNvcPdTtFuviVzVZZXgaQ5pPRi1747nY
IyK2rBLe3RZlBG6pD46N7/UGv1zSoLu0domnNdpmVDYZbtfatEU/+ipqqqwfZkV2
M0hgx9Fe1NrbcrpoGNRihjaGIAcL4dPKeFA0uqWF8QKBgFN4K7Veh7E8nJ8D/ErB
AA3w0djptVzPMBF7JFE72qgIYiErviEf2X5aFwTLQJNtpLBNDFGhlsyM0B3vQMG6
IWTRPUZRNojVvK1dQ+xPN/9HsFVUb6JWyU4e3gocnYoe2zGdyT9p9u0Pr3JikgAC
QJg24g1I/Zb4EUJmo2WNBzGS
-----END PRIVATE KEY-----
)EOC");
		certstore->add(std::move(certchain), std::move(private_key));
		if (!serv.bindCrypto(6695, &serv.srv, certstore)
			|| !serv.bindCrypto(6696, &serv.srv, certstore)
			|| !serv.bindCrypto(6697, &serv.srv, certstore)
			|| !serv.bindCrypto(6698, &serv.srv, certstore)
			|| !serv.bindCrypto(6699, &serv.srv, certstore)
			)
		{
			std::cout << "Failed to bind to ports 6695-6699\n";
			return 1;
		}
		std::cout << "Listening on ports 6695-6699\n";

		ServerWebService web_srv([](soup::Socket& s, soup::HttpRequest&& req, soup::ServerWebService&)
		{
			if (mgmt_loopback_only && !s.peer.ip.isLoopback())
			{
				ServerWebService::sendText(s, "This service is available via loopback only.");
				return;
			}

			if (req.path == "/")
			{
				ServerWebService::sendHtml(s, R"EOC(<p>Send redtext</p>
<input type="text" />
<input type="submit" onclick="sendRedtext();" />
<script>
	function sendRedtext() {
		fetch("/redtext?" + encodeURIComponent(document.querySelector("input[type=text]").value));
	}
</script>)EOC");
			}
			else if (req.path.substr(0, 9) == "/redtext?")
			{
				std::string msg = ":Soup WALLOPS :";
				msg.append(urlenc::decode(req.path.substr(9)));
				msg.append("\r\n");
				static_cast<IrcServer*>(Scheduler::get())->broadcast(msg);
			}
			else
			{
				ServerWebService::send404(s);
			}
		});
		if (serv.bind(mgmt_port, &web_srv))
		{
			std::cout << "Management interface available at http://localhost:" << mgmt_port;
			if (mgmt_loopback_only)
			{
				std::cout << " (loopback only)";
			}
			std::cout << std::endl;
		}

		serv.run();
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}
}
