#include <iostream>

#include <CertStore.hpp>
#include <console.hpp>
#include <dnsOsResolver.hpp>
#include <HttpRequestTask.hpp>
#include <IrcServer.hpp>
#include <json.hpp>
#include <netConfig.hpp>
#include <pem.hpp>
#include <ServerWebService.hpp>
#include <Socket.hpp>
#include <urlenc.hpp>
#include <X509Certchain.hpp>

#ifdef DOCKER
#include <signal.h>
#endif

using namespace soup;

static std::string http_host;
static bool http_use_tls;

static int16_t mgmt_port;
static bool mgmt_loopback_only;

static bool public_chats_allow_noobies;

struct AuthPendingTag {};

struct AuthenticatedUserData
{
	std::string accountId;
	std::string nonce;
	std::string guildId;
	std::string allianceId;
	bool guildChatModerator = false;
	bool allianceChatModerator = false;
	bool administrator = false;
	bool noobie = false;
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
		//SOUP_ASSERT(s);
	}

	static HttpRequest buildRequest(const std::string& accountId, const std::string& nonce)
	{
		std::string path = "/custom/getAccountInfo?accountId=";
		path.append(accountId);
		path.append("&nonce=");
		path.append(nonce);
		path.append("&ct=IRC");

		HttpRequest hr(http_host, std::move(path));
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
							if (auto AllianceId = jr->reinterpretAsObj().find("AllianceId"))
							{
								aud.allianceId = AllianceId->asStr();
								aud.allianceChatModerator = (jr->reinterpretAsObj().at("GuildRank").asInt() <= 1)
														&& (jr->reinterpretAsObj().at("AlliancePermissions").asInt() & 512)
														;
							}
						}
						if (auto IsAdministrator = jr->reinterpretAsObj().find("IsAdministrator"))
						{
							aud.administrator = IsAdministrator->asBool();
						}
						if (auto CompletedVorsPrize = jr->reinterpretAsObj().find("CompletedVorsPrize"))
						{
							aud.noobie = !CompletedVorsPrize->asBool();
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

struct VerifyChannelJoinTask final : public soup::Task
{
	SharedPtr<Worker> s;
	const std::string& channel_name;
	Promise<std::string>& reject_reason_promise;

	VerifyChannelJoinTask(Socket& _s, const std::string& channel_name, Promise<std::string>& reject_reason_promise)
		: s(Scheduler::get()->getShared(_s)), channel_name(channel_name), reject_reason_promise(reject_reason_promise)
	{
	}

	void onTick() final
	{
		if (static_cast<Socket*>(s.get())->isWorkDoneOrClosed())
		{
			return setWorkDone();
		}
		if (static_cast<Socket*>(s.get())->custom_data.isStructInMap(AuthPendingTag))
		{
			return;
		}
		if (static_cast<Socket*>(s.get())->custom_data.isStructInMap(AuthenticatedUserData)
			&& static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(AuthenticatedUserData).noobie
			)
		{
			if (channel_name.substr(0, 2) == "#R" // Recruiting
				|| channel_name.substr(0, 2) == "#T" // Trade
				|| channel_name.substr(0, 2) == "#G" // Region
				|| channel_name.substr(0, 2) == "#Q" // Q&A
				)
			{
				if (!public_chats_allow_noobies)
				{
					std::cout << "Rejecting " << static_cast<Socket*>(s.get())->custom_data.getStructFromMapConst(IrcClientData).nick << " from " << channel_name << " due to being a noobie" << std::endl;
					reject_reason_promise.fulfil("Censored");
					return setWorkDone();
				}
			}
		}
		reject_reason_promise.fulfil({});
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
		if (line.substr(0, 4) == "USER")
		{
			auto arr = string::explode(line, ' ');
			std::string nonce;
			if (arr.size() == 5)
			{
				auto realname = arr[4];
				if (realname.c_str()[0] != ':') // Not a real IRC client?
				{
					if (realname.starts_with("nonce=")) // Bootstrapper 0.10.4 and above
					{
						nonce = realname.substr(6);
					}
					else
					{
						nonce = std::move(realname); // U8 and below
					}
				}
			}
			if (!nonce.empty())
			{
				s.custom_data.addStructToMap(AuthPendingTag, AuthPendingTag{});
				this->add<VerifyCredsTask>(s, line.substr(5, 24), std::move(nonce));
			}
			else
			{
				s.send(":Soup WALLOPS :Your client did not provide credentials (accountId-nonce pair). You will be chatting unauthenticated.\r\n");
			}
		}
	}

	void canClientJoinChannel(Socket& s, const std::string& channel_name, Promise<std::string>& reject_reason_promise) final
	{
		this->add<VerifyChannelJoinTask>(s, channel_name, reject_reason_promise);
	}

	void onClientJoinedChannel(Socket& s, const std::string& channel_name, IrcChannelMembershipData& md) final
	{
		if (s.custom_data.isStructInMap(AuthenticatedUserData))
		{
			if (channel_name.substr(0, 2) == "#C")
			{
				md.op = (s.custom_data.getStructFromMapConst(AuthenticatedUserData).guildId == channel_name.substr(2)
					&& s.custom_data.getStructFromMapConst(AuthenticatedUserData).guildChatModerator
					);
			}
			else if (channel_name.substr(0, 2) == "#A")
			{
				md.op = (s.custom_data.getStructFromMapConst(AuthenticatedUserData).allianceId == channel_name.substr(2)
					&& s.custom_data.getStructFromMapConst(AuthenticatedUserData).allianceChatModerator
					);
			}
			else
			{
				md.op = s.custom_data.getStructFromMapConst(AuthenticatedUserData).administrator;
			}
		}
		else
		{
			md.op = false;
		}
		if (md.op)
		{
			std::cout << "Giving " << s.custom_data.getStructFromMapConst(IrcClientData).nick << " oper in " << channel_name << std::endl;
		}
	}
};

#ifdef DOCKER
	#define CONFIG_PATH "conf/irc_config.json"
#else
	#define CONFIG_PATH "irc_config.json"
#endif

int main()
{
	try
	{
		soup::console.init(false);

		{
			UniquePtr<JsonNode> config = json::decode(string::fromFile(CONFIG_PATH));

			bool modified = false;
			if (!config || !config->isObj())
			{
				modified = true;
				config = soup::make_unique<JsonObject>();
			}
#ifdef DOCKER
			if (!config->reinterpretAsObj().contains("http_host")) { modified = true; config->reinterpretAsObj().add("http_host", "spaceninjaserver"); }
#else
			if (!config->reinterpretAsObj().contains("http_host")) { modified = true; config->reinterpretAsObj().add("http_host", "localhost"); }
#endif
			if (!config->reinterpretAsObj().contains("http_port")) { modified = true; config->reinterpretAsObj().add("http_port", 80); }
			if (!config->reinterpretAsObj().contains("http_use_tls")) { modified = true; config->reinterpretAsObj().add("http_use_tls", false); }
			if (!config->reinterpretAsObj().contains("mgmt_port")) { modified = true; config->reinterpretAsObj().add("mgmt_port", 6688); }
			if (!config->reinterpretAsObj().contains("mgmt_loopback_only")) { modified = true; config->reinterpretAsObj().add("mgmt_loopback_only", true); }
			if (!config->reinterpretAsObj().contains("public_chats_allow_noobies")) { modified = true; config->reinterpretAsObj().add("public_chats_allow_noobies", false); }
			if (modified)
			{
				string::toFile(CONFIG_PATH, config->reinterpretAsObj().encodePretty());
			}

			http_host = config->reinterpretAsObj().at("http_host").asStr().value;
			http_use_tls = config->reinterpretAsObj().at("http_use_tls").asBool().value;
			if (uint16_t http_port = config->reinterpretAsObj().at("http_port").asInt().value; http_port != (http_use_tls ? 443 : 80))
			{
				http_host.push_back(':');
				http_host.append(std::to_string(config->reinterpretAsObj().at("http_port").asInt().value));
			}
			mgmt_port = config->reinterpretAsObj().at("mgmt_port").asInt().value;
			mgmt_loopback_only = config->reinterpretAsObj().at("mgmt_loopback_only").asBool().value;
			public_chats_allow_noobies = config->reinterpretAsObj().at("public_chats_allow_noobies").asBool().value;
		}

		LoggingIrcServer serv;
		auto certstore = soup::make_shared<soup::CertStore>();
		soup::X509Certchain certchain;
		certchain.fromDer({
			soup::pem::decode(R"EOC(
-----BEGIN CERTIFICATE-----
MIIGMDCCBRigAwIBAgIQX4800cgswlDH/QexMSnnnjANBgkqhkiG9w0BAQsFADCB
jzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQD
Ey5TZWN0aWdvIFJTQSBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENB
MB4XDTI1MDMwNjAwMDAwMFoXDTI2MDMwNjIzNTk1OVowGDEWMBQGA1UEAwwNKi5m
YWtldGxzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMe42XWK
HJuR7doFTX79zrEKfTlD2hjRIif3dHKJNTJNvZa52mIoHelP7RVUuFOhp7aZCNLh
IEzDyZObl8vwO6L2PVu5tbBEEoNixbpfhc8ZICEBuVo2UAhnJFcMJtuvtrCq+7ye
oczM/k/nh8FBz2WnLzWs4CZt1sa5knZXFmBmsHJQtQIC6vx7QzVcKGOlAosIEHSK
X4nIz5fLgWSzor1Gay56j31PTk+qRvlPQM2aKiLWnlLfRED4zHJqLe94itu8llPX
b6g+cLxxRKUpMqtG/15cDdBZwv40Dja7bmNfe1u4w2QCVLjvHVaVpNXbcRay/Mhn
M1w5LzDZmV58b18CAwEAAaOCAvwwggL4MB8GA1UdIwQYMBaAFI2MXsRUrYrhd+mb
+ZsF4bgBjWHhMB0GA1UdDgQWBBS6/x/N38wMJrQq/cE1oIcRERMonTAOBgNVHQ8B
Af8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwSQYDVR0gBEIwQDA0BgsrBgEEAbIxAQICBzAlMCMGCCsGAQUFBwIBFhdo
dHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBAgEwgYQGCCsGAQUFBwEBBHgw
djBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNB
RG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNydDAjBggrBgEFBQcwAYYX
aHR0cDovL29jc3Auc2VjdGlnby5jb20wJQYDVR0RBB4wHIINKi5mYWtldGxzLmNv
bYILZmFrZXRscy5jb20wggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB2AJaXZL9V
WJet90OHaDcIQnfp8DrV9qTzNm5GpD8PyqnGAAABlWsz5fgAAAQDAEcwRQIgTN7Y
/mDqiD3RbGVLEOQK2wvXsboBolBRwGJFuFEsDScCIQCQ0qfb/0V8qqSxrkx/PiVS
1lSn5gBEnQUiQOkefcnW0gB2ABmG1Mcoqm/+ugNveCpNAZGqzi1yMQ+uzl1wQS0l
TMfUAAABlWsz5dAAAAQDAEcwRQIhAJnQJyrSCWWdi9Kyoa7XuMGyDKt183jJMY0E
71abTuBOAiBC+WnK1esG6xr8aVGHRcc+1U/I7LiaG3LCRMYtCKrTGwB2AMs49xWJ
fIShRF9bwd37yW7ymlnNRwppBYWwyxTDFFjnAAABlWsz5f4AAAQDAEcwRQIhAJUs
4PWDwyQJnCxCyEwFlFUY2uYQkGrQPA9f9Sw5Xk1fAiB63eQtZQGjvzvhOghy6z9a
8oGYbDfDQ/zfisMYO7rM6zANBgkqhkiG9w0BAQsFAAOCAQEAEHnSoeBbWiK3CS3a
px0BL+YXxRxdUcTMHgn5o+LlI9sWlpf+JLXmn7Z4QA6fAwT4k/Ue7xsmIq0OraDk
/pEVXWm1HO/9wUkGQg0DBi77BpfHircd7OWIMdt250Q8UAmZkOyhVgnwBcScqMwq
2T5CPaYvYGgYWx/qkIBv7JqhVbrP82rnF9b9ZUZ8GIE31chBmtMva9AsnAN5dmRw
81bVvPWXUfX30CYu5sxeWL06Zpy9nfJumxZri1SWXNTBjSvud2jsZ8tSCUAWLL/4
ui3Vien9m2oMOpaA8xbS88ZTk9Alm/o5febEKJZUPlytQzij8gQpiovFw2v+Cdei
+tFXKw==
-----END CERTIFICATE-----
)EOC"),
soup::pem::decode(R"EOC(
-----BEGIN CERTIFICATE-----
MIIGEzCCA/ugAwIBAgIQfVtRJrR2uhHbdBYLvFMNpzANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTgx
MTAyMDAwMDAwWhcNMzAxMjMxMjM1OTU5WjCBjzELMAkGA1UEBhMCR0IxGzAZBgNV
BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
ChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFJTQSBEb21haW4g
VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA1nMz1tc8INAA0hdFuNY+B6I/x0HuMjDJsGz99J/LEpgPLT+N
TQEMgg8Xf2Iu6bhIefsWg06t1zIlk7cHv7lQP6lMw0Aq6Tn/2YHKHxYyQdqAJrkj
eocgHuP/IJo8lURvh3UGkEC0MpMWCRAIIz7S3YcPb11RFGoKacVPAXJpz9OTTG0E
oKMbgn6xmrntxZ7FN3ifmgg0+1YuWMQJDgZkW7w33PGfKGioVrCSo1yfu4iYCBsk
Haswha6vsC6eep3BwEIc4gLw6uBK0u+QDrTBQBbwb4VCSmT3pDCg/r8uoydajotY
uK3DGReEY+1vVv2Dy2A0xHS+5p3b4eTlygxfFQIDAQABo4IBbjCCAWowHwYDVR0j
BBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFI2MXsRUrYrhd+mb
+ZsF4bgBjWHhMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAbBgNVHSAEFDASMAYGBFUdIAAw
CAYGZ4EMAQIBMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0
LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB2Bggr
BgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNv
bS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDov
L29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMr9hvQ5Iw0/H
ukdN+Jx4GQHcEx2Ab/zDcLRSmjEzmldS+zGea6TvVKqJjUAXaPgREHzSyrHxVYbH
7rM2kYb2OVG/Rr8PoLq0935JxCo2F57kaDl6r5ROVm+yezu/Coa9zcV3HAO4OLGi
H19+24rcRki2aArPsrW04jTkZ6k4Zgle0rj8nSg6F0AnwnJOKf0hPHzPE/uWLMUx
RP0T7dWbqWlod3zu4f+k+TY4CFM5ooQ0nBnzvg6s1SQ36yOoeNDT5++SR2RiOSLv
xvcRviKFxmZEJCaOEDKNyJOuB56DPi/Z+fVGjmO+wea03KbNIaiGCpXZLoUmGv38
sbZXQm2V0TP2ORQGgkE49Y9Y3IBbpNV9lXj9p5v//cWoaasm56ekBYdbqbe4oyAL
l6lFhd2zi+WJN44pDfwGF/Y4QA5C5BIG+3vzxhFoYt/jmPQT2BVPi7Fp2RBgvGQq
6jG35LWjOhSbJuMLe/0CjraZwTiXWTb2qHSihrZe68Zk6s+go/lunrotEbaGmAhY
LcmsJWTyXnW0OMGuf1pGg+pRyrbxmRE1a6Vqe8YAsOf4vmSyrcjC8azjUeqkk+B5
yOGBQMkKW+ESPMFgKuOXwIlCypTPRpgSabuY0MLTDXJLR27lk8QyKGOHQ+SwMj4K
00u/I5sUKUErmgQfky3xxzlIPK1aEn8=
-----END CERTIFICATE-----
)EOC"),
			});
		auto private_key = soup::RsaPrivateKey::fromPem(R"EOC(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHuNl1ihybke3a
BU1+/c6xCn05Q9oY0SIn93RyiTUyTb2WudpiKB3pT+0VVLhToae2mQjS4SBMw8mT
m5fL8Dui9j1bubWwRBKDYsW6X4XPGSAhAblaNlAIZyRXDCbbr7awqvu8nqHMzP5P
54fBQc9lpy81rOAmbdbGuZJ2VxZgZrByULUCAur8e0M1XChjpQKLCBB0il+JyM+X
y4Fks6K9Rmsueo99T05Pqkb5T0DNmioi1p5S30RA+Mxyai3veIrbvJZT12+oPnC8
cUSlKTKrRv9eXA3QWcL+NA42u25jX3tbuMNkAlS47x1WlaTV23EWsvzIZzNcOS8w
2ZlefG9fAgMBAAECggEAT1Tti/LASks8300b60WFxG0WMJjzGMh5eMaiSpyVtNWM
aUKJrFOjDfnhgoeUcCPWKoG/L4Sc/+EFQMydDzTte120IasysEFZ2TZytAUdcZXZ
XUMCDQNl5vCRTsJU7Q5u0t4YAGRCgMcsfTDKi8lISGiQKBHzN1CJ74Xm13rgOInd
lAc0wd5S89sL6RYmRTj1LvuZ95EHXHqQGdv0fIFEyP3pF1iPwcoTuIVEeICqnEvW
vd8CVO68eH3HFIwioqjp4qW3pxPZMhVq4161805uAMkoQlE+7MtEVenmP++1u1gM
FjvAs3j9CZqOHZKcLlOtcGSwDlD++fCMMT4slLgLgQKBgQDy58E5nuYXdxlFQQk4
QccUKpyJ2aVXyp9xvTFBot/5Pik1SkuDzv2XU1OTxdxf3EongLy91nMJ2/6/39Je
lf0/2MjzCtJ/lSzZ/zpJAu86UkBkWBAA5loGIof6OKedbEIgqpJqtK59S+j3ExO9
eqa+uFrtt1UfaJG4A7TT+dIvIwKBgQDSfSOdSM5Dh3KsQHVnIWcIkzwTtlJlO+rG
6rDEADxw6Kp8VIL/dq4Foe8yW4VqLVrWUuZsU6jzC9GdnyYi6VaqZ/iSUtGkBMOT
WTTYhqXlURaQ13jhqdwCZJRbVI72JbXn2OGEv8DgXnk//QKED/8VdKqAzCSr1t1f
3yfwei0AlQKBgD19KU66yKg7/+umEP1quUiDmOjUbaSRqFcUe3mQD356m9ffnMob
BdrevxNzTNv/Wc4yKpUryic+x3gu4oQLF/annAbaQHsHejkdANYmpgRvedls6XAw
360Z5K4U1WlmVD8Mrs/QOTOCmdChxad7euZgqLPwat3ujKS2W3oljW1dAoGBAM4/
AB6lsDZLCfnuTxt2h1bHrh5CkAnR5AJ1BC+Ja6/WyvZ4eMOIroumWJKnStr3BgLr
yAxtDSbZddNUljGvIdRnfBEkRXbJlDlVN4rSpMtF4S6bcz7rCUDu/M9g05Qs70j2
IkPJAFzZNUWVzFlKs096uXbqkSQvrUq7ho8DqAThAoGBAL7Nrbr5LWcBgvwEhEla
VRfYb0FUrDwLIrVWntJjW566/pVQQ4BmatsblLjlQYWk9MCIYXWZbnB+2fRx9yjQ
Adggez7Dws/Mrh/wVudKgayHCy5Lgd8rYjNgC+VZf8XGrWX3QXMJ6UWAyQLTeoO7
hToW9o9CQMIhaR43G8di1kjF
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
		std::cout << "Listening for TLS traffic on 6695-6699\n";

		if (serv.bind(6665, &serv.srv)
			&& serv.bind(6666, &serv.srv)
			&& serv.bind(6667, &serv.srv)
			&& serv.bind(6668, &serv.srv)
			&& serv.bind(6669, &serv.srv)
			)
		{
			std::cout << "Listening for unencrypted traffic on 6665-6669\n";
		}
		else
		{
			std::cout << "Failed to bind to ports 6665-6669, won't be listening for unencrypted traffic\n";
		}

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

		netConfig::get().dns_resolver = soup::make_shared<dnsOsResolver>();

#ifdef DOCKER
		// Ctrl+C not killing your software? According to the professional ChatGPTs hired by Docker Inc, it's not an issue. Why? Because there's a workaround!
		signal(SIGTERM, [](int) { exit(0); });
#endif

		serv.run();
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}
}
