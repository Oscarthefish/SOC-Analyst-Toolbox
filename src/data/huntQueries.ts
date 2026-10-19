/**
 * Hunting query templates for Microsoft Sentinel / Defender XDR (KQL) and Splunk (SPL).
 *
 * Two kinds:
 *  - indicator sweeps (`ioc` set): where has this indicator appeared in our logs?
 *  - technique hunts (no `ioc`): is this behaviour happening anywhere, regardless of indicator?
 *
 * Placeholders (filled by lib/hunting.ts):
 *   {{iocs}}        KQL dynamic([...]) / SPL "a", "b"
 *   {{hosts}}       hostnames taken from URL indicators, same formats
 *   {{iocsSuffix}}  SPL "*a", "*b"        (domain and its subdomains)
 *   {{iocsLike}}    SPL "*a*", "*b*"      (anywhere in the field)
 *   {{iocsAt}}      SPL "*@a", "*@b"      (any address at the domain)
 *   {{iocsTerms}}   SPL "a" OR "b"        (raw term search)
 *   {{hashField}}   KQL SHA256 / SHA1 / MD5
 *   {{time}}        KQL TimeGenerated (Sentinel) or Timestamp (Defender XDR)
 *   {{lookback}}    KQL 24h / 7d / 30d / 90d
 *   {{earliest}}    SPL -24h / -7d / -30d / -90d
 *   {{idx:<source>}} SPL base search for a data source, set on the Hunt page
 *
 * KQL follows the Sentinel-Queries conventions (time filter first, then where,
 * summarize … by, sort). SPL uses CIM field names so it works across vendors once
 * the data is CIM-mapped.
 */

export type Platform = 'sentinel' | 'defender' | 'splunk';
export type IocKind = 'ip' | 'domain' | 'url' | 'hash' | 'email';
export type SplunkSource = 'network' | 'web' | 'dns' | 'email' | 'endpoint' | 'auth' | 'o365';

export interface HuntTemplate {
  id: string;
  title: string;
  /** Indicator sweeps only: which kind of indicator the query takes */
  ioc?: IocKind;
  /** Hash sweeps only: restrict to these hash types when the table lacks the others */
  hashTypes?: ('md5' | 'sha1' | 'sha256')[];
  techniques: string[];
  platforms: Platform[];
  /** Table or data source the query needs */
  source: string;
  query: string;
  /** What to look for in the results */
  lookFor: string;
}

const KQL: Platform[] = ['sentinel', 'defender'];
const SENTINEL: Platform[] = ['sentinel'];
const DEFENDER: Platform[] = ['defender'];
const SPL: Platform[] = ['splunk'];

const q = (s: string) => s.trim();

export const HUNT_TEMPLATES: HuntTemplate[] = [
  // ══ Indicator sweeps — KQL ═════════════════════════════════════════════

  {
    id: 'kql-ip-device-network', title: 'Device connections to or from the IP', ioc: 'ip',
    techniques: ['T1071', 'T1041'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
let iocs = {{iocs}};
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemoteIP in (iocs) or LocalIP in (iocs)
| summarize Connections = count(), FirstSeen = min({{time}}), LastSeen = max({{time}}),
    Ports = make_set(RemotePort, 20), Processes = make_set(InitiatingProcessFileName, 20), Actions = make_set(ActionType, 10)
    by DeviceName, RemoteIP
| sort by Connections desc`),
    lookFor: 'Which devices talked to the address, from which process and on which ports. Browser traffic to a scanner is usually noise; scripting engines, LOLBins or unsigned binaries are not.',
  },
  {
    id: 'kql-ip-signin', title: 'Entra ID sign-ins from the IP', ioc: 'ip',
    techniques: ['T1078', 'T1110'], platforms: SENTINEL, source: 'SigninLogs (Entra ID)',
    query: q(`
let iocs = {{iocs}};
SigninLogs
| where {{time}} > ago({{lookback}})
| where IPAddress in (iocs)
| summarize Attempts = count(), Succeeded = countif(ResultType == "0"), Failed = countif(ResultType != "0"),
    Users = make_set(UserPrincipalName, 50), Apps = make_set(AppDisplayName, 20), Results = make_set(ResultType, 20)
    by IPAddress`),
    lookFor: 'Any successful sign-in from a flagged address is a priority. Many users with failures points to spraying; one user with many failures to brute force.',
  },
  {
    id: 'kql-ip-signin-xdr', title: 'Entra ID sign-ins from the IP', ioc: 'ip',
    techniques: ['T1078', 'T1110'], platforms: DEFENDER, source: 'AADSignInEventsBeta (EntraIdSignInEvents in newer tenants)',
    query: q(`
let iocs = {{iocs}};
AADSignInEventsBeta
| where {{time}} > ago({{lookback}})
| where IPAddress in (iocs)
| summarize Attempts = count(), Succeeded = countif(ErrorCode == 0), Failed = countif(ErrorCode != 0),
    Users = make_set(AccountUpn, 50), Apps = make_set(Application, 20)
    by IPAddress`),
    lookFor: 'Any successful sign-in from a flagged address is a priority. Many users with failures points to spraying; one user with many failures to brute force.',
  },
  {
    id: 'kql-ip-logon', title: 'Logons to devices from the IP', ioc: 'ip',
    techniques: ['T1110', 'T1021', 'T1078'], platforms: KQL, source: 'DeviceLogonEvents (Defender for Endpoint)',
    query: q(`
let iocs = {{iocs}};
DeviceLogonEvents
| where {{time}} > ago({{lookback}})
| where RemoteIP in (iocs)
| summarize Attempts = count(), Succeeded = countif(ActionType == "LogonSuccess"), Failed = countif(ActionType == "LogonFailed"),
    Accounts = make_set(AccountName, 50), LogonTypes = make_set(LogonType, 10)
    by DeviceName, RemoteIP
| sort by Succeeded desc, Attempts desc`),
    lookFor: 'Successful RemoteInteractive (RDP) or Network logons from the address. Check the accounts used and whether the device is internet-facing.',
  },
  {
    id: 'kql-ip-cef', title: 'Firewall and proxy events for the IP', ioc: 'ip',
    techniques: ['T1071', 'T1595'], platforms: SENTINEL, source: 'CommonSecurityLog (CEF firewalls and proxies)',
    query: q(`
let iocs = {{iocs}};
CommonSecurityLog
| where {{time}} > ago({{lookback}})
| where SourceIP in (iocs) or DestinationIP in (iocs)
| summarize Events = count(), FirstSeen = min({{time}}), LastSeen = max({{time}}),
    Ports = make_set(DestinationPort, 20), Actions = make_set(DeviceAction, 10)
    by DeviceVendor, DeviceProduct, SourceIP, DestinationIP
| sort by Events desc`),
    lookFor: 'Allowed traffic is what matters. Inbound-only denies from a scanner rarely need action; outbound allowed connections from internal hosts do.',
  },
  {
    id: 'kql-domain-device-network', title: 'Device connections to the domain', ioc: 'domain',
    techniques: ['T1071.001'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
let iocs = {{iocs}};
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemoteUrl has_any (iocs)
| summarize Connections = count(), FirstSeen = min({{time}}), LastSeen = max({{time}}),
    RemoteIPs = make_set(RemoteIP, 20), Processes = make_set(InitiatingProcessFileName, 20)
    by DeviceName, RemoteUrl
| sort by Connections desc`),
    lookFor: 'Devices that reached the domain and the process responsible. Repeated connections from a non-browser process suggest command and control.',
  },
  {
    id: 'kql-domain-dns', title: 'DNS lookups for the domain', ioc: 'domain',
    techniques: ['T1071.004', 'T1568'], platforms: SENTINEL, source: 'DnsEvents (Windows DNS via AMA)',
    query: q(`
let iocs = {{iocs}};
DnsEvents
| where {{time}} > ago({{lookback}})
| where SubType == "LookupQuery" and Name has_any (iocs)
| summarize Queries = count(), FirstSeen = min({{time}}), LastSeen = max({{time}}), Answers = make_set(IPAddresses, 20)
    by ClientIP, Name
| sort by Queries desc`),
    lookFor: 'Clients that resolved the domain, even if the connection was later blocked. Subdomains you did not expect can reveal more infrastructure.',
  },
  {
    id: 'kql-domain-email-sender', title: 'Email from the domain', ioc: 'domain',
    techniques: ['T1566'], platforms: KQL, source: 'EmailEvents (Defender for Office 365)',
    query: q(`
let iocs = {{iocs}};
EmailEvents
| where {{time}} > ago({{lookback}})
| where SenderFromDomain in~ (iocs) or SenderMailFromDomain in~ (iocs)
| summarize Emails = count(), Recipients = dcount(RecipientEmailAddress), Delivered = countif(DeliveryAction == "Delivered"),
    Subjects = make_set(Subject, 10), Senders = make_set(SenderFromAddress, 10)
    by SenderFromDomain`),
    lookFor: 'Delivered messages and who received them. Reuse the recipient list to scope clicks, replies and sign-ins.',
  },
  {
    id: 'kql-domain-email-urls', title: 'Emails containing links to the domain', ioc: 'domain',
    techniques: ['T1566.002'], platforms: KQL, source: 'EmailUrlInfo + EmailEvents (Defender for Office 365)',
    query: q(`
let iocs = {{iocs}};
EmailUrlInfo
| where {{time}} > ago({{lookback}})
| where UrlDomain in~ (iocs)
| join kind=inner (EmailEvents | where {{time}} > ago({{lookback}})) on NetworkMessageId
| project {{time}}, RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction, ThreatTypes
| sort by {{time}} desc`),
    lookFor: 'Messages that were delivered with the link. Check whether ZAP removed them and whether anyone clicked (next query).',
  },
  {
    id: 'kql-domain-clicks', title: 'Link clicks to the domain', ioc: 'domain',
    techniques: ['T1204.001'], platforms: KQL, source: 'UrlClickEvents (Safe Links)',
    query: q(`
let iocs = {{iocs}};
UrlClickEvents
| where {{time}} > ago({{lookback}})
| where Url has_any (iocs)
| project {{time}}, AccountUpn, Url, ActionType, IsClickedThrough, Workload, IPAddress
| sort by {{time}} desc`),
    lookFor: 'ClickAllowed or IsClickedThrough = true means the user reached the page. Follow up with their sign-ins and devices.',
  },
  {
    id: 'kql-domain-cef', title: 'Proxy and firewall events for the domain', ioc: 'domain',
    techniques: ['T1071.001'], platforms: SENTINEL, source: 'CommonSecurityLog (CEF proxies)',
    query: q(`
let iocs = {{iocs}};
CommonSecurityLog
| where {{time}} > ago({{lookback}})
| where DestinationHostName has_any (iocs) or RequestURL has_any (iocs)
| summarize Requests = count(), Users = make_set(SourceUserName, 20), Sources = make_set(SourceIP, 20), Actions = make_set(DeviceAction, 10)
    by DeviceProduct, DestinationHostName
| sort by Requests desc`),
    lookFor: 'Allowed requests and the users behind them. Blocked-only results show the control worked but still identify exposed users.',
  },
  {
    id: 'kql-url-email', title: 'Emails containing the URL', ioc: 'url',
    techniques: ['T1566.002'], platforms: KQL, source: 'EmailUrlInfo + EmailEvents (Defender for Office 365)',
    query: q(`
let iocs = {{iocs}};
EmailUrlInfo
| where {{time}} > ago({{lookback}})
| where Url in~ (iocs)
| join kind=inner (EmailEvents | where {{time}} > ago({{lookback}})) on NetworkMessageId
| project {{time}}, RecipientEmailAddress, SenderFromAddress, Subject, Url, DeliveryAction, ThreatTypes
| sort by {{time}} desc`),
    lookFor: 'Every recipient of the exact link. Search by the host instead if the attacker varies the path per recipient.',
  },
  {
    id: 'kql-url-clicks', title: 'Clicks on the URL', ioc: 'url',
    techniques: ['T1204.001'], platforms: KQL, source: 'UrlClickEvents (Safe Links)',
    query: q(`
let iocs = {{iocs}};
UrlClickEvents
| where {{time}} > ago({{lookback}})
| where Url in~ (iocs)
| project {{time}}, AccountUpn, Url, ActionType, IsClickedThrough, Workload, IPAddress
| sort by {{time}} desc`),
    lookFor: 'Users who reached the page. For credential phishing, check their sign-ins straight after the click.',
  },
  {
    id: 'kql-url-device-network', title: 'Device connections to the URL’s host', ioc: 'url',
    techniques: ['T1071.001'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
let hosts = {{hosts}};
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemoteUrl has_any (hosts)
| summarize Connections = count(), FirstSeen = min({{time}}), LastSeen = max({{time}}), Processes = make_set(InitiatingProcessFileName, 20)
    by DeviceName, RemoteUrl
| sort by Connections desc`),
    lookFor: 'Devices that reached the host, which catches visits from outside email (chat, documents, typed URLs).',
  },
  {
    id: 'kql-hash-files', title: 'Files with the hash on devices', ioc: 'hash',
    techniques: ['T1204.002', 'T1105'], platforms: KQL, source: 'DeviceFileEvents (Defender for Endpoint)',
    query: q(`
let iocs = {{iocs}};
DeviceFileEvents
| where {{time}} > ago({{lookback}})
| where {{hashField}} in~ (iocs)
| summarize Events = count(), FirstSeen = min({{time}}), LastSeen = max({{time}}),
    Paths = make_set(FolderPath, 20), Creators = make_set(InitiatingProcessFileName, 20)
    by DeviceName, FileName
| sort by FirstSeen asc`),
    lookFor: 'Where the file landed first and what wrote it (browser, mail client, archive tool). That process usually points to the delivery route.',
  },
  {
    id: 'kql-hash-process', title: 'Processes started from the hash', ioc: 'hash',
    techniques: ['T1204.002', 'T1059'], platforms: KQL, source: 'DeviceProcessEvents (Defender for Endpoint)',
    query: q(`
let iocs = {{iocs}};
DeviceProcessEvents
| where {{time}} > ago({{lookback}})
| where {{hashField}} in~ (iocs) or InitiatingProcess{{hashField}} in~ (iocs)
| project {{time}}, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by {{time}} asc`),
    lookFor: 'Execution, not just presence. Child processes and command lines show what the sample did next.',
  },
  {
    id: 'kql-hash-email', title: 'Email attachments with the hash', ioc: 'hash', hashTypes: ['sha256'],
    techniques: ['T1566.001'], platforms: KQL, source: 'EmailAttachmentInfo + EmailEvents (Defender for Office 365)',
    query: q(`
let iocs = {{iocs}};
EmailAttachmentInfo
| where {{time}} > ago({{lookback}})
| where SHA256 in~ (iocs)
| join kind=inner (EmailEvents | where {{time}} > ago({{lookback}})) on NetworkMessageId
| project {{time}}, RecipientEmailAddress, SenderFromAddress, Subject, FileName, DeliveryAction, DeliveryLocation
| sort by {{time}} desc`),
    lookFor: 'Recipients of the attachment and whether it was delivered to the inbox. Pair with the file query to see who opened it.',
  },
  {
    id: 'kql-email-messages', title: 'Mail sent from or to the address', ioc: 'email',
    techniques: ['T1566'], platforms: KQL, source: 'EmailEvents (Defender for Office 365)',
    query: q(`
let iocs = {{iocs}};
EmailEvents
| where {{time}} > ago({{lookback}})
| where SenderFromAddress in~ (iocs) or SenderMailFromAddress in~ (iocs) or RecipientEmailAddress in~ (iocs)
| project {{time}}, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, ThreatTypes, NetworkMessageId
| sort by {{time}} desc`),
    lookFor: 'Delivered messages, their subjects and who received them. A mismatch between From and MailFrom is worth a closer look.',
  },
  {
    id: 'kql-email-signins', title: 'Sign-ins by the account', ioc: 'email',
    techniques: ['T1078', 'T1078.004'], platforms: SENTINEL, source: 'SigninLogs (Entra ID)',
    query: q(`
let iocs = {{iocs}};
SigninLogs
| where {{time}} > ago({{lookback}})
| where UserPrincipalName in~ (iocs)
| summarize Attempts = count(), Succeeded = countif(ResultType == "0"),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 20), IPs = make_set(IPAddress, 50), Apps = make_set(AppDisplayName, 20)
    by UserPrincipalName`),
    lookFor: 'Countries, IPs and apps that do not fit the user. For exposed credentials, check for successful sign-ins after the exposure date.',
  },

  // ══ Indicator sweeps — SPL ═════════════════════════════════════════════

  {
    id: 'spl-ip-network', title: 'Network traffic to or from the IP', ioc: 'ip',
    techniques: ['T1071', 'T1041'], platforms: SPL, source: 'CIM Network_Traffic',
    query: q(`
{{idx:network}} earliest={{earliest}} (src_ip IN ({{iocs}}) OR dest_ip IN ({{iocs}}))
| stats count AS events, min(_time) AS first_seen, max(_time) AS last_seen, values(dest_port) AS ports, values(action) AS actions by src_ip, dest_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - events`),
    lookFor: 'Allowed outbound connections from internal hosts. Inbound-only blocked traffic from a scanner rarely needs action.',
  },
  {
    id: 'spl-ip-web', title: 'Web proxy requests involving the IP', ioc: 'ip',
    techniques: ['T1071.001'], platforms: SPL, source: 'CIM Web',
    query: q(`
{{idx:web}} earliest={{earliest}} (src IN ({{iocs}}) OR dest IN ({{iocs}}))
| stats count AS requests, values(url) AS urls, values(http_user_agent) AS user_agents, values(status) AS statuses by src, dest, user
| sort - requests`),
    lookFor: 'Direct-to-IP web requests are unusual for normal browsing. Note the user agent and which users were involved.',
  },
  {
    id: 'spl-ip-auth', title: 'Authentication from the IP', ioc: 'ip',
    techniques: ['T1078', 'T1110'], platforms: SPL, source: 'CIM Authentication',
    query: q(`
{{idx:auth}} earliest={{earliest}} src IN ({{iocs}})
| stats count(eval(action="success")) AS succeeded, count(eval(action="failure")) AS failed, values(user) AS users, values(app) AS apps by src
| sort - succeeded`),
    lookFor: 'Any success from a flagged address. Failures across many users suggest spraying.',
  },
  {
    id: 'spl-domain-dns', title: 'DNS lookups for the domain', ioc: 'domain',
    techniques: ['T1071.004', 'T1568'], platforms: SPL, source: 'CIM Network_Resolution',
    query: q(`
{{idx:dns}} earliest={{earliest}} query IN ({{iocsSuffix}})
| stats count AS lookups, min(_time) AS first_seen, max(_time) AS last_seen, values(answer) AS answers by src, query
| convert ctime(first_seen) ctime(last_seen)
| sort - lookups`),
    lookFor: 'Internal clients that resolved the domain or its subdomains, even where the connection was blocked later.',
  },
  {
    id: 'spl-domain-web', title: 'Web requests to the domain', ioc: 'domain',
    techniques: ['T1071.001'], platforms: SPL, source: 'CIM Web',
    query: q(`
{{idx:web}} earliest={{earliest}} (dest IN ({{iocsSuffix}}) OR url IN ({{iocsLike}}))
| stats count AS requests, values(user) AS users, values(http_method) AS methods, values(action) AS actions by src, dest
| sort - requests`),
    lookFor: 'Allowed requests and the users behind them. POSTs to a phishing domain suggest credentials were submitted.',
  },
  {
    id: 'spl-domain-email', title: 'Email from the domain', ioc: 'domain',
    techniques: ['T1566'], platforms: SPL, source: 'CIM Email',
    query: q(`
{{idx:email}} earliest={{earliest}} src_user IN ({{iocsAt}})
| stats count AS messages, dc(recipient) AS recipients, values(subject) AS subjects, values(action) AS actions by src_user
| sort - messages`),
    lookFor: 'Delivered messages and how many people received them.',
  },
  {
    id: 'spl-url-web', title: 'Web requests for the URL', ioc: 'url',
    techniques: ['T1204.001', 'T1071.001'], platforms: SPL, source: 'CIM Web',
    query: q(`
{{idx:web}} earliest={{earliest}} (url IN ({{iocs}}) OR dest IN ({{hosts}}))
| stats count AS requests, values(url) AS urls, values(http_method) AS methods, values(action) AS actions by src, user, dest
| sort - requests`),
    lookFor: 'Users who requested the URL or its host. A POST after a GET on a phishing page usually means credentials were entered.',
  },
  {
    id: 'spl-hash-endpoint', title: 'Endpoint events containing the hash', ioc: 'hash',
    techniques: ['T1204.002', 'T1105'], platforms: SPL, source: 'Endpoint process and file events (EDR, Sysmon)',
    query: q(`
{{idx:endpoint}} earliest={{earliest}} ({{iocsTerms}})
| stats count AS events, min(_time) AS first_seen, max(_time) AS last_seen, values(process_name) AS processes, values(parent_process_name) AS parents by dest, sourcetype
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen`),
    lookFor: 'A raw term search, so it matches hash fields however your EDR names them (Sysmon puts them in Hashes). First host and parent process show how it arrived.',
  },
  {
    id: 'spl-hash-email', title: 'Email attachments with the hash', ioc: 'hash',
    techniques: ['T1566.001'], platforms: SPL, source: 'CIM Email',
    query: q(`
{{idx:email}} earliest={{earliest}} file_hash IN ({{iocs}})
| stats count AS messages, values(file_name) AS files, values(subject) AS subjects, values(action) AS actions by src_user, recipient`),
    lookFor: 'Recipients of the attachment and whether it was delivered.',
  },
  {
    id: 'spl-email-messages', title: 'Mail sent from or to the address', ioc: 'email',
    techniques: ['T1566'], platforms: SPL, source: 'CIM Email',
    query: q(`
{{idx:email}} earliest={{earliest}} (src_user IN ({{iocs}}) OR recipient IN ({{iocs}}))
| table _time, src_user, recipient, subject, action, file_name
| sort - _time`),
    lookFor: 'Delivered messages and their subjects; reuse recipients to scope follow-up searches.',
  },
  {
    id: 'spl-email-auth', title: 'Authentication by the account', ioc: 'email',
    techniques: ['T1078'], platforms: SPL, source: 'CIM Authentication',
    query: q(`
{{idx:auth}} earliest={{earliest}} user IN ({{iocs}})
| iplocation src
| stats count(eval(action="success")) AS succeeded, count(eval(action="failure")) AS failed, values(src) AS sources, values(Country) AS countries by user`),
    lookFor: 'Unexpected countries or sources, especially successes after a known exposure date.',
  },

  // ══ Technique hunts — KQL ══════════════════════════════════════════════

  {
    id: 'kql-t1110-signin', title: 'Failures followed by success from the same IP',
    techniques: ['T1110', 'T1110.001'], platforms: SENTINEL, source: 'SigninLogs (Entra ID)',
    query: q(`
SigninLogs
| where {{time}} > ago({{lookback}})
| summarize Failed = countif(ResultType != "0"), Succeeded = countif(ResultType == "0"), Users = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName, 20)
    by IPAddress
| where Failed >= 20 and Succeeded > 0
| sort by Failed desc`),
    lookFor: 'Addresses that eventually got in after many failures. Tune the threshold to your tenant’s normal failure rate.',
  },
  {
    id: 'kql-t1110-device', title: 'Brute force against devices from the internet',
    techniques: ['T1110', 'T1021'], platforms: KQL, source: 'DeviceLogonEvents (Defender for Endpoint)',
    query: q(`
DeviceLogonEvents
| where {{time}} > ago({{lookback}})
| where RemoteIPType == "Public"
| summarize Failed = countif(ActionType == "LogonFailed"), Succeeded = countif(ActionType == "LogonSuccess"), Accounts = dcount(AccountName)
    by DeviceName, RemoteIP
| where Failed >= 20
| sort by Succeeded desc, Failed desc`),
    lookFor: 'Internet-exposed devices taking failed logons, and any success from the same address.',
  },
  {
    id: 'kql-t1110-spray', title: 'Password spraying (one IP, many users)',
    techniques: ['T1110.003'], platforms: SENTINEL, source: 'SigninLogs (Entra ID)',
    query: q(`
SigninLogs
| where {{time}} > ago({{lookback}})
| where ResultType == "50126"
| summarize Users = dcount(UserPrincipalName), Attempts = count(), Sample = make_set(UserPrincipalName, 20) by IPAddress
| where Users >= 10
| sort by Users desc`),
    lookFor: 'ResultType 50126 is a bad username or password. Many distinct users from one address is spraying; check those users for any later success.',
  },
  {
    id: 'kql-t1090-tor-signin', title: 'Sign-ins from Tor exit nodes',
    techniques: ['T1090.003', 'T1078'], platforms: SENTINEL, source: 'SigninLogs + Tor bulk exit list',
    query: q(`
let TorExits = externaldata (IPAddress: string) [@"https://check.torproject.org/torbulkexitlist"] with (format="txt");
SigninLogs
| where {{time}} > ago({{lookback}})
| where IPAddress in (TorExits)
| summarize Attempts = count(), Succeeded = countif(ResultType == "0"), Users = make_set(UserPrincipalName, 50) by IPAddress`),
    lookFor: 'Successful sign-ins over Tor are rarely legitimate for corporate accounts. The exit list is fetched live, so it reflects current exits only.',
  },
  {
    id: 'kql-t1090-tor-device', title: 'Device connections to Tor exit nodes',
    techniques: ['T1090.003'], platforms: KQL, source: 'DeviceNetworkEvents + Tor bulk exit list',
    query: q(`
let TorExits = externaldata (IP: string) [@"https://check.torproject.org/torbulkexitlist"] with (format="txt");
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemoteIP in (TorExits)
| summarize Connections = count(), Processes = make_set(InitiatingProcessFileName, 20) by DeviceName, RemoteIP
| sort by Connections desc`),
    lookFor: 'Outbound connections to exits suggest a Tor client or proxy on the device. Inbound from exits is usually scanning.',
  },
  {
    id: 'kql-t1071-beacon', title: 'Regular outbound connections (beaconing)',
    techniques: ['T1071', 'T1071.001', 'T1573'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
DeviceNetworkEvents
| where {{time}} > ago(1d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("msedge.exe", "chrome.exe", "firefox.exe", "OneDrive.exe", "Teams.exe", "ms-teams.exe", "svchost.exe")
| summarize HoursActive = dcount(bin({{time}}, 1h)), Connections = count() by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where HoursActive >= 20
| sort by HoursActive desc, Connections desc`),
    lookFor: 'A process talking to the same address in at least 20 of the last 24 hours. Fixed to one day; add your own allow-list for agents and updaters.',
  },
  {
    id: 'kql-t1571-ports', title: 'Scripting engines using non-standard ports',
    techniques: ['T1571', 'T1059'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| where RemotePort !in (80, 443, 53)
| summarize Connections = count(), Ports = make_set(RemotePort, 20) by DeviceName, InitiatingProcessFileName, RemoteIP
| sort by Connections desc`),
    lookFor: 'LOLBins connecting out on unusual ports. Enrich each RemoteIP back in Investigate.',
  },
  {
    id: 'kql-t1105-download', title: 'Download cradles and transfer tools',
    techniques: ['T1105', 'T1059.001'], platforms: KQL, source: 'DeviceProcessEvents (Defender for Endpoint)',
    query: q(`
DeviceProcessEvents
| where {{time}} > ago({{lookback}})
| where (FileName =~ "certutil.exe" and ProcessCommandLine has "urlcache")
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "transfer")
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Invoke-WebRequest", "Start-BitsTransfer"))
    or (FileName in~ ("curl.exe", "wget.exe") and ProcessCommandLine has "http")
| project {{time}}, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by {{time}} desc`),
    lookFor: 'Downloads launched by Office apps, script hosts or unusual parents. The URLs in the command lines are new indicators to investigate.',
  },
  {
    id: 'kql-t1059-encoded', title: 'Encoded or obfuscated PowerShell',
    techniques: ['T1059.001', 'T1027'], platforms: KQL, source: 'DeviceProcessEvents (Defender for Endpoint)',
    query: q(`
DeviceProcessEvents
| where {{time}} > ago({{lookback}})
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-EncodedCommand" or ProcessCommandLine contains "FromBase64String"
| project {{time}}, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by {{time}} desc`),
    lookFor: 'Decode the payload. Encoded commands from management tools are common; from Office, browsers or script hosts they are not.',
  },
  {
    id: 'kql-t1566-attachments', title: 'Risky attachment types delivered',
    techniques: ['T1566.001', 'T1204.002'], platforms: KQL, source: 'EmailAttachmentInfo + EmailEvents (Defender for Office 365)',
    query: q(`
EmailAttachmentInfo
| where {{time}} > ago({{lookback}})
| where FileType in~ ("iso", "img", "vhd", "vhdx", "lnk", "hta", "js", "vbs", "wsf", "one", "html", "htm")
| join kind=inner (EmailEvents | where {{time}} > ago({{lookback}}) | where DeliveryAction == "Delivered") on NetworkMessageId
| project {{time}}, RecipientEmailAddress, SenderFromAddress, Subject, FileName, FileType, SHA256
| sort by {{time}} desc`),
    lookFor: 'Container and script attachments that reached inboxes. Feed the SHA256 values back into Investigate.',
  },
  {
    id: 'kql-t1566-clickthrough', title: 'Users who clicked through a Safe Links warning',
    techniques: ['T1566.002', 'T1204.001'], platforms: KQL, source: 'UrlClickEvents (Safe Links)',
    query: q(`
UrlClickEvents
| where {{time}} > ago({{lookback}})
| where IsClickedThrough == true
| project {{time}}, AccountUpn, Url, ActionType, Workload, IPAddress
| sort by {{time}} desc`),
    lookFor: 'Users who were warned and continued anyway. Check their sign-ins and devices for the following hour.',
  },
  {
    id: 'kql-t1114-forwarding', title: 'Inbox rules that forward or redirect mail',
    techniques: ['T1114.003'], platforms: SENTINEL, source: 'OfficeActivity (Exchange)',
    query: q(`
OfficeActivity
| where {{time}} > ago({{lookback}})
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project {{time}}, UserId, ClientIP, Operation, Parameters
| sort by {{time}} desc`),
    lookFor: 'Forwarding to external addresses, often with rules that also move or delete the message. A classic sign of mailbox compromise.',
  },
  {
    id: 'kql-t1114-forwarding-xdr', title: 'Inbox rules that forward or redirect mail',
    techniques: ['T1114.003'], platforms: DEFENDER, source: 'CloudAppEvents (Defender for Cloud Apps)',
    query: q(`
CloudAppEvents
| where {{time}} > ago({{lookback}})
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| where RawEventData has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project {{time}}, AccountDisplayName, IPAddress, ActionType, RawEventData
| sort by {{time}} desc`),
    lookFor: 'Forwarding to external addresses, often with rules that also move or delete the message.',
  },
  {
    id: 'kql-t1078-risky', title: 'Successful sign-ins flagged as risky',
    techniques: ['T1078', 'T1078.004'], platforms: SENTINEL, source: 'SigninLogs (Entra ID Protection)',
    query: q(`
SigninLogs
| where {{time}} > ago({{lookback}})
| where ResultType == "0" and RiskLevelDuringSignIn in ("medium", "high")
| project {{time}}, UserPrincipalName, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, RiskDetail
| sort by {{time}} desc`),
    lookFor: 'Risky sign-ins that still succeeded. Enrich the IP addresses and check for new MFA methods or inbox rules afterwards.',
  },
  {
    id: 'kql-t1098-roles', title: 'Privileged role and app permission changes',
    techniques: ['T1098'], platforms: SENTINEL, source: 'AuditLogs (Entra ID)',
    query: q(`
AuditLogs
| where {{time}} > ago({{lookback}})
| where OperationName in ("Add member to role", "Add eligible member to role", "Add app role assignment to service principal", "Add owner to application", "Add delegated permission grant")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName)
| project {{time}}, OperationName, Actor, Target, Result
| sort by {{time}} desc`),
    lookFor: 'Changes made by accounts that do not normally administer roles, or straight after a risky sign-in.',
  },
  {
    id: 'kql-t1505-webshell', title: 'Web server processes spawning shells',
    techniques: ['T1505.003', 'T1190'], platforms: KQL, source: 'DeviceProcessEvents (Defender for Endpoint)',
    query: q(`
DeviceProcessEvents
| where {{time}} > ago({{lookback}})
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "php-cgi.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "certutil.exe", "bitsadmin.exe")
| project {{time}}, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| sort by {{time}} desc`),
    lookFor: 'Shells under a web server are a strong sign of a web shell or exploitation. Find the request that triggered it in the web logs.',
  },
  {
    id: 'kql-t1190-waf', title: 'WAF hits by client',
    techniques: ['T1190', 'T1595.002'], platforms: SENTINEL, source: 'AzureDiagnostics (Application Gateway WAF)',
    query: q(`
AzureDiagnostics
| where {{time}} > ago({{lookback}})
| where Category == "ApplicationGatewayFirewallLog" and action_s in ("Blocked", "Matched")
| summarize Hits = count(), Rules = make_set(ruleId_s, 20), Uris = make_set(requestUri_s, 20) by clientIp_s
| sort by Hits desc`),
    lookFor: 'Clients probing many rules. Matched but not blocked requests need checking against the application’s own logs.',
  },
  {
    id: 'kql-t1490-recovery', title: 'Shadow copy and backup deletion',
    techniques: ['T1490', 'T1486'], platforms: KQL, source: 'DeviceProcessEvents (Defender for Endpoint)',
    query: q(`
DeviceProcessEvents
| where {{time}} > ago({{lookback}})
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has "shadows")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine contains "delete")
    or (FileName =~ "bcdedit.exe" and (ProcessCommandLine contains "recoveryenabled" or ProcessCommandLine contains "ignoreallfailures"))
| project {{time}}, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by {{time}} desc`),
    lookFor: 'A common ransomware precursor. Treat any hit outside a known backup job as urgent.',
  },
  {
    id: 'kql-t1486-renames', title: 'Bursts of file renames on a device',
    techniques: ['T1486'], platforms: KQL, source: 'DeviceFileEvents (Defender for Endpoint)',
    query: q(`
DeviceFileEvents
| where {{time}} > ago({{lookback}})
| where ActionType == "FileRenamed"
| summarize Renamed = count(), Extensions = make_set(tostring(split(FileName, ".")[-1]), 10)
    by DeviceName, InitiatingProcessFileName, bin({{time}}, 5m)
| where Renamed > 200
| sort by Renamed desc`),
    lookFor: 'Hundreds of renames in five minutes, especially to a single new extension, from one process.',
  },
  {
    id: 'kql-t1595-scan', title: 'Sources scanning many ports or hosts',
    techniques: ['T1595', 'T1595.001'], platforms: SENTINEL, source: 'CommonSecurityLog (CEF firewalls)',
    query: q(`
CommonSecurityLog
| where {{time}} > ago({{lookback}})
| where DeviceAction in~ ("deny", "drop", "block", "blocked", "reset-both")
| summarize Ports = dcount(DestinationPort), Targets = dcount(DestinationIP), Events = count() by SourceIP
| where Ports >= 20 or Targets >= 50
| sort by Ports desc`),
    lookFor: 'Mostly internet noise. What matters is whether the same sources later got an allowed connection.',
  },
  {
    id: 'kql-t1046-internal', title: 'Internal hosts scanning the network',
    techniques: ['T1046'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemoteIPType == "Private"
| summarize Ports = dcount(RemotePort), Hosts = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin({{time}}, 1h)
| where Ports >= 50 or Hosts >= 100
| sort by Ports desc`),
    lookFor: 'A workstation reaching many internal hosts or ports in an hour. Exclude vulnerability scanners and management servers.',
  },
  {
    id: 'kql-t1021-rdp', title: 'RDP logons from public addresses',
    techniques: ['T1021.001', 'T1133'], platforms: KQL, source: 'DeviceLogonEvents (Defender for Endpoint)',
    query: q(`
DeviceLogonEvents
| where {{time}} > ago({{lookback}})
| where LogonType == "RemoteInteractive" and RemoteIPType == "Public"
| summarize Logons = count(), Accounts = make_set(AccountName, 20), Results = make_set(ActionType, 5) by DeviceName, RemoteIP
| sort by Logons desc`),
    lookFor: 'RDP exposed directly to the internet. Successful logons here need an owner and a reason.',
  },
  {
    id: 'kql-t1021-ssh', title: 'SSH failures and successes by source',
    techniques: ['T1021.004', 'T1110'], platforms: SENTINEL, source: 'Syslog (auth / authpriv)',
    query: q(`
Syslog
| where {{time}} > ago({{lookback}})
| where Facility in ("auth", "authpriv") and SyslogMessage has_any ("Failed password", "Accepted password", "Accepted publickey")
| extend SourceIP = extract(@"from\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})", 1, SyslogMessage), Outcome = iff(SyslogMessage has "Accepted", "Accepted", "Failed")
| summarize Failed = countif(Outcome == "Failed"), Accepted = countif(Outcome == "Accepted") by Computer, SourceIP
| where Failed >= 10
| sort by Accepted desc, Failed desc`),
    lookFor: 'Sources that failed repeatedly and then got in.',
  },
  {
    id: 'kql-t1568-nxdomain', title: 'Clients with many failed DNS lookups',
    techniques: ['T1568.002', 'T1568'], platforms: SENTINEL, source: 'DnsEvents (Windows DNS via AMA)',
    query: q(`
DnsEvents
| where {{time}} > ago({{lookback}})
| where SubType == "LookupQuery" and ResultCode == 3
| summarize FailedLookups = dcount(Name), Sample = make_set(Name, 10) by ClientIP
| where FailedLookups >= 50
| sort by FailedLookups desc`),
    lookFor: 'Many NXDOMAIN answers with random-looking names suggests a DGA. Check the sample names.',
  },
  {
    id: 'kql-t1071-dns-tunnel', title: 'Long or deeply nested DNS names',
    techniques: ['T1071.004', 'T1572'], platforms: SENTINEL, source: 'DnsEvents (Windows DNS via AMA)',
    query: q(`
DnsEvents
| where {{time}} > ago({{lookback}})
| where SubType == "LookupQuery"
| extend Labels = array_length(split(Name, ".")), Length = strlen(Name)
| where Length > 60 or Labels > 6
| extend ParentDomain = strcat_array(array_slice(split(Name, "."), -2, -1), ".")
| summarize Queries = count(), Unique = dcount(Name) by ClientIP, ParentDomain
| where Unique >= 50
| sort by Unique desc`),
    lookFor: 'Many unique long names under one parent domain from one client is typical of DNS tunnelling. CDNs and AV lookups are common false positives.',
  },
  {
    id: 'kql-t1567-cloud', title: 'Connections to file-sharing and paste sites',
    techniques: ['T1567', 'T1567.002'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemoteUrl has_any ("mega.nz", "mega.io", "transfer.sh", "file.io", "gofile.io", "sendspace.com", "pastebin.com", "temp.sh")
| summarize Connections = count(), Urls = make_set(RemoteUrl, 20) by DeviceName, InitiatingProcessFileName
| sort by Connections desc`),
    lookFor: 'Uploads from servers or by command-line tools (rclone, curl) are more concerning than browser use.',
  },
  {
    id: 'kql-t1496-mining', title: 'Connections to mining pools',
    techniques: ['T1496'], platforms: KQL, source: 'DeviceNetworkEvents (Defender for Endpoint)',
    query: q(`
DeviceNetworkEvents
| where {{time}} > ago({{lookback}})
| where RemotePort in (3333, 4444, 5555, 7777, 14444, 45700)
    or RemoteUrl has_any ("nanopool", "minexmr", "2miners", "supportxmr", "moneroocean", "xmrpool")
| summarize Connections = count(), Ports = make_set(RemotePort, 10), Urls = make_set(RemoteUrl, 10) by DeviceName, InitiatingProcessFileName
| sort by Connections desc`),
    lookFor: 'Persistent connections on stratum ports. Port 4444 also overlaps with common reverse shells, so check the process.',
  },

  // ══ Technique hunts — SPL ══════════════════════════════════════════════

  {
    id: 'spl-t1110-auth', title: 'Failures followed by success from the same source',
    techniques: ['T1110', 'T1110.001'], platforms: SPL, source: 'CIM Authentication',
    query: q(`
{{idx:auth}} earliest={{earliest}}
| stats count(eval(action="failure")) AS failed, count(eval(action="success")) AS succeeded, dc(user) AS users by src
| where failed>=20 AND succeeded>0
| sort - failed`),
    lookFor: 'Sources that eventually got in after many failures.',
  },
  {
    id: 'spl-t1110-spray', title: 'Password spraying (one source, many users)',
    techniques: ['T1110.003'], platforms: SPL, source: 'CIM Authentication',
    query: q(`
{{idx:auth}} earliest={{earliest}} action=failure
| stats dc(user) AS users, count AS attempts, values(user) AS sample by src
| where users>=10
| eval sample=mvindex(sample, 0, 19)
| sort - users`),
    lookFor: 'Many distinct users failing from one source. Check those users for later successes.',
  },
  {
    id: 'spl-t1078-countries', title: 'Accounts signing in from several countries',
    techniques: ['T1078', 'T1078.004'], platforms: SPL, source: 'CIM Authentication',
    query: q(`
{{idx:auth}} earliest={{earliest}} action=success
| iplocation src
| stats dc(Country) AS countries, values(Country) AS country_list, values(src) AS sources by user
| where countries>1
| sort - countries`),
    lookFor: 'Accounts with successful logons from more than one country in the window. VPN egress points cause false positives.',
  },
  {
    id: 'spl-t1090-tor', title: 'Traffic to or from Tor exit nodes',
    techniques: ['T1090.003'], platforms: SPL, source: 'CIM Network_Traffic + tor_exit_nodes lookup',
    query: q(`
{{idx:network}} earliest={{earliest}}
| lookup tor_exit_nodes ip AS src_ip OUTPUT ip AS tor_src
| lookup tor_exit_nodes ip AS dest_ip OUTPUT ip AS tor_dest
| where isnotnull(tor_src) OR isnotnull(tor_dest)
| stats count AS events, values(dest_port) AS ports, values(action) AS actions by src_ip, dest_ip`),
    lookFor: 'Needs a lookup named tor_exit_nodes with an ip column, loaded from check.torproject.org/torbulkexitlist. Outbound to exits suggests a Tor client.',
  },
  {
    id: 'spl-t1071-beacon', title: 'Regular outbound connections (beaconing)',
    techniques: ['T1071', 'T1071.001', 'T1573'], platforms: SPL, source: 'CIM Network_Traffic',
    query: q(`
{{idx:network}} earliest=-24h action=allowed
| bin _time span=1h
| stats count by src_ip, dest_ip, dest_port, _time
| stats dc(_time) AS hours_active, sum(count) AS connections by src_ip, dest_ip, dest_port
| where hours_active>=20
| sort - hours_active`),
    lookFor: 'A host talking to the same destination in at least 20 of the last 24 hours. Fixed to one day; allow-list update and monitoring services.',
  },
  {
    id: 'spl-t1571-ports', title: 'Allowed outbound traffic on non-standard ports',
    techniques: ['T1571'], platforms: SPL, source: 'CIM Network_Traffic',
    query: q(`
{{idx:network}} earliest={{earliest}} action=allowed NOT dest_port IN (80, 443, 53, 123)
| where NOT (cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip))
| stats count AS connections, values(dest_port) AS ports, values(app) AS apps by src_ip, dest_ip
| sort - connections`),
    lookFor: 'Internal hosts reaching the internet on unusual ports. Enrich the destinations back in Investigate.',
  },
  {
    id: 'spl-t1105-download', title: 'Download cradles and transfer tools',
    techniques: ['T1105', 'T1059.001'], platforms: SPL, source: 'CIM Endpoint.Processes (EDR, Sysmon)',
    query: q(`
{{idx:endpoint}} earliest={{earliest}} process="*http*"
    (process_name IN ("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")
     OR (process_name IN ("powershell.exe", "pwsh.exe") (process="*DownloadString*" OR process="*DownloadFile*" OR process="*Invoke-WebRequest*" OR process="*Start-BitsTransfer*")))
| table _time, dest, user, process_name, process, parent_process_name
| sort - _time`),
    lookFor: 'Downloads started by Office apps, script hosts or unusual parents. The URLs are new indicators.',
  },
  {
    id: 'spl-t1059-encoded', title: 'Encoded or obfuscated PowerShell',
    techniques: ['T1059.001', 'T1027'], platforms: SPL, source: 'CIM Endpoint.Processes (EDR, Sysmon)',
    query: q(`
{{idx:endpoint}} earliest={{earliest}} process_name IN ("powershell.exe", "pwsh.exe")
    (process="*-enc*" OR process="*-EncodedCommand*" OR process="*FromBase64String*")
| table _time, dest, user, process, parent_process_name
| sort - _time`),
    lookFor: 'Decode the payload and check the parent process.',
  },
  {
    id: 'spl-t1505-webshell', title: 'Web server processes spawning shells',
    techniques: ['T1505.003', 'T1190'], platforms: SPL, source: 'CIM Endpoint.Processes (EDR, Sysmon)',
    query: q(`
{{idx:endpoint}} earliest={{earliest}}
    parent_process_name IN ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat*.exe", "php-cgi.exe")
    process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "certutil.exe")
| table _time, dest, parent_process_name, process_name, process, user
| sort - _time`),
    lookFor: 'A strong sign of a web shell or exploitation. Find the matching request in the web server logs.',
  },
  {
    id: 'spl-t1490-recovery', title: 'Shadow copy and backup deletion',
    techniques: ['T1490', 'T1486'], platforms: SPL, source: 'CIM Endpoint.Processes (EDR, Sysmon)',
    query: q(`
{{idx:endpoint}} earliest={{earliest}}
    ((process_name="vssadmin.exe" process="*delete*shadows*")
     OR (process_name="wmic.exe" process="*shadowcopy*delete*")
     OR (process_name="wbadmin.exe" process="*delete*")
     OR (process_name="bcdedit.exe" (process="*recoveryenabled*" OR process="*ignoreallfailures*")))
| table _time, dest, user, process_name, process, parent_process_name
| sort - _time`),
    lookFor: 'A common ransomware precursor. Treat any hit outside a known backup job as urgent.',
  },
  {
    id: 'spl-t1566-attachments', title: 'Risky attachment types received',
    techniques: ['T1566.001', 'T1204.002'], platforms: SPL, source: 'CIM Email',
    query: q(`
{{idx:email}} earliest={{earliest}}
    file_name IN ("*.iso", "*.img", "*.vhd", "*.vhdx", "*.lnk", "*.hta", "*.js", "*.vbs", "*.wsf", "*.one", "*.html", "*.htm")
| stats count AS messages, values(file_name) AS files, values(action) AS actions by src_user, recipient, subject
| sort - messages`),
    lookFor: 'Container and script attachments, and whether they were delivered.',
  },
  {
    id: 'spl-t1114-forwarding', title: 'Inbox rules that forward or redirect mail',
    techniques: ['T1114.003'], platforms: SPL, source: 'Microsoft 365 management activity (Splunk Add-on for Microsoft Office 365)',
    query: q(`
{{idx:o365}} earliest={{earliest}} Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    ("ForwardTo" OR "ForwardAsAttachmentTo" OR "RedirectTo")
| table _time, UserId, ClientIP, Operation, Parameters{}.Name, Parameters{}.Value
| sort - _time`),
    lookFor: 'Forwarding to external addresses, often with rules that also move or delete the message.',
  },
  {
    id: 'spl-t1595-scan', title: 'Sources scanning many ports or hosts',
    techniques: ['T1595', 'T1595.001'], platforms: SPL, source: 'CIM Network_Traffic',
    query: q(`
{{idx:network}} earliest={{earliest}} action=blocked
| stats dc(dest_port) AS ports, dc(dest_ip) AS targets, count AS events by src_ip
| where ports>=20 OR targets>=50
| sort - ports`),
    lookFor: 'Mostly internet noise; check whether the same sources ever got an allowed connection.',
  },
  {
    id: 'spl-t1046-internal', title: 'Internal hosts scanning the network',
    techniques: ['T1046'], platforms: SPL, source: 'CIM Network_Traffic',
    query: q(`
{{idx:network}} earliest={{earliest}}
| where cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip)
| bin _time span=1h
| stats dc(dest_port) AS ports, dc(dest_ip) AS hosts by src_ip, _time
| where ports>=50 OR hosts>=100
| sort - ports`),
    lookFor: 'Workstations touching many hosts or ports in an hour. Exclude scanners and management servers.',
  },
  {
    id: 'spl-t1021-rdp', title: 'RDP logons from public addresses',
    techniques: ['T1021.001', 'T1133'], platforms: SPL, source: 'Windows Security 4624 (CIM Authentication)',
    query: q(`
{{idx:auth}} earliest={{earliest}} signature_id=4624 Logon_Type=10
| where NOT (cidrmatch("10.0.0.0/8", src) OR cidrmatch("172.16.0.0/12", src) OR cidrmatch("192.168.0.0/16", src) OR cidrmatch("127.0.0.0/8", src))
| stats count AS logons, values(user) AS users by dest, src
| sort - logons`),
    lookFor: 'RDP reachable from the internet. Each success needs an owner and a reason.',
  },
  {
    id: 'spl-t1021-ssh', title: 'SSH failures by source',
    techniques: ['T1021.004', 'T1110'], platforms: SPL, source: 'Linux auth logs (CIM Authentication)',
    query: q(`
{{idx:auth}} earliest={{earliest}} app=sshd
| stats count(eval(action="failure")) AS failed, count(eval(action="success")) AS succeeded by src, dest
| where failed>=10
| sort -succeeded, -failed`),
    lookFor: 'Sources that failed repeatedly and then got in.',
  },
  {
    id: 'spl-t1568-nxdomain', title: 'Clients with many failed DNS lookups',
    techniques: ['T1568.002', 'T1568'], platforms: SPL, source: 'CIM Network_Resolution',
    query: q(`
{{idx:dns}} earliest={{earliest}} reply_code IN ("NXDomain", "NXDOMAIN", "3")
| stats dc(query) AS failed_lookups, values(query) AS sample by src
| where failed_lookups>=50
| eval sample=mvindex(sample, 0, 9)
| sort - failed_lookups`),
    lookFor: 'Random-looking failed names from one client suggests a DGA.',
  },
  {
    id: 'spl-t1071-dns-tunnel', title: 'Long or deeply nested DNS names',
    techniques: ['T1071.004', 'T1572'], platforms: SPL, source: 'CIM Network_Resolution',
    query: q(`
{{idx:dns}} earliest={{earliest}}
| eval len=len(query), labels=mvcount(split(query, "."))
| where len>60 OR labels>6
| rex field=query "(?<parent>[^.]+\\.[^.]+)$"
| stats count AS queries, dc(query) AS unique by src, parent
| where unique>=50
| sort - unique`),
    lookFor: 'Many unique long names under one parent from one client. CDNs and AV lookups are common false positives.',
  },
  {
    id: 'spl-t1567-cloud', title: 'Uploads to file-sharing and paste sites',
    techniques: ['T1567', 'T1567.002'], platforms: SPL, source: 'CIM Web',
    query: q(`
{{idx:web}} earliest={{earliest}}
    dest IN ("*mega.nz", "*mega.io", "*transfer.sh", "*file.io", "*gofile.io", "*sendspace.com", "*pastebin.com", "*temp.sh")
| stats count AS requests, sum(bytes_out) AS bytes_out, values(dest) AS sites by src, user
| sort - bytes_out`),
    lookFor: 'Large bytes_out to these sites, especially from servers.',
  },
  {
    id: 'spl-t1496-mining', title: 'Connections to mining pool ports',
    techniques: ['T1496'], platforms: SPL, source: 'CIM Network_Traffic',
    query: q(`
{{idx:network}} earliest={{earliest}} action=allowed dest_port IN (3333, 4444, 5555, 7777, 14444, 45700)
| stats count AS connections, values(dest_ip) AS destinations, values(dest_port) AS ports by src_ip
| sort - connections`),
    lookFor: 'Persistent connections on stratum ports. 4444 overlaps with common reverse shells.',
  },
];

/** Default SPL base searches use CIM tags, so they work without knowing index names. */
export const DEFAULT_SPLUNK_SOURCES: Record<SplunkSource, string> = {
  network: 'index=* tag=network tag=communicate',
  web: 'index=* tag=web',
  dns: 'index=* tag=network tag=resolution tag=dns',
  email: 'index=* tag=email',
  endpoint: 'index=* tag=process tag=report',
  auth: 'index=* tag=authentication',
  o365: 'index=* sourcetype="o365:management:activity"',
};

export const SPLUNK_SOURCE_LABEL: Record<SplunkSource, string> = {
  network: 'Network traffic (firewall)',
  web: 'Web / proxy',
  dns: 'DNS',
  email: 'Email',
  endpoint: 'Endpoint processes',
  auth: 'Authentication',
  o365: 'Microsoft 365 audit',
};
