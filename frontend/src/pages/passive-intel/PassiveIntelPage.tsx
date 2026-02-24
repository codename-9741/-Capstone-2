import { useState, useEffect } from 'react';

// ── Tech Stack types (from /api/findings/techstack) ───────────────────────────

interface TechItem {
  name: string; source: string; confidence: string; count: number;
}
interface TechStackResult {
  domain: string;
  servers: TechItem[]; frameworks: TechItem[]; languages: TechItem[];
  cms: TechItem[]; databases: TechItem[]; cdn: TechItem[];
  analytics: TechItem[]; javascript: TechItem[]; security: TechItem[];
  other: TechItem[];
}

// ── Passive intelligence types (from /api/intel/passive/:domain) ──────────────

interface GeoData { country: string; city: string; region: string; }
interface IPInfo {
  address: string; type: string; isp: string; asn: number; ports: number[];
  geolocation: GeoData;
}
interface Subdomain { name: string; source: string; ip_addresses: string[]; cnames: string[]; }
interface DNSSecurity { dnssec_enabled: boolean; spf_record: string; dmarc_record: string; caa_records: string[]; }
interface CDNInfo { provider: string; detected: boolean; indicators: string[]; }
interface Certificate { subject: string; issuer: string; valid_from: string; valid_to: string; sans: string[]; }
interface SocialProfile { platform: string; username: string; url: string; verified: boolean; followers: number; description: string; }
interface GHRepo { name: string; description: string; language: string; stars: number; forks: number; topics: string[]; }
interface CompanyInfo { name: string; description: string; founded: string; headquarters: string; employee_count: string; industry: string; website: string; }
interface AWSResource { type: string; identifier: string; region: string; public: boolean; }
interface S3Bucket { name: string; region: string; public: boolean; listable: boolean; }
interface RiskIndicator { category: string; description: string; severity: string; evidence: string; source: string; }

interface Person {
  name: string; title: string; department: string; company: string; location: string;
  linkedin_url: string; github_url: string; twitter_url: string;
  email: string; avatar_url: string; skills: string[]; source: string;
}
interface EmailRecord { email: string; name: string; title: string; source: string; confidence: string; }
interface EmailPattern { pattern: string; format: string; examples: string[]; confidence: string; }
interface JobListing { id: string; title: string; department: string; location: string; url: string; posted_at: string; source: string; tech_keywords: string[]; }
interface TechHiringSignal { technology: string; category: string; job_count: number; roles: string[]; }

interface PassiveData {
  target: string;
  started_at: string; completed_at: string; duration_seconds: number;
  modules_executed: number; modules_succeeded: number; modules_failed: number;
  dns_records: Record<string, string[]>;
  nameservers: string[]; mail_servers: string[];
  dns_security: DNSSecurity;
  ip_addresses: IPInfo[];
  cdn_detection: CDNInfo;
  ssl_certificates: Certificate[];
  social_profiles: SocialProfile[];
  github_repos: GHRepo[];
  company_info: CompanyInfo;
  subdomains: Subdomain[];
  aws_resources: AWSResource[]; azure_resources: { type: string; name: string; location: string; public: boolean }[];
  gcp_resources: { type: string; name: string; zone: string; public: boolean }[];
  s3_buckets: S3Bucket[];
  data_sources: string[];
  risk_indicators: RiskIndicator[];
  people: Person[]; emails: EmailRecord[]; email_patterns: EmailPattern[];
  job_listings: JobListing[]; hiring_tech: TechHiringSignal[];
}

type Tab = 'overview' | 'techstack' | 'infrastructure' | 'security' | 'people' | 'social' | 'hiring';

// ── Constants ─────────────────────────────────────────────────────────────────

const TECH_META: Record<string, { label: string; tw: string }> = {
  servers:    { label: 'Web Servers',     tw: 'bg-blue-50 border-blue-200 text-blue-700 dark:bg-blue-900/20 dark:border-blue-800 dark:text-blue-400' },
  frameworks: { label: 'Frameworks',      tw: 'bg-purple-50 border-purple-200 text-purple-700 dark:bg-purple-900/20 dark:border-purple-800 dark:text-purple-400' },
  languages:  { label: 'Languages',       tw: 'bg-orange-50 border-orange-200 text-orange-700 dark:bg-orange-900/20 dark:border-orange-800 dark:text-orange-400' },
  cms:        { label: 'CMS',             tw: 'bg-pink-50 border-pink-200 text-pink-700 dark:bg-pink-900/20 dark:border-pink-800 dark:text-pink-400' },
  databases:  { label: 'Databases',       tw: 'bg-emerald-50 border-emerald-200 text-emerald-700 dark:bg-emerald-900/20 dark:border-emerald-800 dark:text-emerald-400' },
  cdn:        { label: 'CDN / Edge',      tw: 'bg-cyan-50 border-cyan-200 text-cyan-700 dark:bg-cyan-900/20 dark:border-cyan-800 dark:text-cyan-400' },
  analytics:  { label: 'Analytics',       tw: 'bg-amber-50 border-amber-200 text-amber-700 dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-400' },
  javascript: { label: 'JS Libraries',    tw: 'bg-yellow-50 border-yellow-200 text-yellow-700 dark:bg-yellow-900/20 dark:border-yellow-800 dark:text-yellow-400' },
  security:   { label: 'Security',        tw: 'bg-red-50 border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-800 dark:text-red-400' },
  other:      { label: 'Other',           tw: 'bg-slate-50 border-slate-200 text-slate-700 dark:bg-slate-800/50 dark:border-slate-700 dark:text-slate-400' },
};

const CONFIDENCE_DOT: Record<string, string> = { High: 'bg-emerald-500', Medium: 'bg-amber-400', Low: 'bg-slate-400' };
const CONFIDENCE_BADGE: Record<string, string> = {
  High: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
  Medium: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  Low: 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
};
const PLATFORM_COLOR: Record<string, string> = {
  linkedin: 'bg-blue-600', instagram: 'bg-pink-600', twitter: 'bg-sky-500',
  github: 'bg-slate-700', reddit: 'bg-orange-600', youtube: 'bg-red-600', facebook: 'bg-blue-700',
};
const PLATFORM_ABBR: Record<string, string> = {
  linkedin: 'LI', instagram: 'IG', twitter: 'TW', github: 'GH', reddit: 'RD', youtube: 'YT', facebook: 'FB',
};
const HIRING_CAT_COLOR: Record<string, string> = {
  Language: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
  Framework: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
  Cloud: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
  DevOps: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
  Database: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
  Messaging: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  Security: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  Other: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400',
};

// ── Shared helpers ─────────────────────────────────────────────────────────────

function Chip({ label, cls }: { label: string; cls?: string }) {
  return <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-medium ${cls ?? 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}>{label}</span>;
}
function Card({ title, children, badge }: { title: string; children: React.ReactNode; badge?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
        {badge && <span className="text-xs text-slate-400">{badge}</span>}
      </div>
      {children}
    </div>
  );
}
function Empty({ msg }: { msg: string }) {
  return (
    <div className="rounded-xl border border-dashed border-slate-200 dark:border-slate-700 p-8 text-center">
      <p className="text-sm text-slate-400">{msg}</p>
    </div>
  );
}
function Stat({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${color ?? 'text-slate-900 dark:text-white'}`}>{value}</p>
      {sub && <p className="text-xs text-slate-400 mt-0.5">{sub}</p>}
    </div>
  );
}
function TabBtn({ id, label, active, count, onClick }: { id: Tab; label: string; active: boolean; count?: number; onClick: (t: Tab) => void }) {
  return (
    <button onClick={() => onClick(id)}
      className={`flex items-center gap-1.5 px-3.5 py-2 text-sm font-medium rounded-lg transition-colors whitespace-nowrap ${
        active ? 'bg-brand-600 text-white'
               : 'text-slate-500 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-white dark:hover:bg-slate-800'
      }`}>
      {label}
      {!!count && count > 0 && (
        <span className={`text-[11px] px-1.5 py-0.5 rounded-full font-semibold ${active ? 'bg-white/25 text-white' : 'bg-slate-200 text-slate-600 dark:bg-slate-700 dark:text-slate-300'}`}>
          {count}
        </span>
      )}
    </button>
  );
}

// ── Infer business partners from all available data ───────────────────────────

interface BusinessPartner { name: string; category: string; evidence: string; }

function inferBusinessPartners(passive: PassiveData | null, stack: TechStackResult | null): BusinessPartner[] {
  const partners: BusinessPartner[] = [];
  const seen = new Set<string>();
  const add = (name: string, category: string, evidence: string) => {
    if (!seen.has(name.toLowerCase())) {
      seen.add(name.toLowerCase());
      partners.push({ name, category, evidence });
    }
  };

  // From CDN detection
  if (passive?.cdn_detection?.detected && passive.cdn_detection.provider) {
    add(passive.cdn_detection.provider, 'CDN / DDoS Protection', 'CDN detection');
  }

  // From mail servers (email provider)
  (passive?.mail_servers ?? []).forEach(mx => {
    const m = mx.toLowerCase();
    if (m.includes('google') || m.includes('aspmx')) add('Google Workspace', 'Email Provider', `MX: ${mx}`);
    else if (m.includes('outlook') || m.includes('microsoft') || m.includes('protection.outlook')) add('Microsoft 365', 'Email Provider', `MX: ${mx}`);
    else if (m.includes('mxroute')) add('MXRoute', 'Email Provider', `MX: ${mx}`);
    else if (m.includes('protonmail')) add('ProtonMail', 'Email Provider', `MX: ${mx}`);
    else if (m.includes('fastmail')) add('Fastmail', 'Email Provider', `MX: ${mx}`);
    else if (m.includes('zoho')) add('Zoho Mail', 'Email Provider', `MX: ${mx}`);
    else if (m.includes('sendgrid')) add('SendGrid', 'Email Delivery', `MX: ${mx}`);
    else if (m.includes('mailchimp') || m.includes('mcsv.net')) add('Mailchimp', 'Email Marketing', `MX: ${mx}`);
  });

  // From DNS / SPF record vendors
  const spf = (passive?.dns_security?.spf_record ?? '').toLowerCase();
  if (spf.includes('sendgrid')) add('SendGrid', 'Email Delivery', 'SPF record');
  if (spf.includes('mailchimp') || spf.includes('mcsv.net')) add('Mailchimp', 'Email Marketing', 'SPF record');
  if (spf.includes('salesforce')) add('Salesforce', 'CRM', 'SPF record');
  if (spf.includes('hubspot')) add('HubSpot', 'CRM / Marketing', 'SPF record');
  if (spf.includes('zendesk')) add('Zendesk', 'Customer Support', 'SPF record');
  if (spf.includes('postmark') || spf.includes('sppostmark')) add('Postmark', 'Email Delivery', 'SPF record');
  if (spf.includes('amazonses') || spf.includes('amazonaws')) add('Amazon SES', 'Email Delivery', 'SPF record');

  // From SSL certificate issuers
  (passive?.ssl_certificates ?? []).forEach(cert => {
    const issuer = cert.issuer ?? '';
    if (issuer.includes("Let's Encrypt")) add("Let's Encrypt", 'Certificate Authority', 'SSL certificate');
    else if (issuer.includes('DigiCert')) add('DigiCert', 'Certificate Authority', 'SSL certificate');
    else if (issuer.includes('Comodo') || issuer.includes('Sectigo')) add('Sectigo', 'Certificate Authority', 'SSL certificate');
    else if (issuer.includes('GlobalSign')) add('GlobalSign', 'Certificate Authority', 'SSL certificate');
    else if (issuer.includes('Cloudflare')) add('Cloudflare', 'CDN / Security', 'SSL certificate');
  });

  // From cloud resources
  if ((passive?.aws_resources?.length ?? 0) > 0 || (passive?.s3_buckets?.length ?? 0) > 0) {
    add('Amazon Web Services', 'Cloud Provider', 'Detected cloud resources');
  }
  if ((passive?.azure_resources?.length ?? 0) > 0) {
    add('Microsoft Azure', 'Cloud Provider', 'Detected cloud resources');
  }
  if ((passive?.gcp_resources?.length ?? 0) > 0) {
    add('Google Cloud', 'Cloud Provider', 'Detected cloud resources');
  }

  // From IP ISPs
  (passive?.ip_addresses ?? []).forEach(ip => {
    const isp = (ip.isp ?? '').toLowerCase();
    if (isp.includes('amazon') || isp.includes('aws')) add('Amazon Web Services', 'Cloud / Hosting', `IP ${ip.address}`);
    else if (isp.includes('google')) add('Google Cloud', 'Cloud / Hosting', `IP ${ip.address}`);
    else if (isp.includes('microsoft') || isp.includes('azure')) add('Microsoft Azure', 'Cloud / Hosting', `IP ${ip.address}`);
    else if (isp.includes('cloudflare')) add('Cloudflare', 'CDN / Network', `IP ${ip.address}`);
    else if (isp.includes('fastly')) add('Fastly', 'CDN', `IP ${ip.address}`);
    else if (isp.includes('akamai')) add('Akamai', 'CDN', `IP ${ip.address}`);
    else if (isp.includes('digitalocean')) add('DigitalOcean', 'Cloud / Hosting', `IP ${ip.address}`);
    else if (isp.includes('linode') || isp.includes('akamai technologies')) add('Linode', 'Cloud / Hosting', `IP ${ip.address}`);
    else if (isp.includes('ovh')) add('OVH', 'Cloud / Hosting', `IP ${ip.address}`);
    else if (isp.includes('hetzner')) add('Hetzner', 'Cloud / Hosting', `IP ${ip.address}`);
  });

  // From tech stack (analytics, CDN, etc.)
  const allTechItems: TechItem[] = [
    ...(stack?.analytics ?? []),
    ...(stack?.cdn ?? []),
    ...(stack?.other ?? []),
  ];
  allTechItems.forEach(t => {
    const n = t.name.toLowerCase();
    if (n.includes('google analytics') || n.includes('gtm')) add('Google Analytics', 'Analytics', 'Tech stack detection');
    if (n.includes('hotjar')) add('Hotjar', 'Analytics / UX', 'Tech stack detection');
    if (n.includes('mixpanel')) add('Mixpanel', 'Analytics', 'Tech stack detection');
    if (n.includes('segment')) add('Segment', 'Customer Data Platform', 'Tech stack detection');
    if (n.includes('amplitude')) add('Amplitude', 'Analytics', 'Tech stack detection');
    if (n.includes('intercom')) add('Intercom', 'Customer Messaging', 'Tech stack detection');
    if (n.includes('stripe')) add('Stripe', 'Payment Processing', 'Tech stack detection');
    if (n.includes('paypal')) add('PayPal', 'Payment Processing', 'Tech stack detection');
    if (n.includes('cloudflare')) add('Cloudflare', 'CDN / Security', 'Tech stack detection');
    if (n.includes('akamai')) add('Akamai', 'CDN', 'Tech stack detection');
    if (n.includes('fastly')) add('Fastly', 'CDN', 'Tech stack detection');
    if (n.includes('datadog')) add('Datadog', 'Monitoring', 'Tech stack detection');
    if (n.includes('newrelic') || n.includes('new relic')) add('New Relic', 'Monitoring', 'Tech stack detection');
    if (n.includes('sentry')) add('Sentry', 'Error Tracking', 'Tech stack detection');
    if (n.includes('pagerduty')) add('PagerDuty', 'Incident Management', 'Tech stack detection');
  });

  return partners;
}

// ── TAB: Overview ─────────────────────────────────────────────────────────────

function OverviewTab({ passive, stack }: { passive: PassiveData | null; stack: TechStackResult | null }) {
  const partners = inferBusinessPartners(passive, stack);

  const catColors: Record<string, string> = {
    'CDN / DDoS Protection': 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
    'CDN / Security': 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
    'CDN': 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
    'CDN / Network': 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400',
    'Email Provider': 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    'Email Delivery': 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    'Email Marketing': 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    'Cloud Provider': 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
    'Cloud / Hosting': 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
    'Analytics': 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    'Analytics / UX': 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    'Customer Data Platform': 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    'CRM': 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    'CRM / Marketing': 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    'Payment Processing': 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
    'Certificate Authority': 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
    'Monitoring': 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400',
    'Error Tracking': 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400',
    'Customer Messaging': 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400',
    'Customer Support': 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400',
    'Incident Management': 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  };

  return (
    <div className="space-y-6">
      {/* Company Info */}
      {passive?.company_info && (passive.company_info.name || passive.company_info.description) && (
        <Card title="Company Overview">
          <div className="grid gap-3 md:grid-cols-2">
            {passive.company_info.name && (
              <div><p className="text-xs text-slate-400 uppercase tracking-wide">Name</p><p className="text-sm font-medium text-slate-900 dark:text-white mt-0.5">{passive.company_info.name}</p></div>
            )}
            {passive.company_info.industry && (
              <div><p className="text-xs text-slate-400 uppercase tracking-wide">Industry</p><p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">{passive.company_info.industry}</p></div>
            )}
            {passive.company_info.founded && (
              <div><p className="text-xs text-slate-400 uppercase tracking-wide">Founded</p><p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">{passive.company_info.founded}</p></div>
            )}
            {passive.company_info.headquarters && (
              <div><p className="text-xs text-slate-400 uppercase tracking-wide">Headquarters</p><p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">{passive.company_info.headquarters}</p></div>
            )}
            {passive.company_info.employee_count && (
              <div><p className="text-xs text-slate-400 uppercase tracking-wide">Employees</p><p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">{passive.company_info.employee_count}</p></div>
            )}
            {passive.company_info.website && (
              <div><p className="text-xs text-slate-400 uppercase tracking-wide">Website</p><a href={passive.company_info.website} target="_blank" rel="noreferrer" className="text-sm text-brand-600 dark:text-brand-400 hover:underline mt-0.5 block">{passive.company_info.website}</a></div>
            )}
          </div>
          {passive.company_info.description && (
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-3 border-t border-slate-100 dark:border-slate-800 pt-3">{passive.company_info.description}</p>
          )}
        </Card>
      )}

      {/* Stats row */}
      {passive && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="People Found" value={passive.people?.length ?? 0} />
          <Stat label="Subdomains" value={passive.subdomains?.length ?? 0} />
          <Stat label="Emails" value={passive.emails?.length ?? 0} />
          <Stat label="Job Listings" value={passive.job_listings?.length ?? 0} />
        </div>
      )}

      {/* Business Partners */}
      <Card title="Companies They Do Business With" badge={`${partners.length} detected`}>
        {partners.length === 0 ? (
          <p className="text-sm text-slate-400">Run a scan to detect vendors, cloud providers, analytics tools, email services, and CDN partners.</p>
        ) : (
          <div className="grid gap-2 md:grid-cols-2">
            {partners.map((p, i) => (
              <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-900 dark:text-white">{p.name}</p>
                  <p className="text-xs text-slate-400 mt-0.5 truncate">{p.evidence}</p>
                </div>
                <Chip label={p.category} cls={catColors[p.category] ?? 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'} />
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Risk Indicators */}
      {(passive?.risk_indicators?.length ?? 0) > 0 && (
        <Card title="Risk Indicators" badge={`${passive!.risk_indicators.length} found`}>
          <div className="space-y-2">
            {passive!.risk_indicators.map((r, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50">
                <span className={`flex-shrink-0 px-2 py-0.5 rounded text-[11px] font-bold uppercase mt-0.5 ${
                  r.severity === 'Critical' ? 'bg-red-100 text-red-700' :
                  r.severity === 'High' ? 'bg-orange-100 text-orange-700' :
                  r.severity === 'Medium' ? 'bg-amber-100 text-amber-700' : 'bg-slate-200 text-slate-600'
                }`}>{r.severity}</span>
                <div>
                  <p className="text-sm font-medium text-slate-900 dark:text-white">{r.category}</p>
                  <p className="text-xs text-slate-500">{r.description}</p>
                  {r.evidence && <p className="text-xs text-slate-400 mt-0.5 font-mono">{r.evidence}</p>}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Data sources */}
      {(passive?.data_sources?.length ?? 0) > 0 && (
        <Card title="Intelligence Sources">
          <div className="flex flex-wrap gap-2">
            {passive!.data_sources.map((s, i) => (
              <Chip key={i} label={s} cls="bg-brand-50 text-brand-700 dark:bg-brand-900/20 dark:text-brand-400 border border-brand-100 dark:border-brand-800" />
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── TAB: Tech Stack ───────────────────────────────────────────────────────────

function TechStackTab({ stack, passive }: { stack: TechStackResult | null; passive: PassiveData | null }) {
  const hasScanStack = stack && Object.keys(TECH_META).some(k => (stack[k as keyof TechStackResult] as TechItem[] | undefined)?.length);
  const passiveTech = passive?.hiring_tech ?? [];

  if (!hasScanStack && passiveTech.length === 0) {
    return <Empty msg="No technology data — run an Active or Full scan to fingerprint the target, or a Passive scan to see hiring tech signals" />;
  }

  return (
    <div className="space-y-6">
      {/* Fingerprinted tech from scan findings */}
      {hasScanStack && (
        <div className="space-y-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Detected from Scans (whatweb, nmap, nuclei)</h3>
          <div className="grid gap-4 md:grid-cols-2">
            {(Object.keys(TECH_META) as Array<keyof TechStackResult>).filter(k => Array.isArray(stack[k]) && (stack[k] as TechItem[]).length > 0).map(catKey => {
              const meta = TECH_META[catKey]!;
              const items = stack[catKey] as TechItem[];
              return (
                <Card key={catKey} title={meta.label} badge={`${items.length} detected`}>
                  <div className="flex flex-wrap gap-2">
                    {items.map((item, idx) => (
                      <div key={idx} className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ${meta.tw}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${CONFIDENCE_DOT[item.confidence] || 'bg-slate-400'}`} />
                        {item.name}
                        <span className="opacity-50 text-[10px]">({item.source})</span>
                      </div>
                    ))}
                  </div>
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {/* Tech signals from job postings */}
      {passiveTech.length > 0 && (
        <div className="space-y-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Technologies Actively Hired For (from job postings)</h3>
          <Card title="Hiring Tech Signals" badge={`${passiveTech.length} technologies`}>
            {(() => {
              const maxCount = Math.max(...passiveTech.map(t => t.job_count), 1);
              return (
                <div className="space-y-2">
                  {passiveTech.slice(0, 25).map((t, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span className="w-32 text-xs text-slate-600 dark:text-slate-300 truncate text-right flex-shrink-0">{t.technology}</span>
                      <div className="flex-1 h-4 bg-slate-100 dark:bg-slate-800 rounded overflow-hidden">
                        <div className="h-full rounded bg-brand-500 dark:bg-brand-600 transition-all"
                          style={{ width: `${(t.job_count / maxCount) * 100}%` }} />
                      </div>
                      <span className="w-4 text-xs text-slate-400 text-right flex-shrink-0">{t.job_count}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded flex-shrink-0 ${HIRING_CAT_COLOR[t.category] || HIRING_CAT_COLOR.Other}`}>{t.category}</span>
                    </div>
                  ))}
                </div>
              );
            })()}
          </Card>
        </div>
      )}
    </div>
  );
}

// ── TAB: Infrastructure ───────────────────────────────────────────────────────

function InfraTab({ passive }: { passive: PassiveData | null }) {
  if (!passive) return <Empty msg="No infrastructure data — run a Passive or Full scan" />;

  const hasIPs   = (passive.ip_addresses?.length ?? 0) > 0;
  const hasSubs  = (passive.subdomains?.length ?? 0) > 0;
  const hasDNS   = passive.dns_records && Object.keys(passive.dns_records).length > 0;
  const hasMX    = (passive.mail_servers?.length ?? 0) > 0;
  const hasNS    = (passive.nameservers?.length ?? 0) > 0;
  const hasCloud = (passive.aws_resources?.length ?? 0) > 0 || (passive.azure_resources?.length ?? 0) > 0 ||
                   (passive.gcp_resources?.length ?? 0) > 0 || (passive.s3_buckets?.length ?? 0) > 0;

  if (!hasIPs && !hasSubs && !hasDNS && !hasCloud) return <Empty msg="No infrastructure data found — run a Passive or Full scan" />;

  return (
    <div className="space-y-6">
      {/* IP Addresses */}
      {hasIPs && (
        <Card title="IP Addresses" badge={`${passive.ip_addresses.length} IPs`}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-100 dark:border-slate-800">
                  <th className="pb-2 pr-3 font-medium">IP</th>
                  <th className="pb-2 pr-3 font-medium">Type</th>
                  <th className="pb-2 pr-3 font-medium">Country</th>
                  <th className="pb-2 pr-3 font-medium">City</th>
                  <th className="pb-2 pr-3 font-medium">ISP</th>
                  <th className="pb-2 pr-3 font-medium">ASN</th>
                  <th className="pb-2 font-medium">Open Ports</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {passive.ip_addresses.map((ip, i) => (
                  <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="py-2 pr-3 font-mono text-brand-600 dark:text-brand-400">{ip.address}</td>
                    <td className="py-2 pr-3 text-slate-500">{ip.type || '—'}</td>
                    <td className="py-2 pr-3 text-slate-600 dark:text-slate-300">{ip.geolocation?.country || '—'}</td>
                    <td className="py-2 pr-3 text-slate-500">{ip.geolocation?.city || '—'}</td>
                    <td className="py-2 pr-3 text-slate-500 max-w-[120px] truncate">{ip.isp || '—'}</td>
                    <td className="py-2 pr-3 text-slate-400">{ip.asn ? `AS${ip.asn}` : '—'}</td>
                    <td className="py-2">
                      {ip.ports?.length ? (
                        <div className="flex flex-wrap gap-1">
                          {ip.ports.slice(0, 8).map(p => (
                            <span key={p} className="px-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-mono">{p}</span>
                          ))}
                          {ip.ports.length > 8 && <span className="text-slate-400">+{ip.ports.length - 8}</span>}
                        </div>
                      ) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* DNS Records */}
      {(hasDNS || hasMX || hasNS) && (
        <Card title="DNS Records">
          <div className="space-y-3">
            {hasNS && (
              <div>
                <p className="text-xs font-medium text-slate-400 uppercase mb-1">Nameservers</p>
                <div className="flex flex-wrap gap-1.5">
                  {passive.nameservers.map((ns, i) => <Chip key={i} label={ns} cls="bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400 font-mono text-[11px]" />)}
                </div>
              </div>
            )}
            {hasMX && (
              <div>
                <p className="text-xs font-medium text-slate-400 uppercase mb-1">Mail Servers (MX)</p>
                <div className="flex flex-wrap gap-1.5">
                  {passive.mail_servers.map((mx, i) => <Chip key={i} label={mx} cls="bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400 font-mono text-[11px]" />)}
                </div>
              </div>
            )}
            {hasDNS && Object.entries(passive.dns_records).map(([type, values]) => values && values.length > 0 && (
              <div key={type}>
                <p className="text-xs font-medium text-slate-400 uppercase mb-1">{type} Records</p>
                <div className="space-y-0.5">
                  {values.slice(0, 5).map((v, i) => <p key={i} className="text-xs font-mono text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-800/50 px-2 py-0.5 rounded">{v}</p>)}
                  {values.length > 5 && <p className="text-xs text-slate-400">+{values.length - 5} more</p>}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Subdomains */}
      {hasSubs && (
        <Card title="Subdomains" badge={`${passive.subdomains.length} found`}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-100 dark:border-slate-800">
                  <th className="pb-2 pr-3 font-medium">Subdomain</th>
                  <th className="pb-2 pr-3 font-medium">IPs</th>
                  <th className="pb-2 pr-3 font-medium">CNAMEs</th>
                  <th className="pb-2 font-medium">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {passive.subdomains.map((s, i) => (
                  <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="py-2 pr-3 font-mono text-slate-700 dark:text-slate-300">{s.name}</td>
                    <td className="py-2 pr-3 text-slate-500">{s.ip_addresses?.join(', ') || '—'}</td>
                    <td className="py-2 pr-3 text-slate-400 max-w-[160px] truncate">{s.cnames?.join(', ') || '—'}</td>
                    <td className="py-2 text-slate-400">{s.source || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Cloud assets */}
      {hasCloud && (
        <Card title="Cloud Assets">
          <div className="grid gap-2 md:grid-cols-2">
            {passive.s3_buckets?.map((b, i) => (
              <div key={i} className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-slate-900 dark:text-white font-mono">{b.name}</p>
                  <Chip label="S3 Bucket" cls="bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400" />
                </div>
                <p className="text-xs text-slate-500 mt-1">{b.region || 'us-east-1'}</p>
                {b.public && <span className="text-[10px] text-red-500 font-medium">Public</span>}
                {b.listable && <span className="text-[10px] text-red-600 font-bold ml-2">Listable!</span>}
              </div>
            ))}
            {passive.aws_resources?.map((r, i) => (
              <div key={i} className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-slate-900 dark:text-white">{r.identifier || r.type}</p>
                  <Chip label={`AWS ${r.type}`} cls="bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" />
                </div>
                {r.region && <p className="text-xs text-slate-500 mt-1">{r.region}</p>}
                {r.public && <span className="text-[10px] text-red-500 font-medium">Publicly accessible</span>}
              </div>
            ))}
            {passive.azure_resources?.map((r, i) => (
              <div key={i} className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-slate-900 dark:text-white">{r.name}</p>
                  <Chip label={`Azure ${r.type}`} cls="bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400" />
                </div>
                {r.location && <p className="text-xs text-slate-500 mt-1">{r.location}</p>}
                {r.public && <span className="text-[10px] text-red-500 font-medium">Publicly accessible</span>}
              </div>
            ))}
            {passive.gcp_resources?.map((r, i) => (
              <div key={i} className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium text-slate-900 dark:text-white">{r.name}</p>
                  <Chip label={`GCP ${r.type}`} cls="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" />
                </div>
                {r.zone && <p className="text-xs text-slate-500 mt-1">{r.zone}</p>}
                {r.public && <span className="text-[10px] text-red-500 font-medium">Publicly accessible</span>}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── TAB: Security ─────────────────────────────────────────────────────────────

function SecurityTab({ passive }: { passive: PassiveData | null }) {
  if (!passive) return <Empty msg="No security data — run a Passive or Full scan" />;

  const hasCerts = (passive.ssl_certificates?.length ?? 0) > 0;
  const hasDNSSec = passive.dns_security && (passive.dns_security.spf_record || passive.dns_security.dmarc_record || passive.dns_security.dnssec_enabled);
  const hasCDN = passive.cdn_detection?.detected;

  if (!hasCerts && !hasDNSSec && !hasCDN) return <Empty msg="No security data found" />;

  return (
    <div className="space-y-6">
      {/* CDN / WAF */}
      {hasCDN && (
        <Card title="CDN / WAF Detection">
          <div className="flex items-center gap-3">
            <span className="text-2xl font-bold text-brand-600 dark:text-brand-400">{passive.cdn_detection.provider}</span>
            <Chip label="Detected" cls="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" />
          </div>
          {passive.cdn_detection.indicators?.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {passive.cdn_detection.indicators.map((ind, i) => <Chip key={i} label={ind} />)}
            </div>
          )}
        </Card>
      )}

      {/* DNS Security */}
      {hasDNSSec && (
        <Card title="Email & DNS Security">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="text-xs font-medium text-slate-500 w-16">DNSSEC</span>
              <Chip label={passive.dns_security.dnssec_enabled ? 'Enabled' : 'Disabled'}
                cls={passive.dns_security.dnssec_enabled
                  ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
                  : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                } />
            </div>
            {passive.dns_security.spf_record && (
              <div>
                <p className="text-xs font-medium text-slate-500 mb-1">SPF Record</p>
                <p className="text-xs font-mono bg-slate-50 dark:bg-slate-800 rounded p-2 text-slate-600 dark:text-slate-300 break-all">{passive.dns_security.spf_record}</p>
              </div>
            )}
            {passive.dns_security.dmarc_record && (
              <div>
                <p className="text-xs font-medium text-slate-500 mb-1">DMARC Record</p>
                <p className="text-xs font-mono bg-slate-50 dark:bg-slate-800 rounded p-2 text-slate-600 dark:text-slate-300 break-all">{passive.dns_security.dmarc_record}</p>
              </div>
            )}
            {passive.dns_security.caa_records?.length > 0 && (
              <div>
                <p className="text-xs font-medium text-slate-500 mb-1">CAA Records (allowed CAs)</p>
                <div className="flex flex-wrap gap-1.5">
                  {passive.dns_security.caa_records.map((r, i) => <Chip key={i} label={r} cls="font-mono text-[11px]" />)}
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* SSL Certificates */}
      {hasCerts && (
        <Card title="SSL / TLS Certificates" badge={`${passive.ssl_certificates.length} found`}>
          <div className="space-y-3">
            {passive.ssl_certificates.map((cert, i) => {
              const expiry = cert.valid_to ? new Date(cert.valid_to) : null;
              const expired = expiry && expiry < new Date();
              const expiringSoon = expiry && !expired && expiry < new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
              return (
                <div key={i} className="p-3 rounded-lg border border-slate-200 dark:border-slate-800">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono font-medium text-slate-900 dark:text-white truncate">{cert.subject}</p>
                      <p className="text-xs text-slate-500 mt-0.5">Issued by: {cert.issuer}</p>
                    </div>
                    {expired && <Chip label="Expired" cls="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 flex-shrink-0" />}
                    {expiringSoon && !expired && <Chip label="Expiring Soon" cls="bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 flex-shrink-0" />}
                    {!expired && !expiringSoon && expiry && <Chip label="Valid" cls="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400 flex-shrink-0" />}
                  </div>
                  <div className="flex gap-4 mt-2 text-xs text-slate-400">
                    {cert.valid_from && <span>From: {new Date(cert.valid_from).toLocaleDateString()}</span>}
                    {cert.valid_to && <span>To: {new Date(cert.valid_to).toLocaleDateString()}</span>}
                  </div>
                  {cert.sans?.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {cert.sans.slice(0, 6).map((san, j) => <Chip key={j} label={san} cls="font-mono text-[10px]" />)}
                      {cert.sans.length > 6 && <Chip label={`+${cert.sans.length - 6} more`} />}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── TAB: People & Emails ──────────────────────────────────────────────────────

function PeopleTab({ passive }: { passive: PassiveData | null }) {
  const [search, setSearch] = useState('');
  if (!passive) return <Empty msg="No people data — run a Passive or Full scan" />;

  const hasPeople = (passive.people?.length ?? 0) > 0;
  const hasEmails = (passive.emails?.length ?? 0) > 0;
  const hasPatterns = (passive.email_patterns?.length ?? 0) > 0;

  if (!hasPeople && !hasEmails && !hasPatterns) return <Empty msg="No people discovered — run a Passive or Full scan to harvest GitHub org members, commit authors, and email addresses" />;

  const people = (passive.people ?? []).filter(p =>
    !search ||
    p.name?.toLowerCase().includes(search.toLowerCase()) ||
    p.title?.toLowerCase().includes(search.toLowerCase()) ||
    p.email?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Email Patterns */}
      {hasPatterns && (
        <Card title="Email Format Patterns" badge="company email format">
          <div className="grid gap-3 md:grid-cols-2">
            {passive.email_patterns.map((pat, i) => (
              <div key={i} className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-mono font-semibold text-brand-600 dark:text-brand-400">{pat.format}</span>
                  <Chip label={pat.confidence} cls={CONFIDENCE_BADGE[pat.confidence] || CONFIDENCE_BADGE.Low} />
                </div>
                {pat.examples?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {pat.examples.map((ex, j) => <Chip key={j} label={ex} cls="font-mono text-[10px] bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300" />)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* People */}
      {hasPeople && (
        <div className="space-y-3">
          <input type="text" placeholder="Search by name, title, or email..."
            value={search} onChange={e => setSearch(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white" />
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {people.map((p, i) => (
              <div key={i} className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0 w-10 h-10 rounded-full bg-brand-100 dark:bg-brand-900/30 flex items-center justify-center overflow-hidden text-brand-700 dark:text-brand-400 font-bold text-sm">
                    {p.avatar_url
                      ? <img src={p.avatar_url} alt={p.name} className="w-10 h-10 object-cover" onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                      : (p.name ? p.name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() : '?')
                    }
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">{p.name || 'Unknown'}</p>
                    {p.title && <p className="text-xs text-slate-500 truncate">{p.title}</p>}
                    {p.email && <p className="text-xs text-brand-600 dark:text-brand-400 mt-0.5 font-mono truncate">{p.email}</p>}
                  </div>
                </div>
                {p.location && <p className="text-xs text-slate-400 mt-2">{p.location}</p>}
                <div className="flex items-center gap-2 mt-3 flex-wrap">
                  {p.github_url   && <a href={p.github_url}   target="_blank" rel="noreferrer" className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-white hover:bg-slate-700">GitHub</a>}
                  {p.linkedin_url && <a href={p.linkedin_url} target="_blank" rel="noreferrer" className="text-[11px] px-2 py-0.5 rounded bg-blue-600 text-white hover:bg-blue-700">LinkedIn</a>}
                  {p.twitter_url  && <a href={p.twitter_url}  target="_blank" rel="noreferrer" className="text-[11px] px-2 py-0.5 rounded bg-sky-500 text-white hover:bg-sky-600">Twitter</a>}
                  <span className="text-[10px] text-slate-400 ml-auto">{p.source}</span>
                </div>
                {p.skills?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {p.skills.slice(0, 5).map((s, j) => <Chip key={j} label={s} cls="text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-500" />)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Emails table */}
      {hasEmails && (
        <Card title={`Discovered Email Addresses (${passive.emails.length})`}>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-100 dark:border-slate-800">
                  <th className="pb-2 pr-4 font-medium">Email</th>
                  <th className="pb-2 pr-4 font-medium">Name</th>
                  <th className="pb-2 pr-4 font-medium">Title</th>
                  <th className="pb-2 pr-4 font-medium">Source</th>
                  <th className="pb-2 font-medium">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {passive.emails.map((e, i) => (
                  <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td className="py-2 pr-4 font-mono text-brand-600 dark:text-brand-400">{e.email}</td>
                    <td className="py-2 pr-4 text-slate-700 dark:text-slate-300">{e.name || '—'}</td>
                    <td className="py-2 pr-4 text-slate-500">{e.title || '—'}</td>
                    <td className="py-2 pr-4 text-slate-400">{e.source}</td>
                    <td className="py-2"><Chip label={e.confidence} cls={CONFIDENCE_BADGE[e.confidence] || CONFIDENCE_BADGE.Low} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

// ── TAB: Social & Company Presence ────────────────────────────────────────────

function SocialTab({ passive }: { passive: PassiveData | null }) {
  if (!passive) return <Empty msg="No social data — run a Passive or Full scan" />;

  const hasSocial = (passive.social_profiles?.length ?? 0) > 0;
  const hasRepos  = (passive.github_repos?.length ?? 0) > 0;

  if (!hasSocial && !hasRepos) return <Empty msg="No social or repository data found — run a Passive or Full scan" />;

  return (
    <div className="space-y-6">
      {hasSocial && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400 mb-3">Social Profiles</h3>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {passive.social_profiles.map((p, i) => (
              <div key={i} className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-start gap-3">
                  <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-white text-xs font-bold ${PLATFORM_COLOR[p.platform?.toLowerCase()] || 'bg-slate-600'}`}>
                    {PLATFORM_ABBR[p.platform?.toLowerCase()] || p.platform?.slice(0, 2).toUpperCase() || '?'}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-slate-900 dark:text-white capitalize">{p.platform}</p>
                      <Chip label={p.verified ? 'Verified' : 'Unverified'}
                        cls={p.verified
                          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
                          : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400'
                        } />
                    </div>
                    {p.username && <p className="text-xs text-slate-500 mt-0.5">@{p.username}</p>}
                    {p.followers > 0 && <p className="text-xs text-slate-400 mt-0.5">{p.followers.toLocaleString()} followers</p>}
                  </div>
                </div>
                {p.description && <p className="text-xs text-slate-500 mt-3 line-clamp-2">{p.description}</p>}
                {p.url && <a href={p.url} target="_blank" rel="noreferrer" className="mt-3 inline-block text-xs text-brand-600 dark:text-brand-400 hover:underline truncate max-w-full">{p.url}</a>}
              </div>
            ))}
          </div>
        </div>
      )}

      {hasRepos && (
        <Card title="GitHub Repositories" badge={`${passive.github_repos.length} public repos`}>
          <div className="grid gap-3 md:grid-cols-2">
            {passive.github_repos.map((repo, i) => (
              <div key={i} className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800">
                <div className="flex items-start justify-between gap-2">
                  <p className="text-xs font-semibold text-slate-900 dark:text-white">{repo.name}</p>
                  <div className="flex items-center gap-2 text-[11px] text-slate-400 flex-shrink-0">
                    <span>★ {repo.stars}</span>
                    <span>⑂ {repo.forks}</span>
                  </div>
                </div>
                {repo.description && <p className="text-xs text-slate-500 mt-1 line-clamp-2">{repo.description}</p>}
                <div className="flex flex-wrap gap-1 mt-2">
                  {repo.language && <Chip label={repo.language} cls="bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400 text-[10px]" />}
                  {repo.topics?.slice(0, 4).map((t, j) => <Chip key={j} label={t} cls="text-[10px]" />)}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── TAB: Hiring & Jobs ────────────────────────────────────────────────────────

function HiringTab({ passive }: { passive: PassiveData | null }) {
  const [filter, setFilter] = useState('');
  if (!passive) return <Empty msg="No hiring data — run a Passive or Full scan" />;

  const hasJobs = (passive.job_listings?.length ?? 0) > 0;
  const hasTech = (passive.hiring_tech?.length ?? 0) > 0;

  if (!hasJobs && !hasTech) return <Empty msg="No job listings found — Greenhouse, Lever, and Workable are queried automatically during Passive scan" />;

  const jobs = (passive.job_listings ?? []).filter(j =>
    !filter ||
    j.title?.toLowerCase().includes(filter.toLowerCase()) ||
    j.department?.toLowerCase().includes(filter.toLowerCase())
  );

  const SOURCE_CLS: Record<string, string> = {
    greenhouse: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    lever: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
    workable: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-400',
  };

  return (
    <div className="space-y-6">
      {hasTech && (() => {
        const maxCount = Math.max(...passive.hiring_tech.map(t => t.job_count), 1);
        const byCategory = passive.hiring_tech.reduce<Record<string, TechHiringSignal[]>>((acc, t) => {
          (acc[t.category || 'Other'] = acc[t.category || 'Other'] || []).push(t);
          return acc;
        }, {});
        return (
          <div className="grid gap-6 md:grid-cols-2">
            <Card title="Top Technologies" badge="from job postings">
              <div className="space-y-2">
                {passive.hiring_tech.slice(0, 15).map((t, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span className="w-24 text-xs text-slate-600 dark:text-slate-300 truncate text-right flex-shrink-0">{t.technology}</span>
                    <div className="flex-1 h-4 bg-slate-100 dark:bg-slate-800 rounded overflow-hidden">
                      <div className="h-full rounded bg-brand-500 dark:bg-brand-600"
                        style={{ width: `${(t.job_count / maxCount) * 100}%` }} />
                    </div>
                    <span className="w-5 text-xs text-slate-400 text-right flex-shrink-0">{t.job_count}</span>
                  </div>
                ))}
              </div>
            </Card>
            <Card title="By Category">
              <div className="space-y-2">
                {Object.entries(byCategory).map(([cat, items]) => (
                  <div key={cat} className="flex items-center justify-between p-2 rounded bg-slate-50 dark:bg-slate-800/50">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded ${HIRING_CAT_COLOR[cat] || HIRING_CAT_COLOR.Other}`}>{cat}</span>
                    <div className="flex flex-wrap gap-1 max-w-[65%] justify-end">
                      {items.slice(0, 4).map((t, i) => <Chip key={i} label={t.technology} cls="text-[10px]" />)}
                      {items.length > 4 && <Chip label={`+${items.length - 4}`} cls="text-[10px] bg-slate-200 text-slate-500" />}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        );
      })()}

      {hasJobs && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <input type="text" placeholder="Filter by title or department..."
              value={filter} onChange={e => setFilter(e.target.value)}
              className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white" />
            <span className="text-sm text-slate-400 flex-shrink-0">{jobs.length} listings</span>
          </div>
          {jobs.map((job, i) => (
            <div key={i} className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-semibold text-slate-900 dark:text-white">{job.title}</p>
                    <Chip label={job.source} cls={SOURCE_CLS[job.source] || 'bg-slate-100 text-slate-500'} />
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
                    {job.department && <span>{job.department}</span>}
                    {job.location   && <span>— {job.location}</span>}
                    {job.posted_at  && <span>— {job.posted_at.slice(0, 10)}</span>}
                  </div>
                </div>
                {job.url && <a href={job.url} target="_blank" rel="noreferrer" className="flex-shrink-0 text-xs px-3 py-1.5 rounded-lg bg-brand-50 text-brand-600 hover:bg-brand-100 dark:bg-brand-900/20 dark:text-brand-400 font-medium">View</a>}
              </div>
              {job.tech_keywords?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-3">
                  {job.tech_keywords.map((kw, j) => <Chip key={j} label={kw} cls="text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-500" />)}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function PassiveIntelPage() {
  const [techStacks, setTechStacks]   = useState<TechStackResult[]>([]);
  const [osintDomains, setOsintDomains] = useState<string[]>([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [passive, setPassive]         = useState<PassiveData | null>(null);
  const [tab, setTab]                 = useState<Tab>('overview');
  const [loading, setLoading]         = useState(true);
  const [loadingPassive, setLoadingPassive] = useState(false);

  useEffect(() => { loadAll(); }, []);

  const loadAll = async () => {
    setLoading(true);

    // Load tech stack and passive list independently — one failing doesn't block the other
    let stacks: TechStackResult[] = [];
    let pDomains: string[] = [];

    try {
      const res = await fetch('/api/findings/techstack');
      const data = await res.json();
      if (data.success) stacks = data.data ?? [];
    } catch { /* ignore */ }

    try {
      const res = await fetch('/api/intel/passive');
      const data = await res.json();
      if (data.status === 'success') {
        pDomains = (data.data ?? []).map((s: { domain: string }) => s.domain);
      }
    } catch { /* ignore */ }

    setTechStacks(stacks);
    setOsintDomains(pDomains);

    const allDomains = Array.from(new Set([
      ...stacks.map(s => s.domain),
      ...pDomains,
    ]));

    setLoading(false);

    if (allDomains.length > 0) {
      // setSelectedDomain triggers the passive load effect below
      setSelectedDomain(prev => prev || allDomains[0]);
    }
  };

  // Load passive OSINT whenever domain changes
  useEffect(() => {
    if (!selectedDomain) { setPassive(null); return; }
    if (!osintDomains.includes(selectedDomain)) { setPassive(null); return; }
    setLoadingPassive(true);
    fetch(`/api/intel/passive/${encodeURIComponent(selectedDomain)}`)
      .then(r => r.json())
      .then(data => { if (data.status === 'success') setPassive(data.data as PassiveData); else setPassive(null); })
      .catch(() => setPassive(null))
      .finally(() => setLoadingPassive(false));
  }, [selectedDomain, osintDomains]);

  const allDomains = Array.from(new Set([...techStacks.map(s => s.domain), ...osintDomains]));
  const currentStack = techStacks.find(s => s.domain === selectedDomain) ?? null;
  const hasPassive = osintDomains.includes(selectedDomain);

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: 'overview',        label: 'Overview' },
    { id: 'techstack',       label: 'Tech Stack', count: currentStack ? Object.keys(TECH_META).reduce((n, k) => n + ((currentStack[k as keyof TechStackResult] as TechItem[] | undefined)?.length ?? 0), 0) : undefined },
    { id: 'infrastructure',  label: 'Infrastructure', count: (passive?.ip_addresses?.length ?? 0) + (passive?.subdomains?.length ?? 0) || undefined },
    { id: 'security',        label: 'Security' },
    { id: 'people',          label: 'People', count: (passive?.people?.length ?? 0) + (passive?.emails?.length ?? 0) || undefined },
    { id: 'social',          label: 'Social & Repos', count: (passive?.social_profiles?.length ?? 0) + (passive?.github_repos?.length ?? 0) || undefined },
    { id: 'hiring',          label: 'Hiring & Jobs', count: passive?.job_listings?.length },
  ];

  if (loading) return <div className="py-20 text-center text-slate-400 text-sm">Loading intelligence data...</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Target Intelligence</h1>
          <p className="text-sm text-slate-500">Tech stack, infrastructure, people, social presence, and business partners</p>
        </div>
        <button onClick={loadAll}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700">
          Refresh
        </button>
      </div>

      {allDomains.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-200 dark:border-slate-700 p-20 text-center">
          <p className="text-slate-500 font-medium">No data yet</p>
          <p className="text-sm text-slate-400 mt-2 max-w-sm mx-auto">
            Go to <span className="font-semibold text-brand-600">Discover</span> and run a scan.
            Use <span className="font-semibold">Full Scan</span> or <span className="font-semibold">Passive Only</span> for complete OSINT data alongside tech fingerprinting.
          </p>
        </div>
      ) : (
        <>
          {/* Target selector */}
          <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-start gap-4">
              <div className="flex-1">
                <label className="text-xs font-medium uppercase tracking-wide text-slate-400 block mb-1.5">Select Target</label>
                <select value={selectedDomain}
                  onChange={e => { setSelectedDomain(e.target.value); setTab('overview'); setPassive(null); }}
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-800 dark:text-white">
                  {allDomains.map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
              <div className="pt-6 flex flex-col gap-1">
                {currentStack && <Chip label="Tech Stack" cls="bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400" />}
                {hasPassive
                  ? <Chip label="OSINT Available" cls="bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" />
                  : <Chip label="No OSINT" cls="bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400" />
                }
              </div>
            </div>
            {!hasPassive && selectedDomain && (
              <p className="text-xs text-slate-400 mt-2">
                No passive OSINT for <strong className="text-slate-600 dark:text-slate-300">{selectedDomain}</strong> — run a <strong>Full Scan</strong> or <strong>Passive Only</strong> scan from the Discover page to collect OSINT data.
              </p>
            )}
          </div>

          {/* Tabs */}
          <div className="flex items-center gap-1 flex-wrap pb-1">
            {tabs.map(t => <TabBtn key={t.id} id={t.id} label={t.label} active={tab === t.id} count={t.count} onClick={setTab} />)}
          </div>

          {/* Loading passive */}
          {loadingPassive && (
            <div className="py-8 text-center text-slate-400 text-sm">Loading OSINT data...</div>
          )}

          {/* Tab content */}
          {!loadingPassive && (
            <>
              {tab === 'overview'       && <OverviewTab   passive={passive} stack={currentStack} />}
              {tab === 'techstack'      && <TechStackTab  stack={currentStack} passive={passive} />}
              {tab === 'infrastructure' && <InfraTab      passive={passive} />}
              {tab === 'security'       && <SecurityTab   passive={passive} />}
              {tab === 'people'         && <PeopleTab     passive={passive} />}
              {tab === 'social'         && <SocialTab     passive={passive} />}
              {tab === 'hiring'         && <HiringTab     passive={passive} />}
            </>
          )}
        </>
      )}
    </div>
  );
}
