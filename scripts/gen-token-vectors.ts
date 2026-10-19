// Token vectors for proxy/gate: tokens issued by the sites' own code (cars-cli
// registry/lib/security/api-token.ts) and the verdict the sites' API gate (registry/lib/request-gate,
// createProxy) gives each request that carries one. proxy/gate's tests take the same requests to
// boks_gate in enforce and hold it to the second column of each vector: the site's verdict, except in
// the two classes the plan lets the proxy be stricter in (AC1) — a token without the address (no_ip)
// and a token whose base64url only Node's lenient decoder reads (stricter).
//
//   CARS_CLI=<a clone of kopandante/cars-cli> bun run scripts/gen-token-vectors.ts > proxy/gate/testdata/vectors.json
//
// next/server and the site's ban lookup are stubbed: the gate's pipeline is run as it is, with the
// ban never matching and no geo.
import { createHmac } from "node:crypto";
import { plugin } from "bun";

const cars = process.env.CARS_CLI;
if (!cars) throw new Error("CARS_CLI: the path of a cars-cli clone");

class StubResponse {
	status: number;
	body: string;
	headers = new Headers();
	constructor(body?: string | null, init?: { status?: number; headers?: Record<string, string> }) {
		this.status = init?.status ?? 200;
		this.body = body ?? "";
		for (const [k, v] of Object.entries(init?.headers ?? {})) this.headers.set(k, v);
	}
	static json(body: unknown, init?: { status?: number }) {
		return new StubResponse(JSON.stringify(body), { status: init?.status, headers: { "content-type": "application/json" } });
	}
	static next() {
		return new StubResponse();
	}
}

// The site's own modules first, under the aliases request-gate imports them by: Bun's runtime plugins
// take virtual modules, not a resolver for a path alias.
const lib = ["security/api-token", "security/client-ip", "security/fingerprint-server", "security/security-headers", "security/types"];
const real = Object.fromEntries(await Promise.all(lib.map(async (m) => [m, await import(`${cars}/registry/lib/${m}.ts`)])));

plugin({
	name: "site stubs",
	setup(build) {
		build.module("next/server", () => ({ exports: { NextResponse: StubResponse, NextRequest: class {} }, loader: "object" }));
		build.module("@/lib/security/ip-blocking", () => ({
			exports: { isIpBlocked: async () => false, isIpBlockedByAdmin: async () => false },
			loader: "object",
		}));
		for (const m of lib) build.module(`@cars/lib/${m}`, () => ({ exports: real[m], loader: "object" }));
	},
});

const { createApiToken } = real["security/api-token"];
const { createProxy } = await import(`${cars}/registry/lib/request-gate/request-gate.ts`);

// Keys of the vectors alone, not of any site: written out so the file can be read and diffed.
const CURRENT = "vectors-only-current-key-0000000000000000";
const PREVIOUS = "vectors-only-previous-key-000000000000000";
const STRANGER = "vectors-only-stranger-key-000000000000000";
const NOW = 1_792_400_000_000; // 2026-10-19, fixed so the vectors do not move
const TTL = 3 * 60 * 1000;
const IP = "203.0.113.7";
const IPV6 = "2001:db8::7";
const OTHER = "198.51.100.9";
const FP = "a".repeat(64);
const FP2 = "b".repeat(64);

function withEnv<T>(current: string, previous: string | undefined, fn: () => T): T {
	process.env.API_SECRET_CURRENT = current;
	if (previous) process.env.API_SECRET_PREVIOUS = previous;
	else delete process.env.API_SECRET_PREVIOUS;
	return fn();
}

function issued(opts: { fp?: string; ip?: string; age?: number; secret?: string }): string {
	const realNow = Date.now;
	Date.now = () => NOW - (opts.age ?? 1000);
	try {
		return withEnv(opts.secret ?? CURRENT, undefined, () => createApiToken(opts.fp, opts.ip));
	} finally {
		Date.now = realNow;
	}
}

// signed is a token of any payload text and encoding, signed as api-token.ts signs: what only a holder
// of the secret can make, to see how each side reads an encoding the sites never write.
function signed(encodedPayload: string, secret = CURRENT): string {
	return `${encodedPayload}.${createHmac("sha256", secret).update(encodedPayload).digest("base64url")}`;
}

const b64url = (s: string) => Buffer.from(s).toString("base64url");

// A payload whose standard base64 holds + or /: Node's base64url decoder reads them, Go's does not.
function stdAlphabetPayload(): string {
	for (let i = 0; ; i++) {
		const json = JSON.stringify({ iat: NOW - 1000, nonce: i.toString(16).padStart(16, "0"), fp: FP, ip: IP, x: "?>?>" });
		const std = Buffer.from(json).toString("base64").replace(/=+$/, "");
		if (/[+/]/.test(std)) return std;
	}
}

type Token = { name: string; class: string; token: string };

const fresh = issued({ fp: FP, ip: IP });
const tokens: Token[] = [
	{ name: "fp+ip", class: "valid", token: fresh },
	{ name: "ip only (page token of the proxy)", class: "valid", token: issued({ ip: IP }) },
	{ name: "fp+ip ipv6", class: "valid", token: issued({ fp: FP, ip: IPV6 }) },
	{ name: "fp+ip signed with previous", class: "previous", token: issued({ fp: FP, ip: IP, secret: PREVIOUS }) },
	{ name: "previous, age ttl+1", class: "ttl", token: issued({ fp: FP, ip: IP, secret: PREVIOUS, age: TTL + 1 }) },
	{ name: "fp+ip signed with a stranger", class: "signature", token: issued({ fp: FP, ip: IP, secret: STRANGER }) },
	{ name: "age exactly ttl", class: "ttl", token: issued({ fp: FP, ip: IP, age: TTL }) },
	{ name: "age ttl+1", class: "ttl", token: issued({ fp: FP, ip: IP, age: TTL + 1 }) },
	{ name: "iat in the future", class: "ttl", token: issued({ fp: FP, ip: IP, age: -1 }) },
	{ name: "other address", class: "ip", token: issued({ fp: FP, ip: OTHER }) },
	{ name: "ip only, other address", class: "ip", token: issued({ ip: OTHER }) },
	// The address is compared as a string: another spelling of the client's own is another address.
	{ name: "own address v4-mapped", class: "ip", token: issued({ fp: FP, ip: `::ffff:${IP}` }) },
	{ name: "own address ipv6 upper case", class: "ip", token: issued({ fp: FP, ip: IPV6.toUpperCase() }) },
	{ name: "iat fractional, signed", class: "valid", token: signed(b64url(JSON.stringify({ iat: NOW - 1000.5, nonce: "00", fp: FP, ip: IP }))) },
	{ name: "nonce a number, signed", class: "no_ip", token: signed(b64url(JSON.stringify({ iat: NOW - 1000, nonce: 1, fp: FP, ip: IP }))) },
	{ name: "nonce null, signed", class: "no_ip", token: signed(b64url(JSON.stringify({ iat: NOW - 1000, nonce: null, fp: FP, ip: IP }))) },
	// fp or ip of another type only a holder of the secret writes: the proxy refuses the payload.
	{ name: "fp a number, signed", class: "stricter", token: signed(b64url(JSON.stringify({ iat: NOW - 1000, nonce: "00", fp: 123, ip: IP }))) },
	{ name: "fp false, signed", class: "stricter", token: signed(b64url(JSON.stringify({ iat: NOW - 1000, nonce: "00", fp: false, ip: IP }))) },
	{ name: "fp only, no ip", class: "no_ip", token: issued({ fp: FP }) },
	{ name: "no fp, no ip (page token of a site)", class: "no_ip", token: issued({}) },
	{
		name: "no nonce, signed",
		class: "no_ip",
		token: signed(b64url(JSON.stringify({ iat: NOW - 1000, fp: FP, ip: IP }))),
	},
	{ name: "iat a string, signed", class: "garbage", token: signed(b64url(JSON.stringify({ iat: String(NOW), nonce: "00", ip: IP }))) },
	{ name: "payload not json, signed", class: "garbage", token: signed(b64url("not json")) },
	{ name: "payload tampered", class: "signature", token: `${b64url(JSON.stringify({ iat: NOW - 1000, nonce: "00", fp: FP, ip: OTHER }))}.${fresh.split(".")[1]}` },
	{ name: "signature truncated", class: "signature", token: fresh.slice(0, -4) },
	{ name: "no dot", class: "garbage", token: fresh.replace(".", "") },
	{ name: "dot alone", class: "garbage", token: "." },
	{ name: "leading dot", class: "garbage", token: `.${fresh.split(".")[1]}` },
	{ name: "trailing dot", class: "garbage", token: `${fresh.split(".")[0]}.` },
	{ name: "signature padded with =", class: "stricter", token: `${fresh}=` },
	{
		// The last of 43 characters carries two bits the decoder drops: a sibling decodes to the same bytes.
		name: "signature, other unused trailing bits",
		class: "stricter",
		token: (() => {
			const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
			return fresh.slice(0, -1) + abc[abc.indexOf(fresh.at(-1) ?? "A") ^ 1];
		})(),
	},
	{
		name: "signature in the standard alphabet",
		class: "stricter",
		token: (() => {
			// Re-issue until the signature holds - or _, which the standard alphabet writes as + or /.
			for (;;) {
				const t = issued({ fp: FP, ip: IP });
				const sig = t.split(".")[1];
				if (/[-_]/.test(sig)) return `${t.split(".")[0]}.${sig.replace(/-/g, "+").replace(/_/g, "/")}`;
			}
		})(),
	},
	{ name: "payload padded, signed", class: "stricter", token: signed(`${b64url(JSON.stringify({ iat: NOW - 1000, nonce: "0", fp: FP, ip: IP }))}==`) },
	{ name: "payload in the standard alphabet, signed", class: "stricter", token: signed(stdAlphabetPayload()) },
];

type Req = { name: string; method: string; path: string; fingerprint?: string };
// How the token comes: the cookie (no via), the header alone, the header behind an empty cookie, or the
// cookie with another token in the header.
type Delivery = { via?: "header" | "cookie-empty" | "cookie+header"; header?: string };
const requests: Req[] = [
	{ name: "GET with its fp", method: "GET", path: "/api/encar/catalog", fingerprint: FP },
	{ name: "GET with another fp", method: "GET", path: "/api/encar/catalog", fingerprint: FP2 },
	{ name: "GET with its fp upper case", method: "GET", path: "/api/encar/catalog", fingerprint: FP.toUpperCase() },
	{ name: "GET without fp", method: "GET", path: "/api/encar/catalog" },
	{ name: "POST with its fp", method: "POST", path: "/api/encar/catalog", fingerprint: FP },
	{ name: "POST with another fp", method: "POST", path: "/api/encar/catalog", fingerprint: FP2 },
	{ name: "POST without fp", method: "POST", path: "/api/encar/catalog" },
	// The fp relaxation is GET's alone: HEAD and PUT compare it as POST does.
	{ name: "HEAD with its fp", method: "HEAD", path: "/api/encar/catalog", fingerprint: FP },
	{ name: "HEAD with another fp", method: "HEAD", path: "/api/encar/catalog", fingerprint: FP2 },
	{ name: "HEAD without fp", method: "HEAD", path: "/api/encar/catalog" },
	{ name: "PUT without fp", method: "PUT", path: "/api/encar/catalog" },
	{ name: "GET pics, fp skipped", method: "GET", path: "/api/encar/pics/1.jpg" },
	{ name: "GET pics with another fp, skipped", method: "GET", path: "/api/encar/pics/1.jpg", fingerprint: FP2 },
	{ name: "POST pics without fp, skipped", method: "POST", path: "/api/encar/pics/1.jpg" },
	{ name: "POST picsX without fp, skipped by raw prefix", method: "POST", path: "/api/encar/picsX" },
];

const gate = createProxy({ api: { skipFingerprintPrefixes: ["/api/encar/pics"] } });

async function site(token: string | undefined, req: Req, ip: string, d: Delivery) {
	const headers = new Headers({ host: "cars.example.com", "x-forwarded-for": ip });
	if (req.fingerprint) headers.set("x-fingerprint", req.fingerprint);
	let cookie: string | undefined = token;
	const header = d.via === "cookie+header" ? d.header : d.via ? token : undefined;
	if (d.via === "header") cookie = undefined;
	if (d.via === "cookie-empty") cookie = "";
	if (header) headers.set("x-api-token", header);
	const request = {
		method: req.method,
		headers,
		nextUrl: { pathname: req.path, protocol: "http:" },
		cookies: { get: (n: string) => (n === "x-api-token" && cookie !== undefined ? { value: cookie } : undefined) },
	};
	const realNow = Date.now;
	Date.now = () => NOW;
	try {
		const res = await withEnv(CURRENT, PREVIOUS, () => gate(request));
		return { status: res.status, body: res.body };
	} finally {
		Date.now = realNow;
	}
}

const vectors: object[] = [];
// The proxy's column is the site's, but for the classes the plan lets it be stricter in.
async function push(t: Token, req: Req, ip: string, d: Delivery = {}) {
	const s = await site(t.token || undefined, req, ip, d);
	const proxy = t.class === "no_ip" || t.class === "stricter" ? { status: 401, body: '{"error":"Access denied"}' } : s;
	const name = `${t.name} / ${req.name}${d.via ? `, token by ${d.via}${d.via === "cookie+header" ? (d.header === fresh ? " (valid)" : " (bad)") : ""}` : ""}`;
	vectors.push({ name, class: t.class, token: t.token, ...(d.via && { via: d.via }), ...(d.header && { header_token: d.header }), method: req.method, path: req.path, fingerprint: req.fingerprint ?? "", client_ip: ip, site: s, proxy });
}
for (const t of tokens) {
	for (const req of requests) await push(t, req, t.name.includes("ipv6") ? IPV6 : IP);
}
// The delivery axis, on tokens that pass and that fail each check: a header token is checked, not
// just let through, and the cookie decides over the header whatever the header holds.
const viaTokens = tokens.filter((t) => ["fp+ip", "fp+ip signed with a stranger", "age ttl+1", "other address", "no fp, no ip (page token of a site)"].includes(t.name));
const strangerToken = viaTokens.find((t) => t.class === "signature")?.token ?? "";
const deliveries: Delivery[] = [{ via: "header" }, { via: "cookie-empty" }, { via: "cookie+header", header: fresh }, { via: "cookie+header", header: strangerToken }];
for (const d of deliveries) {
	for (const t of viaTokens) await push(t, requests[0], IP, d);
}
await push({ name: "no token", class: "garbage", token: "" }, requests[0], IP);

// One vector per line: the file stays reviewable as a diff without tripling its length.
const head = JSON.stringify({ key_current: CURRENT, key_previous: PREVIOUS, now_ms: NOW, skip_fp: ["/api/encar/pics"] });
console.log(`${head.slice(0, -1)},"vectors":[\n${vectors.map((v) => JSON.stringify(v)).join(",\n")}\n]}`);
