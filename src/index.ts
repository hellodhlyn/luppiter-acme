import * as protoLoader from "@grpc/proto-loader";
import acme from "acme-client";
import dns from "dns";
import * as grpc from "grpc";

let acmeClient: acme.Client;

const protoPath = __dirname + "/../protos/certificate.proto";

const packageDef = protoLoader.loadSync(protoPath, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const { certificate } = grpc.loadPackageDefinition(packageDef) as any;

const host = process.env.HOST || "127.0.0.1";
const port = process.env.PORT || "50051";
const workerUuid = process.env.WORKER_UUID;

console.log(`Connecting: ${host}:${port} (${workerUuid})`);

const grpcClient = new certificate.Certificate(`${host}:${port}`, grpc.credentials.createInsecure());

// Return Promise<object>
//                object = { email: string }
async function initialize(): Promise<{email: string}> {
  const privKey = await acme.forge.createPrivateKey();
  acmeClient = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey: privKey,
  });

  return new Promise((resolve, reject) => {
    grpcClient.registerClient({ uuid: workerUuid }, (e: any, res: any) => {
      if (e) {
        reject(e);
      } else {
        resolve(res);
      }
    });
  });
}

async function createAccount(email: string) {
  await acmeClient.createAccount({
    termsOfServiceAgreed: true,
    contact: [`mailto:${email}`],
  });
}

async function fetchDomains(): Promise<string[]> {
  return new Promise((resolve, reject) => {
    grpcClient.fetchDomains({ uuid: workerUuid }, (e: any, res: any) => {
      if (e) {
        reject(e);
      } else {
        resolve(res.domains);
      }
    });
  });
}

async function getChallenges(domains: string[]): Promise<{
  order: acme.Order, challenges: Array<{ auth: acme.Authorization, challenge: acme.Dns01Challenge}>,
}> {
  const identifiers = domains.map((d) => ({ type: "dns", value: d }));
  const order = await acmeClient.createOrder({ identifiers });

  const authorizations = await acmeClient.getAuthorizations(order);
  const challenges = authorizations.map((auth) => {
    const filters = auth.challenges.filter((c) => c.type === "dns-01");
    if (filters.length === 0) {
      throw Error("Unabled to find dns-01 challenge.");
    }

    return {
      auth,
      challenge: filters[0] as acme.Dns01Challenge,
    };
  });

  return { order, challenges };
}

async function pushRecords(records: Array<{key: string, value: string}>): Promise<void> {
  return new Promise((resolve, reject) => {
    grpcClient.registerChallenges({ uuid: workerUuid, records: records.map((r) => r.value) }, (e: any, _: any) => {
      e ? reject(e) : resolve();
    });
  });
}

async function waitUntilVerify(record: {key: string, value: string}) {
  return new Promise((resolve) => {
    let intervalId: NodeJS.Timeout;
    intervalId = setInterval((k, v) => {
      dns.resolveCname(k, (e, addresses) => {
        if (e) {
          return;
        }

        addresses.forEach((addr) => {
          // tslint:disable-next-line:no-console
          console.log(`Found CNAME ${k} => ${addr}`);
          dns.resolveTxt(addr, (innerE, result) => {
            if (innerE) {
              return;
            }

            const records = [].concat(...result);
            // tslint:disable-next-line:no-console
            console.log(`Found TXT ${addr} => ${records}`);
            if (records.indexOf(v) !== -1) {
              setTimeout(() => resolve(), 15 * 1000);
              clearInterval(intervalId);
            }
          });
        });
      });
    }, 5 * 1000, record.key, record.value);
  });
}

async function finalize(challenge: {auth: acme.Authorization, challenge: acme.Dns01Challenge}) {
  await acmeClient.verifyChallenge(challenge.auth, challenge.challenge);
  await acmeClient.completeChallenge(challenge.challenge);
  await acmeClient.waitForValidStatus(challenge.challenge);
}

async function issue(domains: string[], order: acme.Order): Promise<void> {
  const [key, csr] = await acme.forge.createCsr({
    commonName: domains[0],
    altNames: domains.slice(1),
  });

  await acmeClient.finalizeOrder(order, csr);
  const cert = await acmeClient.getCertificate(order);

  return new Promise((resolve, reject) => {
    grpcClient.verifiedCallback({
      uuid: workerUuid,
      csr: csr.toString("base64"),
      privKey: key.toString("base64"),
      certificate: Buffer.from(cert).toString("base64"),
    }, (e: any, _: any) => {
      e ? reject(e) : resolve();
    });
  });
}

async function startWorker() {
  const initResult = await initialize();
  await createAccount(initResult.email);

  const domains = await fetchDomains();
  const { order, challenges } = await getChallenges(domains);
  const records = await Promise.all(challenges.map(async (c) => {
    return {
      key: `_acme-challenge.${c.auth.identifier.value}`,
      value: await acmeClient.getChallengeKeyAuthorization(c.challenge),
    };
  }));
  await pushRecords(records);

  // tslint:disable-next-line:no-console
  console.log("Waiting untils DNS verified...");
  await Promise.all(records.map(async (r) => waitUntilVerify(r)));
  await Promise.all(challenges.map(async (c) => finalize(c)));

  await issue(domains, order);
}

startWorker();
