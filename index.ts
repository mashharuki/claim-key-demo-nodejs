import { ProviderType } from "@lit-protocol/constants";
import {
  LitAuthClient,
  StytchOtpProvider,
} from "@lit-protocol/lit-auth-client/src/index.js";
import { LitNodeClientNodeJs } from "@lit-protocol/lit-node-client-nodejs";
import * as dotenv from 'dotenv';
import prompts from "prompts";
import * as stytch from "stytch";

dotenv.config();

/**
 * Should be defined in your local enviorment before running
 * see here: https://stytch.com/docs for setting up your stytch project
 */
const STYTCH_PROJECT_ID: string | undefined = process.env.STYTCH_PROJECT_ID;
const STYTCH_SECRET: string | undefined = process.env.STYTCH_SECRET;
const LIT_RELAY_API_KEY: string | undefined = process.env.LIT_RELAY_API_KEY;
const EMAIL_ADDRESS: string | undefined = process.env.EMAIL_ADDRESS;

if (!STYTCH_PROJECT_ID || !STYTCH_SECRET) {
  throw Error("Could not find stytch project secret or id in enviorment");
}

if (process.argv.length < 3) {
  throw Error("Please provide either --lookup or --claim flag");
}

const client = new stytch.Client({
  project_id: STYTCH_PROJECT_ID,
  secret: STYTCH_SECRET,
});

// Eメールの時の設定
const emailResponse = await prompts({
  type: "text",
  name: "email",
  message: EMAIL_ADDRESS,
});

const stytchResponse = await client.otps.email.loginOrCreate({
  email: emailResponse.email,
});

const otpResponse = await prompts({
  type: "text",
  name: "code",
  message: "Enter the code sent to your email:",
});

// ワンタイムパスワード認証の設定
const authResponse = await client.otps.authenticate({
  method_id: stytchResponse.email_id,
  code: otpResponse.code,
  session_duration_minutes: 60 * 24 * 7,
});

let sessionResp = await client.sessions.get({
  user_id: authResponse.user_id,
});

const sessionStatus = await client.sessions.authenticate({
  session_token: authResponse.session_token,
});

const litNodeClient = new LitNodeClientNodeJs({
  litNetwork: "cayenne",
  debug: false,
});

// connect
await litNodeClient.connect();

// Lit用のインスタンスを設定
const authClient = new LitAuthClient({
  litRelayConfig: {
    relayApiKey: LIT_RELAY_API_KEY,
  },
  litNodeClient,
});

const session = authClient.initProvider<StytchOtpProvider>(
  ProviderType.StytchOtp,
  {
    userId: sessionStatus.session.user_id,
    appId: STYTCH_PROJECT_ID,
  }
);

const authMethod = await session.authenticate({
  accessToken: sessionStatus.session_jwt,
});
// get public key
const publicKey = await session.computePublicKeyFromAuthMethod(authMethod);
console.log("local public key computed: ", publicKey);

if (process.argv.length >= 3 && process.argv[2] === "--claim") {
  let claimResp = await session.claimKeyId({
    authMethod,
  });
  console.log("claim response public key: ", claimResp.pubkey);
} else if (process.argv.length >= 3 && process.argv[2] === "--lookup") {
  const pkpInfo = await session.fetchPKPsThroughRelayer(authMethod);
  console.log("pkpInfo:", pkpInfo);
}
