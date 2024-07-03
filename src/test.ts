import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";

// assert function checking if two Uint8Array are equal
function assert(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) {
    throw new Error("arrays have different lengths");
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error("arrays are different");
    }
  }
}

// inviter
const invitationSecret = randomBytes(32);
const invitationUnlockKey = randomBytes(32);

// create invitation
const invitationCiphertextNonce = randomBytes(24);
const invitationCiphertext = xchacha20poly1305(
  invitationUnlockKey,
  invitationCiphertextNonce
).encrypt(invitationSecret);
const invitationId = hmac(sha256, invitationUnlockKey, "invitationId");

// create invitation server envelop
const inviterServerSessionKey = randomBytes(32);
const nonceServerEnvelop = randomBytes(24);
const invitationServerEnvelop = xchacha20poly1305(
  inviterServerSessionKey,
  nonceServerEnvelop
).encrypt(
  new Uint8Array([
    ...invitationId,
    ...invitationCiphertextNonce,
    ...invitationCiphertext,
  ])
);

// data sent to the server
const serverData = {
  invitationServerEnvelop,
  nonceServerEnvelop,
};

// server
const result = xchacha20poly1305(
  inviterServerSessionKey,
  serverData.nonceServerEnvelop
).decrypt(serverData.invitationServerEnvelop);
// extract the invitation id, nonce and ciphertext
const invitationIdReceived = result.slice(0, 32);
const invitationCiphertextNonceReceived = result.slice(32, 56);
const invitationCiphertextReceived = result.slice(56);
// check if the invitation id is correct
assert(invitationIdReceived, invitationId);
assert(invitationCiphertextNonceReceived, invitationCiphertextNonce);
assert(invitationCiphertextReceived, invitationCiphertext);

// retrieve and decrypt the invitation

const inviteeServerSessionKey = randomBytes(32);
// encrypt the invitationCiphertextNonceReceived and invitationCiphertextReceived using the inviteeServerSessionKey
const inviteeEnvelopNonce = randomBytes(24);
const inviteeEnvelop = xchacha20poly1305(
  inviteeServerSessionKey,
  inviteeEnvelopNonce
).encrypt(
  new Uint8Array([
    ...invitationCiphertextNonceReceived,
    ...invitationCiphertextReceived,
  ])
);

// invitee
const inviteeInvitationReceived = xchacha20poly1305(
  inviteeServerSessionKey,
  inviteeEnvelopNonce
).decrypt(inviteeEnvelop);
const inviteeInvitationSecret = xchacha20poly1305(
  invitationUnlockKey,
  inviteeInvitationReceived.slice(0, 24)
).decrypt(inviteeInvitationReceived.slice(24));
assert(inviteeInvitationSecret, invitationSecret);

console.log("All tests passed");
