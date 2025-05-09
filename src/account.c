#include "account.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>

#define SALT_LEN 16 /* 16 bytes*/
#define HASH_BYTES 32 /*SHA-256*/
#define OUTBUF_MAX HASH_LENGTH
/*---- BEGIN minimal SHA-256 implementation*/
static const unit32_t sha256_k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n)    (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)    (((x)&(y)) ^ (~(x)&(z)))
#define MAJ(x,y,z)   (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define EP0(x)       (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)       (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x)      (ROTR(x,7) ^ ROTR(x,18) ^ ((x)>>3))
#define SIG1(x)      (ROTR(x,17)^ ROTR(x,19) ^ ((x)>>10))
typedef struct{
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} SHA256_CTX;
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
  uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
  uint32_t i,j;
  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (data[j] << 24) | (data[j+1] << 16) |
           (data[j+2] <<  8) | (data[j+3]);
  for ( ; i < 64; ++i)
    m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
  a = ctx->state[0]; b = ctx->state[1];
  c = ctx->state[2]; d = ctx->state[3];
  e = ctx->state[4]; f = ctx->state[5];
  g = ctx->state[6]; h = ctx->state[7];
  for (i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + m[i];
    t2 = EP0(a) + MAJ(a,b,c);
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b;
  ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f;
  ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
  ctx->datalen = 0; ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx,
                          const uint8_t data[],
                          size_t len)
{
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = data[i];
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
  uint32_t i = ctx->datalen;
  /* Pad */
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += ctx->datalen * 8;
  /* Append length in bits */
  ctx->data[63] = (uint8_t)(ctx->bitlen);
  ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
  sha256_transform(ctx, ctx->data);
  /* Produce final hash (big-endian) */
  for (i = 0; i < 4; ++i) {
    for (uint32_t j = 0; j < 8; ++j) {
      hash[j * 4 + i] =
        (uint8_t)((ctx->state[j] >> (24 - i * 8)) & 0xFF);
    }
  }
}
/*---- END SHA256 implementatiom ---*/
/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) plaintext_password;
  (void) email;
  (void) birthdate;

  return NULL;
}


void account_free(account_t *acc) {
  if (acc == NULL) {
    return;
  }
  memset(acc, 0, sizeof(account_t));
  free(acc);
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  if (!acc || !new_plaintext_password) {
    log_message(LOG_ERROR,
                "account_update_password: null argument");
    return false;
  }

  uint8_t  salt[SALT_LEN];
  uint8_t  digest[HASH_BYTES];
  SHA256_CTX ctx;

  /* 1) build a random salt */
  srand((unsigned)time(NULL) ^ (uintptr_t)acc);
  for (int i = 0; i < SALT_LEN; ++i) {
    salt[i] = (uint8_t)(rand() & 0xFF);
  }

  /* 2) hash = SHA256(salt ∥ password) */
  sha256_init(&ctx);
  sha256_update(&ctx, salt, SALT_LEN);
  sha256_update(&ctx,
                (const uint8_t*)new_plaintext_password,
                strlen(new_plaintext_password));
  sha256_final(&ctx, digest);

  /* 3) hex-encode into “salt$hash” */
  char out[OUTBUF_MAX];
  int  pos = 0;
  for (int i = 0; i < SALT_LEN && pos + 2 < OUTBUF_MAX; ++i)
    pos += snprintf(out + pos, OUTBUF_MAX - pos, "%02x", salt[i]);

  if (pos + 1 >= OUTBUF_MAX) goto fail_too_long;
  out[pos++] = '$';

  for (int i = 0; i < HASH_BYTES && pos + 2 < OUTBUF_MAX; ++i)
    pos += snprintf(out + pos, OUTBUF_MAX - pos, "%02x", digest[i]);

  out[pos] = '\0';
  if (pos >= OUTBUF_MAX) {
  fail_too_long:
    log_message(LOG_ERROR,
                "account_update_password: output length %d ≥ %d",
                pos, OUTBUF_MAX);
    return false;
  }

  /* 4) store in your fixed buffer */
  memset(acc->password_hash, 0, HASH_LENGTH);
  memcpy(acc->password_hash, out, pos + 1);

  return true;
}

/*
    if account login failed or succeeded change the required account meta data to plus +1 (login_count , login_fail_count, last_login_time)(self explanatory)
    make sure that the last IP address connected from metadata (last_ip) be set correctly
    Whenever a user logs in successfully, their login_fail_count is set to 0
    Whenever a user fails to log in successfully, their login_count is set to 0
*/
void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  acc->login_count=acc->login_count+1;//check that incrementing the value stays safe
  acc->login_fail_count=0;
  acc->last_ip=ip;
}

void account_record_login_failure(account_t *acc) {
  acc->login_count=0;
  acc->login_fail_count=acc->login_fail_count+1; //check that incrementing the value stays safe 
}

bool account_is_banned(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  time_t now = time(NULL);
  return (acc->unban_time != 0) && (now < acc->unban_time);
}

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  time_t now = time(NULL);
  return (acc->expiration_time != 0) && (now > acc->expiration_time);
}

void account_set_unban_time(account_t *acc, time_t t) {
  acc->unban_time=t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  acc->expiration_time=t;
}

void account_set_email(account_t *acc, const char *new_email) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_email;
}
/*
make a human readable summary of account current status which will be given to a file descriptor so address accordingly
Write each variable in a human readable format - something like (readable_variable_name: readable_variable_output). For example, if user_id = 54125612356, we output "User ID: 54125612356".
The variables required to make human readable are: userid, email, birthdate, login_count, login_fail_count and last_ip
Return True on success, or false if write fails

#define USER_ID_LENGTH 100 yp 
#define HASH_LENGTH 128 
#define EMAIL_LENGTH 100 yp
#define BIRTHDATE_LENGTH 10 yp
#define IP_SIZE 4 yp

*/
#include <unistd.h>
#include <stdio.h>
bool account_print_summary(const account_t *acct, int fd) {

  char *format_summary = "User ID: \n, Email: \n, Birthdate: \n, Login Count: \n, Login Fail Count: \n, Last IP: \n";
  int max_length= sizeof(unsigned int)*2 +USER_ID_LENGTH + EMAIL_LENGTH + BIRTHDATE_LENGTH + IP_SIZE+strlen(format_summary);

  char message[max_length];
  int message_success=snprintf(message, max_length,"User ID: %ld\n, Email: %s\n, Birthdate: %s\n, Login Count: %d\n, Login Fail Count: %d\n, Last IP: %s\n",acct->userid, acct->email, acct->birthdate, acct->login_count, acct->login_fail_count, acct->last_ip);
  if (message_success < 0) {
    perror("snprintf failed");//do logg error function provided
    return false;
  }
  if ((size_t)message_success >= sizeof(message)) {
    fprintf(stderr, "snprintf output was truncated\n");
    return false;
  } 
  // check for file descriptor change value vulnerability
  ssize_t bytes_written = write(fd, message, message_success); //check safty of write

  if (bytes_written == -1) {
        perror("write failed");
        return false;
  }

  if (bytes_written != (ssize_t)strlen(message)) {
        fprintf(stderr, "Partial write occurred\n");
        return false;
  }
  return true;
}

