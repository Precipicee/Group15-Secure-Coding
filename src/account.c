#include "account.h"

// new include
#include <string.h>

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

bool account_validate_email(const char *email) {

  if (strlen(email) >= EMAIL_LENGTH) {
    return false;
  }


  // does not check for multiple @ or wrong . characters.
  const char *at = strchr(email, '@');
  const char *dot = strrchr(email, '.');

  if (at == NULL || dot == NULL || at > dot) {
    return false;
  }

  for (const char *p = email; *p != '\0'; p++) {
    if (!isprint(*p) || isspace(*p)) {
      return false;
    }
  }

  return true;

}

bool account_validate_birthdate(const char *birthdate) {



  
  return true;

}

 account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  account_t *new_acc = malloc(sizeof(account_t));
  if (!new_acc) {
    // change the errors
    //   log_message();
    //   account_free(new_acc);
    return NULL;
  }

  if(strlen(userid) >= USER_ID_LENGTH) {
    //   log_message();
    //   account_free(new_acc);
    return NULL;
  }

  if(!account_validate_email(email)) {
    //   log_message();
    //   account_free(new_acc);
    return NULL;
  }

  if(!account_validate_birthdate(birthdate)) {
    //   log_message();
    //   account_free(new_acc);
    return NULL;
  }

  strncpy(new_acc->userid, userid, USER_ID_LENGTH);
  // these may not be necessary.
  new_acc->userid[USER_ID_LENGTH - 1] = '\0';

  // use the account_update_password function to hash the password and store it in the structure.
  // to be implemented in the future.
  // if(!account_update_password(new_acc, plaintext_password)) {
  //   log_message();
  //   account_free(new_acc);
  //   return NULL;
  // }

  strncpy(new_acc->email, email, EMAIL_LENGTH);
  new_acc->email[EMAIL_LENGTH - 1] = '\0';

  memcpy(new_acc->birthdate, birthdate, BIRTHDATE_LENGTH);
  new_acc->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

  // check the account ID field, nothing in project sheet says anything about it.
  new_acc->account_id = 0;
  new_acc->unban_time = 0; 
  new_acc->expiration_time = 0;
  new_acc->login_count = 0; 
  new_acc->login_fail_count = 0;
  new_acc->last_login_time = 0; 
  new_acc->last_ip = 0;

  return new_acc;
}


void account_free(account_t *acc) {
  if (acc == NULL) {
    return;
  }
  memset(acc, 0, sizeof(account_t));
  free(acc);
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
//libscrypt_check returns 0 on match, -1 on mismatch/error
    int status = libscrypt_check(plaintext_password, acc->password_hash);

//Checking if the password mathces/ if the plaintext is matching the password, if 0 it matches, if there 1 then the password does not match
    if (status == 0) {
        return true;
    } else {
        log_message(LOG_WARNING,
                    "account_validate_password: Password mismatch for user %s",
                    acc->userid);
        return false;
    }
}



bool account_update_password(account_t *acc, const char *new_plaintext_password) {
// Preconditions guaranteed by caller: acc and new_plaintext_password are non-NULL

//1) Hash directly into acc->password_hash (size HASH_LENGTH)
    if (libscrypt_hash(
//Input new_plaintext_password bytes, length from strlen().
            (const unsigned char*) new_plaintext_password,
            strlen(new_plaintext_password),
//Outpu writes the encoded hash into acc->password_hash buffer.
            (unsigned char*) acc->password_hash,
// HASH_LENGTH defines the size of the output buffer.
            HASH_LENGTH
        ) != 0)
    {
// Log an error if hashing fails, preserving the old password_hash
        log_message(LOG_ERROR,
                    "account_update_password: scrypt hashing failed for user %s",
                    acc->userid);
        return false;
    }
// Force null termination libscrypt_hash should do this, but just in case)
    acc->password_hash[HASH_LENGTH - 1] = '\0';

    return true;
}


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
// Calls strlen() to count how many characters (not including the trailing '\0') are in new_email, and stores that in length.
    size_t length = strlen(new_email);
//Check for overflow: Compares length to EMAIL_LENGTH (the size of the acc->email array). Email length is 100 in account.h
    if (length >= EMAIL_LENGTH) {
        log_message(LOG_ERROR, "Email is too long. Max allowed is %d characters.", EMAIL_LENGTH - 1);
        return;
    }
//Begin character validation loop:
    for (size_t i = 0; i < length; i++) {
//Fetch & sanitize one byte at a time it reads the ith character from new_email. Casts to unsigned char so it can be safely passed to character‐testing functions.
        unsigned char c = (unsigned char)new_email[i];
//Check for invalid characters such as !isprint(c): rejects non-printable characters. isspace(c): rejects any whitespace (space, tab, newline). 
        if (!isprint(c) || isspace(c) || c == '\n' || c == '\r' || c == '\t') {
            log_message(LOG_ERROR, "Email contains invalid character: ASCII %d", c);
            return;
        }
    }
//Safe updating the email and minus the null byte character 
    strncpy(acc->email, new_email, EMAIL_LENGTH - 1);
    acc->email[EMAIL_LENGTH - 1] = '\0';
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

