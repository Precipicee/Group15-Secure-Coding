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
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) ip;
}

void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}

bool account_is_banned(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_email(account_t *acc, const char *new_email) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_email;
}

bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void) acct;
  (void) fd;
  return false;
}

