#include "account.h"

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

/*
    if account login failed or succeeded change the required account meta data to plus +1 (login_count , login_fail_count, last_login_time)(self explanatory)
    make sure that the last IP address connected from metadata (last_ip) be set correctly
    Whenever a user logs in successfully, their login_fail_count is set to 0
    Whenever a user fails to log in successfully, their login_count is set to 0
*/
void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  // remove the contents of this function and replace it with your own code.
  acc->login_count=acc->login_count+1;
  acc->login_fail_count=0;
  acc->last_ip=ip;

  //(void) acc;
  //(void) ip;
}

void account_record_login_failure(account_t *acc) {
   acc->login_count=0;
  acc->login_fail_count=acc->login_fail_count+1;
  // remove the contents of this function and replace it with your own code.
  //(void) acc;
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
    perror("snprintf failed");
    return false;
  }
  if ((size_t)message_success >= sizeof(message)) {
    fprintf(stderr, "snprintf output was truncated\n");
    return false;
  }

  ssize_t bytes_written = write(fd, message, message_success);

  if (bytes_written == -1) {
        perror("write failed");
        return false;
  }

  if (bytes_written != (ssize_t)strlen(message)) {
        fprintf(stderr, "Partial write occurred\n");
        return false;
  }
  //write(1, "Hello, stdout!\n", 15);
  // remove the contents of this function and replace it with your own code.
  //(void) acct;
  //(void) fd;
  return true;
}

