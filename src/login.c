// login.c

#include "login.h"
#include "account.h"
#include "db.h"
#include "logging.h"

login_result_t handle_login(const char *userid,
                            const char *password,
                            ip4_addr_t client_ip,
                            time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session)
{
  // 1) Validate inputs
  if (!userid || !password) {
    log_message(LOG_ERROR,
                "handle_login: null userid or password");
    return LOGIN_FAIL_INTERNAL_ERROR;
  }

  // 2) Lookup account
  account_t acc = {0};
  if (!account_lookup_by_userid(userid, &acc)) {
    log_message(LOG_WARN,
                "handle_login: user '%s' not found", userid);
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  // 3) Check ban
  if (account_is_banned(&acc)) {
    log_message(LOG_WARN,
                "handle_login: user '%s' is banned", userid);
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }

  // 4) Check expiration
  if (account_is_expired(&acc)) {
    log_message(LOG_WARN,
                "handle_login: user '%s' account expired", userid);
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  // 5) Throttle on too many failures
  if (acc.login_fail_count > 10) {
    log_message(LOG_WARN,
                "handle_login: user '%s' too many failed attempts (%u)",
                userid, acc.login_fail_count);
    return LOGIN_FAIL_INTERNAL_ERROR;
  }

  // 6) Validate password
  if (!account_validate_password(&acc, password)) {
    log_message(LOG_WARN,
                "handle_login: bad password for '%s'", userid);
    account_record_login_failure(&acc);
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  // 7) On success, record it
  account_record_login_success(&acc, client_ip);

  // 8) Populate session data (if requested)
  if (session) {
    session->account_id      = acc.account_id;
    session->session_start   = login_time;
    session->expiration_time = login_time + 3600;  // e.g. 1 hour session
  }

  // 9) Send summary to client
  if (!account_print_summary(&acc, client_output_fd)) {
    log_message(LOG_ERROR,
                "handle_login: failed to send summary for '%s'",
                userid);
    return LOGIN_FAIL_INTERNAL_ERROR;
  }

  // 10) Log success
  log_message(LOG_INFO,
              "handle_login: user '%s' logged in (IP=%u)",
              userid, client_ip);

  return LOGIN_SUCCESS;
}
