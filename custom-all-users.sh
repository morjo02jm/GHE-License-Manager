#!/bin/bash

set -e

usage() {
cat << USAGE
Usage: $(basename "$0") [options]

OPTIONS:
  -h    Show this message
  -d    Display header row.
  -o    Print output to STDOUT. Optional.
  -a    Limit to admin users. Optional.
  -u    Limit to non-admin users. Optional.
  -s    Limit to suspended users. Optional.


USAGE
}

message() {
  echo " --> ${1}"
}

[ "$(whoami)" = "root" ] || {
  exec sudo -u root "$0" "$@"
  echo Run this script as the root user. >&2
  exit 1
}

FILE_PATH="/tmp/users-$(date +"%Y%m%d%H%M%S").csv"

DISPLAY_HEADER=
ADMIN_ONLY=
SUSPENDED_ONLY=
NOADMIN_ONLY=
USE_STDOUT=
QUERY=

while getopts "hdousav" OPTION; do
  case $OPTION in
    h)
      usage
      exit 2
      ;;
    d)
      DISPLAY_HEADER=1
      ;;
    a)
      ADMIN_ONLY="AND users.gh_role = 'staff' "
      ;;
    u)
      NOADMIN_ONLY="AND users.gh_role IS NULL "
      ;;
    s)
      SUSPENDED_ONLY="AND users.suspended_at IS NOT NULL "
      ;;
    o)
      USE_STDOUT=1
      ;;
    ?)
      usage
      exit
      ;;
  esac
done

HEADERS='"login", "email", "role", "ssh_keys", "org_memberships", "repos", "suspension_status", "last_logged_ip", "creation_date", "last_activity_date"'

QUERY="SELECT \
   users.login, \
   (SELECT IFNULL(ue.email, 'N/A') \
    FROM user_emails ue \
    JOIN email_roles er ON ue.id = er.email_id \
    WHERE ue.user_id = users.id AND er.role = 'primary') as email, \
    IF(users.gh_role='staff', 'admin', 'user') as role, \
    (SELECT COUNT(*) FROM public_keys WHERE public_keys.user_id = users.id) as ssh_keys, \
    (SELECT COUNT(DISTINCT teams.organization_id) \
     FROM teams \
     JOIN abilities ON teams.id = abilities.subject_id \
     WHERE abilities.actor_id = users.id \
     AND abilities.actor_type = 'User' \
     AND abilities.subject_type = 'Team') as org_memberships, \
   (SELECT COUNT(*) FROM repositories WHERE repositories.owner_id = users.id) as repos, \
   IF(users.suspended_at IS NULL, 'active', 'suspended') as suspension_status, \
   IFNULL(users.last_ip, 'N/A') as last_logged_ip, \
   users.created_at as created_date, \
   IFNULL(interactions.last_active_at, users.created_at) as last_activity_date \
 FROM users \
 LEFT OUTER JOIN interactions ON interactions.user_id = users.id \
 WHERE users.type <> 'Organization' \
 AND users.login <> 'ghost' \
  ${ADMIN_ONLY} \
  ${NOADMIN_ONLY} \
  ${SUSPENDED_ONLY} \
ORDER BY users.login \
INTO OUTFILE '${FILE_PATH}' \
FIELDS TERMINATED BY ',' \
ENCLOSED BY '\"' \
LINES TERMINATED BY '\n';"

[ ! -z $USE_STDOUT ] || {
  message "Saving list of users to '${FILE_PATH}'..."
}

mysql -u root -e "$QUERY" github_enterprise

[[ ! -z $USE_STDOUT ]] || {
  message "Done."
}

[[ -z $USE_STDOUT ]] || {
  if [[ ! -z $DISPLAY_HEADER ]]; then
    echo ${HEADERS}
  fi
  cat ${FILE_PATH}
  rm ${FILE_PATH}
}