#!/bin/sh
set -e

echo "=== Seeding Active Directory test users and groups ==="

# 1. Create Organizational Units (OUs)
samba-tool ou create "ou=people"
samba-tool ou create "ou=groups"

# 2. Create Users in OU=people
# Note: --use-username-as-cn ensures the DN becomes CN=username,OU=people,DC=example,DC=com
samba-tool user create admin adminpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="admin" --given-name="admin"

samba-tool user create testuser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="testuser" --given-name="testuser"

samba-tool user create alloweduser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="alloweduser" --given-name="alloweduser"

samba-tool user create restricteduser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="restricteduser" --given-name="restricteduser"

samba-tool user create unlisteduser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="unlisteduser" --given-name="unlisteduser"

# 3. Create Groups in OU=groups
samba-tool group add AllowedGroup --groupou="ou=groups"
samba-tool group add RestrictedGroup --groupou="ou=groups"

# 4. Assign Group Memberships
samba-tool group addmembers AllowedGroup testuser,alloweduser
samba-tool group addmembers RestrictedGroup restricteduser

echo "=== Seeding complete! ==="