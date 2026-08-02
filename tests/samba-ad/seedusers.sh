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

samba-tool user create nesteduser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="nesteduser" --given-name="nesteduser"

samba-tool user create distributionuser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="distributionuser" --given-name="distributionuser"

# Exists solely for the write-path probes in the smoke test, which MUTATE the
# password they are testing with. No assertion reads this account, and nothing
# else may start doing so: a probe that leaves it changed must not be able to
# break an unrelated leg. It is in no group beyond Domain Users, so the group
# legs cannot see it either.
samba-tool user create probeuser testpassword \
  --userou="ou=people" --use-username-as-cn \
  --surname="probeuser" --given-name="probeuser"

# 3. Create Groups in OU=groups
samba-tool group add AllowedGroup --groupou="ou=groups"
samba-tool group add RestrictedGroup --groupou="ou=groups"

# NestedOuter contains NestedInner, and nesteduser is a member of the inner
# group only. Resolving nesteduser as a member of NestedOuter therefore requires
# transitive expansion rather than a direct memberOf read.
samba-tool group add NestedOuter --groupou="ou=groups"
samba-tool group add NestedInner --groupou="ou=groups"

# A distribution group, not a security group. GetAuthorizationGroups() returns
# security groups only, so this is the fixture that distinguishes the two
# enumerations the provider unions together.
#
# The flag name is verified rather than trusted: if this image's samba-tool
# spells it differently the group would be created as a security group and the
# group-type assertion downstream would silently be testing nothing.
if samba-tool group add --help 2>&1 | grep -q -- "--group-type"; then
  samba-tool group add DistributionGroup --groupou="ou=groups" --group-type=Distribution
else
  echo "ERROR: samba-tool group add does not support --group-type on this image." >&2
  echo "       DistributionGroup would be created as a security group and the" >&2
  echo "       group-type assertion would be meaningless. Refusing to continue." >&2
  exit 1
fi

# 4. Assign Group Memberships
samba-tool group addmembers AllowedGroup testuser,alloweduser
samba-tool group addmembers RestrictedGroup restricteduser
samba-tool group addmembers NestedOuter NestedInner
samba-tool group addmembers NestedInner nesteduser
samba-tool group addmembers DistributionGroup distributionuser

# 5. Domain password policy
#
# Minimum password age set explicitly to zero rather than relying on the image's
# NOCOMPLEXITY handling to imply it. The smoke test changes a password and then
# immediately changes it back, which a non-zero minimum age would refuse -- and
# that refusal would surface as an opaque directory error rather than as
# anything naming password age.
samba-tool domain passwordsettings set --min-pwd-age=0

# Minimum length set to 9, deliberately NOT the provider's fallback of 6.
#
# The AD provider reads minPwdLength from the domain, and when that read fails it
# logs a warning and advertises 6. A test run against a domain whose minimum IS 6
# cannot tell the two apart. With 9 configured here, a password of 7 or 8
# characters is accepted under the fallback and rejected under a working read --
# which is what the smoke test asserts.
samba-tool domain passwordsettings set --min-pwd-length=9

# 6. Verify the fixtures rather than assuming them
#
# A fixture that was not created the way it was meant to be shows up otherwise
# as a confusing assertion failure several workflow steps later, with nothing
# in the log to explain it.
echo "=== Fixture verification ==="

# groupType is a bitmask: security groups have the 0x80000000 bit set, so a
# global security group reports -2147483646 and a global distribution group
# reports 2. Printed rather than parsed here; the assertion is below.
for group in AllowedGroup RestrictedGroup NestedOuter NestedInner DistributionGroup; do
  group_type=$(samba-tool group show "${group}" --attributes=groupType | grep -i '^groupType:' | awk '{print $2}')
  echo "  group ${group}: groupType=${group_type}"
done

DIST_TYPE=$(samba-tool group show DistributionGroup --attributes=groupType | grep -i '^groupType:' | awk '{print $2}')
if [ "${DIST_TYPE}" = "2" ]; then
  echo "  OK: DistributionGroup is a global distribution group (groupType=2)."
else
  echo "ERROR: DistributionGroup has groupType=${DIST_TYPE}, expected 2 (global distribution)." >&2
  echo "       It was created as a security group, which would make the group-type" >&2
  echo "       assertion in the smoke test meaningless." >&2
  exit 1
fi

for user in testuser alloweduser restricteduser unlisteduser nesteduser distributionuser probeuser; do
  memberships=$(samba-tool user show "${user}" --attributes=memberOf | grep -i '^memberOf:' | sed 's/^memberOf: *//' | tr '\n' ' ')
  primary=$(samba-tool user show "${user}" --attributes=primaryGroupID | grep -i '^primaryGroupID:' | awk '{print $2}')
  echo "  user ${user}: primaryGroupID=${primary:-none} memberOf=${memberships:-none}"
done

echo "=== Seeding complete! ==="