namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Tests the hand-rolled MS-DTYP security-descriptor scan used for
/// cannot-change-password detection. Fixtures are built as self-relative
/// binary descriptors per MS-DTYP 2.4.6 (SD), 2.4.5 (ACL), 2.4.4.11
/// (ACCESS_DENIED_OBJECT_ACE) and 2.4.2.2 (SID) — the BCL's
/// RawSecurityDescriptor cannot be used to generate them because it throws
/// PlatformNotSupportedException off Windows. One fully hand-derived static
/// fixture is included as an independent cross-check of the builder.
/// </summary>
public class LdapSecurityDescriptorTests
{
    private static readonly Guid ChangePasswordRight = new("ab721a53-1e2f-11d0-9819-00aa0040529b");
    private static readonly Guid ForceChangePasswordRight = new("00299570-246d-11d0-a768-00aa006e0529");

    private static readonly byte[] EveryoneSid = Sid(authority: 1, subAuthority: 0);   // S-1-1-0
    private static readonly byte[] SelfSid = Sid(authority: 5, subAuthority: 10);      // S-1-5-10
    private static readonly byte[] OtherSid = Sid(authority: 5, subAuthority: 11);     // S-1-5-11 (Authenticated Users)

    [Fact]
    public void DenyForEveryone_IsFlagged()
    {
        var sd = BuildSd(DenyObjectAce(ChangePasswordRight, EveryoneSid));

        Assert.True(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void DenyForSelfOnly_IsFlagged()
    {
        // Tooling variance exists: some writers set only the SELF deny.
        var sd = BuildSd(DenyObjectAce(ChangePasswordRight, SelfSid));

        Assert.True(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void DenyForBoth_IsFlagged()
    {
        var sd = BuildSd(
            DenyObjectAce(ChangePasswordRight, EveryoneSid),
            DenyObjectAce(ChangePasswordRight, SelfSid));

        Assert.True(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void AllowAcesOnly_IsNotFlagged()
    {
        var sd = BuildSd(
            AllowObjectAce(ChangePasswordRight, EveryoneSid),
            AllowObjectAce(ChangePasswordRight, SelfSid));

        Assert.False(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void DenyOnForceChangeRight_IsNotFlagged_GuidDiscrimination()
    {
        // A deny on the *reset* right must not read as the cannot-change flag.
        var sd = BuildSd(DenyObjectAce(ForceChangePasswordRight, EveryoneSid));

        Assert.False(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void DenyForUnrelatedTrustee_IsNotFlagged()
    {
        var sd = BuildSd(DenyObjectAce(ChangePasswordRight, OtherSid));

        Assert.False(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void DenyWithoutControlAccessMask_IsNotFlagged()
    {
        var sd = BuildSd(DenyObjectAce(ChangePasswordRight, EveryoneSid, accessMask: 0x20));

        Assert.False(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void DenyWithInheritedObjectTypePresent_IsStillFlagged()
    {
        // Layout shifts by 16 bytes when the inherited-object-type GUID is present.
        var sd = BuildSd(DenyObjectAce(ChangePasswordRight, EveryoneSid, includeInheritedType: true));

        Assert.True(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void MixedAcl_DenyAmongOtherAces_IsFlagged()
    {
        var sd = BuildSd(
            AllowObjectAce(ForceChangePasswordRight, EveryoneSid),
            DenyObjectAce(ChangePasswordRight, SelfSid),
            AllowObjectAce(ChangePasswordRight, OtherSid));

        Assert.True(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 1, 2, 3 })]
    public void MissingOrTruncatedDescriptor_IsUnreadable(byte[]? bytes)
    {
        Assert.Null(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(bytes));
    }

    [Fact]
    public void DaclNotPresent_IsUnreadable()
    {
        var sd = BuildSd(); // empty DACL, then clear the DACL-present control bit and offset
        sd[2] = 0x00; // control low byte: remove SE_DACL_PRESENT (0x0004)
        sd[16] = 0; sd[17] = 0; sd[18] = 0; sd[19] = 0;

        Assert.Null(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(sd));
    }

    [Fact]
    public void GarbageBytes_AreUnreadableNotThrowing()
    {
        var garbage = new byte[64];
        new Random(1234).NextBytes(garbage);
        garbage[0] = 1;                 // plausible revision
        garbage[2] = 0x04;              // DACL present
        garbage[16] = 20;               // DACL offset inside buffer
        garbage[17] = 0; garbage[18] = 0; garbage[19] = 0;

        // Must not throw regardless of what the "ACL" bytes contain.
        _ = LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(garbage);
    }

    [Fact]
    public void HandDerivedStaticFixture_IsFlagged()
    {
        // Independently hand-assembled from MS-DTYP (not via the builder):
        // self-relative SD, DACL at offset 20, one ACCESS_DENIED_OBJECT_ACE
        // (0x06) for the User-Change-Password right, trustee Everyone.
        var fixture = new byte[]
        {
            // SECURITY_DESCRIPTOR: rev=1, sbz=0, control=0x8004 (LE), owner=0, group=0, sacl=0, dacl=20
            0x01, 0x00, 0x04, 0x80,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x14, 0x00, 0x00, 0x00,
            // ACL: rev=4, sbz=0, size=48 (LE), count=1 (LE), sbz2=0
            0x04, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00,
            // ACE header: type=6 (deny object), flags=0, size=40 (LE)
            0x06, 0x00, 0x28, 0x00,
            // mask = 0x100 (control access)
            0x00, 0x01, 0x00, 0x00,
            // object flags = 0x1 (object type present)
            0x01, 0x00, 0x00, 0x00,
            // GUID ab721a53-1e2f-11d0-9819-00aa0040529b
            0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11,
            0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b,
            // SID S-1-1-0: rev=1, count=1, authority {0,0,0,0,0,1}, sub 0
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        };

        Assert.True(LdapPasswordChangeProvider.SecurityDescriptorDeniesChangePassword(fixture));
    }

    // ------------------------------------------------------------------
    // Binary fixture builders (MS-DTYP self-relative format)
    // ------------------------------------------------------------------

    private static byte[] Sid(byte authority, uint subAuthority)
    {
        var sid = new byte[12];
        sid[0] = 1;                     // revision
        sid[1] = 1;                     // sub-authority count
        sid[7] = authority;             // 6-byte authority, big-endian: low byte last
        BitConverter.GetBytes(subAuthority).CopyTo(sid, 8); // little-endian
        return sid;
    }

    private static byte[] DenyObjectAce(Guid right, byte[] sid, int accessMask = 0x100, bool includeInheritedType = false) =>
        ObjectAce(aceType: 0x06, right, sid, accessMask, includeInheritedType);

    private static byte[] AllowObjectAce(Guid right, byte[] sid) =>
        ObjectAce(aceType: 0x05, right, sid, accessMask: 0x100, includeInheritedType: false);

    private static byte[] ObjectAce(byte aceType, Guid right, byte[] sid, int accessMask, bool includeInheritedType)
    {
        var objectFlags = 0x1 | (includeInheritedType ? 0x2 : 0);
        var size = 4 + 4 + 4 + 16 + (includeInheritedType ? 16 : 0) + sid.Length;

        var ace = new byte[size];
        ace[0] = aceType;
        ace[1] = 0; // ace flags
        BitConverter.GetBytes((ushort)size).CopyTo(ace, 2);
        BitConverter.GetBytes(accessMask).CopyTo(ace, 4);
        BitConverter.GetBytes(objectFlags).CopyTo(ace, 8);
        right.ToByteArray().CopyTo(ace, 12);
        var sidOffset = 28 + (includeInheritedType ? 16 : 0);
        if (includeInheritedType)
            ForceChangePasswordRight.ToByteArray().CopyTo(ace, 28); // arbitrary inherited-type GUID
        sid.CopyTo(ace, sidOffset);
        return ace;
    }

    private static byte[] BuildSd(params byte[][] aces)
    {
        var acesLength = aces.Sum(a => a.Length);
        var aclSize = 8 + acesLength;
        var sd = new byte[20 + aclSize];

        sd[0] = 1;      // SD revision
        sd[2] = 0x04;   // control LE low byte: SE_DACL_PRESENT
        sd[3] = 0x80;   // control LE high byte: SE_SELF_RELATIVE
        BitConverter.GetBytes(20).CopyTo(sd, 16); // DACL offset

        sd[20] = 0x04;  // ACL revision (DS)
        BitConverter.GetBytes((ushort)aclSize).CopyTo(sd, 22);
        BitConverter.GetBytes((ushort)aces.Length).CopyTo(sd, 24);

        var offset = 28;
        foreach (var ace in aces)
        {
            ace.CopyTo(sd, offset);
            offset += ace.Length;
        }

        return sd;
    }
}
