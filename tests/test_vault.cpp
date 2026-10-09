#include "Credential.hpp"
#include "Vault.hpp"

#include <gtest/gtest.h>

// --- Credential ---

TEST(CredentialTest, ConstructorStoresAllFields) {
    Credential credential(1, "github.com", "tushar", "hunter2", "personal");

    EXPECT_EQ(credential.id(), 1);
    EXPECT_EQ(credential.site(), "github.com");
    EXPECT_EQ(credential.username(), "tushar");
    EXPECT_EQ(credential.password(), "hunter2");
    EXPECT_EQ(credential.notes(), "personal");
}

TEST(CredentialTest, NotesDefaultsToEmpty) {
    Credential credential(1, "site.com", "user", "pass");
    EXPECT_TRUE(credential.notes().empty());
}

TEST(CredentialTest, ConstructorRejectsEmptySite) {
    EXPECT_THROW(Credential(1, "", "user", "pass"), std::invalid_argument);
}

TEST(CredentialTest, ConstructorRejectsEmptyPassword) {
    EXPECT_THROW(Credential(1, "site.com", "user", ""), std::invalid_argument);
}

TEST(CredentialTest, ConstructorAllowsEmptyUsername) {
    EXPECT_NO_THROW(Credential(1, "site.com", "", "pass"));
}

TEST(CredentialTest, SetSiteRejectsEmpty) {
    Credential credential(1, "site.com", "user", "pass");
    EXPECT_THROW(credential.setSite(""), std::invalid_argument);
    EXPECT_EQ(credential.site(), "site.com");  // unchanged after the failed attempt
}

TEST(CredentialTest, SetPasswordRejectsEmpty) {
    Credential credential(1, "site.com", "user", "pass");
    EXPECT_THROW(credential.setPassword(""), std::invalid_argument);
    EXPECT_EQ(credential.password(), "pass");
}

TEST(CredentialTest, SettersUpdateFields) {
    Credential credential(1, "site.com", "user", "pass");
    credential.setSite("newsite.com");
    credential.setUsername("newuser");
    credential.setPassword("newpass");
    credential.setNotes("newnotes");

    EXPECT_EQ(credential.site(), "newsite.com");
    EXPECT_EQ(credential.username(), "newuser");
    EXPECT_EQ(credential.password(), "newpass");
    EXPECT_EQ(credential.notes(), "newnotes");
}

// --- Vault ---

TEST(VaultTest, StartsEmpty) {
    Vault vault;
    EXPECT_EQ(vault.size(), 0u);
    EXPECT_TRUE(vault.allCredentials().empty());
}

TEST(VaultTest, AddCredentialAssignsIncrementingIds) {
    Vault vault;
    // Read each id right away: the returned reference points into the
    // vault's vector and is invalidated by the next add.
    const int firstId = vault.addCredential("a.com", "u1", "p1").id();
    const int secondId = vault.addCredential("b.com", "u2", "p2").id();

    EXPECT_EQ(firstId, 1);
    EXPECT_EQ(secondId, 2);
    EXPECT_EQ(vault.size(), 2u);
}

TEST(VaultTest, AddCredentialRejectsDuplicateSiteAndUsername) {
    Vault vault;
    vault.addCredential("site.com", "user", "pass1");
    EXPECT_THROW(vault.addCredential("site.com", "user", "pass2"), std::invalid_argument);
    EXPECT_EQ(vault.size(), 1u);  // the rejected add did not leave a partial entry
}

TEST(VaultTest, AddCredentialDuplicateCheckIsCaseInsensitive) {
    Vault vault;
    vault.addCredential("Site.com", "User", "pass1");
    EXPECT_THROW(vault.addCredential("site.com", "user", "pass2"), std::invalid_argument);
}

TEST(VaultTest, AddCredentialAllowsSameSiteWithDifferentUsername) {
    Vault vault;
    vault.addCredential("site.com", "user1", "pass1");
    EXPECT_NO_THROW(vault.addCredential("site.com", "user2", "pass2"));
    EXPECT_EQ(vault.size(), 2u);
}

TEST(VaultTest, GetCredentialReturnsMutableReference) {
    Vault vault;
    vault.addCredential("site.com", "user", "pass");

    vault.getCredential(1).setPassword("newpass");
    EXPECT_EQ(vault.getCredential(1).password(), "newpass");
}

TEST(VaultTest, GetCredentialThrowsForMissingId) {
    Vault vault;
    EXPECT_THROW(vault.getCredential(999), std::out_of_range);
}

TEST(VaultTest, RemoveCredentialRemovesTheEntry) {
    Vault vault;
    vault.addCredential("site.com", "user", "pass");
    vault.removeCredential(1);

    EXPECT_EQ(vault.size(), 0u);
    EXPECT_THROW(vault.getCredential(1), std::out_of_range);
}

TEST(VaultTest, RemoveCredentialThrowsForMissingId) {
    Vault vault;
    EXPECT_THROW(vault.removeCredential(999), std::out_of_range);
}

TEST(VaultTest, SearchMatchesSiteCaseInsensitively) {
    Vault vault;
    vault.addCredential("GitHub.com", "user", "pass");

    auto matches = vault.searchCredentials("github");
    ASSERT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].site(), "GitHub.com");
}

TEST(VaultTest, SearchMatchesUsername) {
    Vault vault;
    vault.addCredential("site.com", "tushar.dev", "pass");

    auto matches = vault.searchCredentials("tushar");
    ASSERT_EQ(matches.size(), 1u);
}

TEST(VaultTest, SearchReturnsEmptyWhenNoMatch) {
    Vault vault;
    vault.addCredential("site.com", "user", "pass");

    EXPECT_TRUE(vault.searchCredentials("nonexistent").empty());
}

// This is the bug I caught by hand while building Phase 3: without
// persisting nextId across save/load, deleting an entry and reloading
// could let a new credential reuse an id that used to belong to
// something else. loadSnapshot() is how Storage restores that counter.
TEST(VaultTest, IdsAreNotReusedAfterLoadSnapshot) {
    Vault vault;
    vault.addCredential("a.com", "u", "p");
    vault.addCredential("b.com", "u", "p");
    vault.removeCredential(1);

    Vault reloaded;
    reloaded.loadSnapshot(std::vector<Credential>(vault.allCredentials()), vault.nextId());

    const Credential& added = reloaded.addCredential("c.com", "u", "p");
    EXPECT_EQ(added.id(), 3);
}

TEST(VaultTest, LoadSnapshotReplacesExistingContents) {
    Vault vault;
    vault.addCredential("old.com", "u", "p");

    std::vector<Credential> newContents;
    newContents.emplace_back(5, "new.com", "u2", "p2");
    vault.loadSnapshot(std::move(newContents), 6);

    EXPECT_EQ(vault.size(), 1u);
    EXPECT_EQ(vault.getCredential(5).site(), "new.com");
}
