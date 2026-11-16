package io.floci.aws.services.kms;

import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.storage.AccountAwareStorageBackend;
import io.floci.aws.core.storage.InMemoryStorage;
import io.floci.aws.services.iam.ResourcePolicyProvider.ResourcePolicy;
import io.floci.aws.services.kms.model.KmsAlias;
import io.floci.aws.services.kms.model.KmsKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A key's policy is read in the account of its ARN, whoever is calling, and given to IAM as its resource policy. */
class KmsKeyOfAccountTest {

    private static final String OWNER = "111122223333";
    private static final String CALLER = "444455556666";
    private static final String REGION = "us-east-1";

    private KmsService callers;
    private KmsKey key;

    @BeforeEach
    void setUp() {
        AccountAwareStorageBackend<KmsKey> keys = new AccountAwareStorageBackend<>(new InMemoryStorage<>(), null, OWNER);
        AccountAwareStorageBackend<KmsAlias> aliases = new AccountAwareStorageBackend<>(new InMemoryStorage<>(), null,
                OWNER);
        KmsService owners = new KmsService(keys, aliases, new InMemoryStorage<>(), new RegionResolver(REGION, OWNER));
        callers = new KmsService(keys, aliases, new InMemoryStorage<>(), new RegionResolver(REGION, CALLER));
        key = owners.createKey("snapshot key", REGION);
        owners.createAlias("alias/snapshots", key.getKeyId(), REGION);
    }

    @Test
    void aKeysPolicyIsReadInTheAccountOfItsArn() {
        assertThat(callers.findKeyPolicy(key.getArn()).orElseThrow(), containsString(OWNER));
        assertEquals(Optional.empty(), callers.findKeyPolicy(key.getArn().replace(OWNER, CALLER)));
        assertEquals(Optional.empty(), callers.findKeyPolicy("arn:aws:kms:" + REGION + ":" + OWNER + ":alias/snapshots"));
        assertEquals(Optional.empty(), callers.findKeyPolicy("arn:aws:sqs:" + REGION + ":" + OWNER + ":queue"));
    }

    /**
     * A key's policy is its resource policy, owned by the account in its ARN even when that account holds no such key,
     * so another account's key is judged as cross-account; an alias or a key left open has none.
     */
    @Test
    void theProviderGivesAKeysPolicyAndOwnerAndNothingForAnAliasOrAnOpenKey() {
        KmsResourcePolicyProvider provider = new KmsResourcePolicyProvider(callers);
        List<ResourcePolicy> policies = provider.getResourcePolicies("redshift-serverless", key.getArn());
        assertEquals(1, policies.size());
        assertEquals(OWNER, policies.getFirst().ownerAccountId());
        assertThat(policies.getFirst().policyDocument(), containsString("kms:*"));
        String missing = "arn:aws:kms:" + REGION + ":777788889999:key/" + key.getKeyId();
        assertEquals(List.of(new ResourcePolicy(null, "777788889999")), provider.getResourcePolicies("kms", missing));
        assertTrue(provider.getResourcePolicies("kms", "arn:aws:kms:" + REGION + ":" + OWNER + ":alias/snapshots")
                .isEmpty());
        assertTrue(provider.getResourcePolicies("kms", "arn:aws:kms:" + REGION + ":" + OWNER + ":key/*").isEmpty());
        assertTrue(provider.getResourcePolicies("kms", "*").isEmpty());
    }
}
