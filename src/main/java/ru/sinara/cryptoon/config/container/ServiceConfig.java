package ru.sinara.cryptoon.config.container;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithName;

@ConfigMapping(prefix = "k8s.service", namingStrategy = ConfigMapping.NamingStrategy.KEBAB_CASE)
public interface ServiceConfig {
    String name();

    @WithName("subscriptions")
    SubscriptionsConfig subscriptions();

    @WithName("rest")
    RestConfig rest();
}
