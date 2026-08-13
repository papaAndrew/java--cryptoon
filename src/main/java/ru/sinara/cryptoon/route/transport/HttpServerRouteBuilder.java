package ru.sinara.cryptoon.route.transport;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.model.rest.RestBindingMode;

public class HttpServerRouteBuilder extends RouteBuilder {
    public static final String DIRECT_SIGN = "direct://sign";

    @Override
    public void configure() throws Exception {
        restConfiguration()
            .host("localhost").port("{{quarkus.http.port}}")
            .bindingMode(RestBindingMode.json)
            .dataFormatProperty("autoDiscoverObjectMapper", "true")
        ;

        rest("/cryptoon")

            .post("/sign")
            .consumes("application/json")
            .produces("application/json")
            .to(DIRECT_SIGN)
        ;

        from(DIRECT_SIGN)
            .log("Received!!")
        ;
    }
}
