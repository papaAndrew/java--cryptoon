package ru.sinara.cryptoon.service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.camel.BeanInject;
import org.apache.camel.language.bean.Bean;
import ru.sinara.cryptoon.jcsp.sign.ActionFactory;

@ApplicationScoped
public class Cryptoon {

    @BeanInject
    protected ActionFactory actionFactory;

    public Cryptoon() {
    }


}
