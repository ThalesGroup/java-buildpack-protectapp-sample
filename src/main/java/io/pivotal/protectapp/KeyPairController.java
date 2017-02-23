package io.pivotal.protectapp;

import com.ingrian.security.nae.NAEException;
import com.ingrian.security.nae.NAEPrivateKey;
import com.ingrian.security.nae.NAEPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;

import static io.pivotal.protectapp.Util.zip;

@RestController
final class KeyPairController {

    private final NAEPrivateKey privateKey;

    private final NAEPublicKey publicKey;

    @Autowired
    KeyPairController(NAEPrivateKey privateKey, NAEPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @RequestMapping(method = RequestMethod.GET, value = "/key-pair")
    Map<String, String> keyPair() {
        String privateKey;
        try {
            privateKey = Base64.getEncoder().encodeToString(this.privateKey.export());
        } catch (NAEException e) {
            privateKey = "Not Returned";
        }

        String publicKey = Base64.getEncoder().encodeToString(this.publicKey.export());

        return zip(new String[]{"private", "public"}, new String[]{privateKey, publicKey});
    }

}
