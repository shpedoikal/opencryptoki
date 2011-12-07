
//package com.ibm.crypto.pkcs11impl.provider;

import javax.security.auth.callback.Callback;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.security.auth.callback.*;

public class NullPrompter implements javax.security.auth.callback.CallbackHandler {

    private String userName;
    private char[] authenticator;

    private NullPrompter() { // hide the null constructor, since we're not prompting!
    }

    public NullPrompter(String userName, char authenticator[]) {
        this.userName = userName;
        this.authenticator = authenticator;
    }

    public void nukeEm() {
        this.userName = null;
        for (int i = 0; i < authenticator.length; i++)
                    authenticator[i] = ' ';
    }

    public void handle(Callback[] callbacks)
    throws IOException, UnsupportedCallbackException {

            for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof TextOutputCallback) {

            } else if (callbacks[i] instanceof TextInputCallback) {
                ((TextInputCallback)callbacks[i]).setText(userName);

            } else if (callbacks[i] instanceof PasswordCallback) {
            ((PasswordCallback)callbacks[i]).setPassword(authenticator);
            } else {
                throw new UnsupportedCallbackException
                        (callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
