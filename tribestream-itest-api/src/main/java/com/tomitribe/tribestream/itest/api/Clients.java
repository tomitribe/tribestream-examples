/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.tomitribe.tribestream.itest.api;

import com.tomitribe.tribestream.itest.api.util.Generate;
import com.tomitribe.tribestream.restapi.client.TribestreamClient;
import com.tomitribe.tribestream.restapi.model.account.AccountItem;
import com.tomitribe.tribestream.restapi.model.account.ChangeCredential;
import com.tomitribe.tribestream.restapi.model.account.CredentialsItem;

public class Clients {
    private Clients() {
    }

    /**
     * Resets the default admin password to a generated value and creates and returns
     * a separate admin account that can be used to continue with the bootstrapping
     * of the test scenario.
     *
     * This method is best run immediately after starting Tribestream in a testcase.
     */
    public static TribestreamClient createAdmin(final Tribestream tag) {
        return asNewAdmin(resetAdminPass(TribestreamClient.builder().verbose(true).uri(tag.toURI()).build()));
    }

    /**
     * We recommend not using the built-in admin account for everything.
     * This method will create a new admin account that can be used for testing.
     * The username, email and password will be generated.
     */
    public static TribestreamClient asNewAdmin(final TribestreamClient admin) {
        final String password = Generate.password();

        final AccountItem created = admin.account().create(AccountItem.builder()
                .username(Generate.username())
                .email(Generate.email())
                .credentials(CredentialsItem.builder()
                        .password(password)
                        .build())
                .roles("gateway-admin")
                .build());

        return admin.rebuild()
                .verbose(true)
                .username(created.getUsername())
                .password(password)
                .build();
    }

    /**
     * The first thing anyone should do after setting up Tribestream is
     * to reset the password on the build-in admin account.
     *
     * This method will reset the built-in admin account's default
     * password of "admin" to a new generated password.
     */
    public static TribestreamClient resetAdminPass(final TribestreamClient client) {

        final String password = Generate.password();

        // As the admin account
        client.rebuild()
                .username("admin")
                .password("admin")
                .build()
                // change the admin password
                .account().changeCredential("admin", ChangeCredential.builder()
                .username("admin")
                .oldPassword("admin")
                .password(password)
                .build()
        );

        // return a new client with that new password
        return client.rebuild()
                .verbose(true)
                .username("admin")
                .password(password)
                .build();
    }

    /**
     * Creates a TribestreamClient that is not logged in
     */
    public static TribestreamClient asAnonymous(final TribestreamClient client) {
        return client.rebuild().verbose(true)
                .build();
    }

    /**
     * Creates a TribestreamClient that is logged in as a user that does
     * not have admin access.  The user is generated.
     */
    public static TribestreamClient asUser(final TribestreamClient admin) {
        final String password = Generate.password();
        final AccountItem item = admin.account().create(Generate.account().
                credentials(CredentialsItem.builder()
                        .password(password)
                        .build())
                .build());

        return admin.rebuild().verbose(true)
                .username(item.getUsername())
                .password(password)
                .build();
    }

}
