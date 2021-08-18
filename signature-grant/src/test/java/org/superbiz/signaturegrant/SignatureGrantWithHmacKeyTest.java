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
package org.superbiz.signaturegrant;

import com.tomitribe.tribestream.itest.api.Tribestream;
import com.tomitribe.tribestream.itest.api.util.Generate;
import com.tomitribe.tribestream.restapi.client.TribestreamClient;
import com.tomitribe.tribestream.restapi.model.account.AccountItem;
import com.tomitribe.tribestream.restapi.model.account.ChangeCredential;
import com.tomitribe.tribestream.restapi.model.account.ClientSecretItem;
import com.tomitribe.tribestream.restapi.model.account.CredentialsItem;
import com.tomitribe.tribestream.restapi.model.account.KeyItems;
import com.tomitribe.tribestream.restapi.model.account.PublicPrivateKeyItem;
import com.tomitribe.tribestream.restapi.model.account.SecretKeyItem;
import com.tomitribe.tribestream.restapi.model.base.EntityReference;
import com.tomitribe.tribestream.restapi.model.httpconnection.HttpConnectionItem;
import com.tomitribe.tribestream.restapi.model.httpsignatureprofile.HttpSignatureProfileItem;
import com.tomitribe.tribestream.restapi.model.oauth2profile.OAuth2ProfileItem;
import com.tomitribe.tribestream.restapi.model.routes.RouteItem;
import com.tomitribe.trixie.junit.Archive;
import com.tomitribe.trixie.junit.tomcat.Tomcat;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tomitribe.auth.signatures.Algorithm;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;

import javax.crypto.spec.SecretKeySpec;
import javax.ejb.Lock;
import javax.ejb.Singleton;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.StringReader;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static java.util.Collections.singletonList;
import static javax.ejb.LockType.READ;
import static javax.ws.rs.client.Entity.entity;
import static org.junit.Assert.assertEquals;
import static org.tomitribe.auth.signatures.Algorithm.HMAC_SHA256;

public class SignatureGrantWithHmacKeyTest {

    private static WebTarget gateway;

    @BeforeClass
    public static void setup() throws Exception {
        final Tomcat howdyService = startTestService();

        // Boot a fresh Tribestream install in a tmp directory
        // This is something you'd usually only to in a test case
        final Tribestream tag = Tribestream.tribestream().build();

        // Create a TribestreamClient with admin privileges
        // Use of the TribestreamClient is something you would use
        // in your own code to automate administration of the gateway
        final TribestreamClient admin = createAdmin(tag.toURI());

        // NOTE the TribestreamClient library is something that you
        // absolutely can use in your projects as an alternative to
        // the UI to automate administration of the TAG.

        // HTTP Signatures Profile
        final HttpSignatureProfileItem signatureProfileItem = admin.httpsignatureprofile().create(HttpSignatureProfileItem.builder()
                .name("Test Signature Profile")
                .signatureAlgorithm("hmac-sha256")
                .signatureHeader("Signature")
                .signaturePrefix("Signature")
                .signHeader("(request-target)")
                .signHeader("date")
                .signHeader("digest")
                .debugHeader("X-Signing-Status")
                .digestAlgorithms(singletonList("sha-256"))
                .build());

        // Create an Oauth 2.0 profile
        final OAuth2ProfileItem oAuth2ProfileItem = admin.oauth2profile().create(OAuth2ProfileItem.builder()
                .id("oauth-2.0-profile")
                .name("OAuth 2.0 Profile")
                .allowGrant("signature")
                .allowGrant("refresh_token")
                .httpSignatureProfile(signatureProfileItem.asReference())
                .externalSigning(KeyItems.builder()
                        .signingAlgorithm("RS256")
                        .publicPrivateKey(PublicPrivateKeyItem.builder()
                                .type("RSA")
                                .algorithm("RSA-SHA256")
                                .privateValue("-----BEGIN RSA PRIVATE KEY-----\n" +
                                        "MIIEogIBAAKCAQEAkspegJhNClHF7hdBP41zyYoQrR0L0m2JA/0Ctj2A4o2sJnNn\n" +
                                        "fxM6vi1HmhJUOERp7KRkUHWAqcW/aGYpdv/hIlS/vUQ+ZTnsZWlykiqj8eKZTY9H\n" +
                                        "U6pZpi+Sa3VC60Ar/nHWHVqbJcKMkoNZgrIcLr14jQrr4ZSYlaZEJUgCtAm7bHlX\n" +
                                        "l1PEHdxtQ3CY6gWkW2ynQXjq7wPxrhTbJHlRmaQmEczJa8VK+M2/K7k3Ys44UsfT\n" +
                                        "mS0c6lU1EfhvwCq38zQLjw2CQuVb9gnLvrA4CpeTS7XAeUOoa/n1AVPpK+pv0B1Z\n" +
                                        "tJXQu5u+boESjMDuk2QidTZzBymqedS9hxWCWwIDAQABAoIBAEYJYj+O6ysiSwLH\n" +
                                        "e60762PciQpf0nUrJ/WMMVAMVkNB/0I1S8s4vI1ig0hCuIZENhnfcbFl7uaR4DqK\n" +
                                        "i/woKB2+O+Gs/uxDT8QvJKgSyjgtuqFj3E9R9wYwqna08yHVc2gqnlNRGLdSdMmu\n" +
                                        "+/U8z++JHUyGSndN8+Nq+hajng6R4KsTre80IgK98En4jymgQuOhfzeThECc5LHN\n" +
                                        "wImetrwoOkuPaF0tyuiEyQsj2PIwctIQ5X5O2NQu/Y8u3Eip6DcFnWdMxZxNH8nH\n" +
                                        "f97bR7s46d2R49BnmIlw//pQ82BXSdQaMwPNjcJHpbWAUaLxWP/1GKce1pvmUZAg\n" +
                                        "4Wh7sMECgYEA0LNbMIAqmznjX8u1W/B5W5h4gFuIKPNAMy020P2CqFlOePOKLgJL\n" +
                                        "pI7yukVdmEjgHDGfNqtj+cNy7LHeEoemZUKmSLBcHCU/liki7t3ab4Kyd12FZgPd\n" +
                                        "HmbHWQbqEsu1jC3y/oA3g71kz2yko3t75xZ6hLZKkPr75zTTWS8BhmECgYEAtA8J\n" +
                                        "qRXAhx/JpCzWd5WMWHLhqKEQslyPADcESWClsEbeQ8s87yCw+BOVTVKmBkHpjLR+\n" +
                                        "nwwwg4NM7dE8axfuVF5bgXsYrcz/1l0QkgNiEkJQ/SB7173/7GlgvV7WBfK9nG+Y\n" +
                                        "D7hfCopS7u6v1G/hBnZJ2YJf1ofT9J4E8NSTyjsCgYBdjNhGgF0Y4bUDXuv3v26W\n" +
                                        "2VzCpMT/HjLb/duBiPHFhuq/GuQIxaykohM53hgbSCd1W+Tze5ZAAhWE9iIGilnT\n" +
                                        "MDIbiTpwv12mcOAg1L+ylpJrITfHx9mZZBbd2FSagkfqAzrWTCEWY5JJzHhsc9DR\n" +
                                        "gGkBDjmUjXzXYf2PD5wOYQKBgGwsDJW0J7IF+tHSzhWRlnscqUzxVmKREKgEZWLf\n" +
                                        "2SqJqMX5t2XBsg+XVD7bxDpGJtUNKnTKkeqwWusUpMOB4QB2n2quVSk02w4hYu8V\n" +
                                        "cTme9aDcfwohbzrMI/4gl1uDdT4iHKx1C0P9zc0VQDTT8dA8CCnQFVuAxmlS9Yzp\n" +
                                        "aNA5AoGATbUOFIQj8cQR3fTGGEpGKGJ8brm5iHnpULUdadhEZOfS44UAtTrcv6zO\n" +
                                        "9BaabZLZh0TkUo0kkFLwuucDWhf4XC7W0s39IcaowbkCG5uq56rxcRRdahP2nY0c\n" +
                                        "+X9nTdWCCdUYHx1wmg1/F//09iwq/TlQfJYja6xsoOGNI5jvMmE=\n" +
                                        "-----END RSA PRIVATE KEY-----\n")
                                .active(true)
                                .build())
                        .build())
                .header("Authorization")
                .prefix("bearer")
                .build()
        );

        // Create a load-balancing group called "hello-api"
        // and add our service to it
        admin.httpconnection().create(HttpConnectionItem.builder()
                .name("hello-api")
                .endpoint(howdyService.toURI().toASCIIString())
                .build());

        // Create a secured route to our hello-api load-balanced group
        admin.route().create(false, RouteItem.builder()
                .name("Hello API Secured")
                .modRewrite("RewriteRule \"^/hello/(.*)$\" \"%{API:hello-api}/test/howdy/$1\" [P,auth]")
                .profiles(singletonList(asReference(oAuth2ProfileItem)))
                .build());

        // Create a user account with a key
        admin.account().create(AccountItem.builder()
                .username("garfield")
                .email("garfield@garfield.com")
                .displayName("Garfield")
                .credentials(CredentialsItem.builder()
                        .secretKey(SecretKeyItem.builder()
                                .active(true)
                                .spec("HMAC-SHA256")
                                .id("A1EF365F04A326AE")
                                .value("2YZVeK5fvdvQagowW7cuacijmOY")
                                .build())
                        .build())
                .build()
        );

        // Create a client account with client credentials
        admin.account().create(AccountItem.builder()
                .username("test_client")
                .email("test_client@garfield.com")
                .displayName("Test Client")
                .credentials(CredentialsItem.builder()
                        .clientSecret(ClientSecretItem.builder()
                                .oAuth2ProfileRef(oAuth2ProfileItem.getId())
                                .value("test_secret")
                                .active(true)
                                .build())
                        .build())
                .build()
        );


        gateway = ClientBuilder.newClient().target(tag.toURI());

    }

    /**
     * In a real world setting before using the TAG in production you would
     * change the admin password.  This method changes the password of the
     * admin account to something random.
     *
     * Additionally, in a real-world scenario it is encouraged to avoid using
     * the build-in "admin" account and instead create an account for each
     * administrator with the appropriate privileges.  We'll do that as well,
     * however, we'll generate a person to be the admin.
     */
    public static TribestreamClient createAdmin(final URI tagURI) {
        // Create a TribestreamClient for the built-in admin account
        TribestreamClient admin = TribestreamClient.builder()
                .uri(tagURI)
                .username("admin")
                .password("admin")
                .verbose(true)
                .build();

        // Generate a new password for the admin account
        // In the real world you can pick one manually or
        // use your password generator of choice
        String newPassword = Generate.password();

        // Send a ChangeCredential API call to TAG
        admin.account().changeCredential("admin",
                ChangeCredential.builder()
                        .username("admin")
                        .oldPassword("admin")
                        .password(newPassword)
                        .build());

        // Rebuild the TribestreamClient so it now uses
        // the new password
        admin = admin.rebuild().username("admin").password(newPassword).build();

        // (Optional) Follow best practice and create an admin
        // account for each intended administrator.  For the
        // purposes of testing we'll generate a user to be
        // an admin in the system.
        final String username = Generate.username();
        final String password = Generate.password();
        final String email = Generate.email();

        // To give a user admin privileges grant them the
        // role of "gateway-admin"
        final AccountItem account = admin.account().create(
                AccountItem.builder()
                        .username(username)
                        .email(email)
                        .credentials(CredentialsItem.builder().password(password).build())
                        .roles(new String[]{"gateway-admin"})
                        .build());

        // Now finally, create a TribestreamClient for this new admin account
        // so we can use it for the remainder of our setup as we would in the
        // real world.
        return TribestreamClient.builder()
                .uri(tagURI)
                .username(account.getUsername())
                .password(password)
                .verbose(true)
                .build();
    }

    @Test
    public void test() throws Exception {

        final String accessToken;
        final Key key;

        { // Login to the API Gateway with a signed HTTP message
            final Algorithm algorithm = HMAC_SHA256;
            final Signature signature = new Signature("A1EF365F04A326AE", algorithm, null, "(request-target)", "date", "digest");
            final Signer signer = new Signer(secretKey("2YZVeK5fvdvQagowW7cuacijmOY", algorithm), signature);

            final String payload = "client_id=test_client&client_secret=test_secret&grant_type=signature";
            final String digest = digest(payload, "SHA-256");

            final Map<String, String> headers = new HashMap<>();
            headers.put("Date", now());
            headers.put("Content-Type", "application/x-www-form-urlencoded");
            headers.put("Digest", "sha-256=" + digest);
            headers.put("Signature", signer.sign("POST", "/oauth2/token", headers).toString());

            final String json = gateway.path("/oauth2/token").request()
                    .headers(new MultivaluedHashMap<>(headers))
                    .post(entity(payload, MediaType.APPLICATION_FORM_URLENCODED_TYPE))
                    .readEntity(String.class);

            final JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
            accessToken = jsonObject.getString("access_token");
            final String jwk = jsonObject.getString("key");
            key = Keys.decode(jwk.getBytes());
        }

        { // Send a secured request to our Hello API

            // Obtain the key name from jwk attributes
            final String kid = key.getAttribute("kid");

            // Create a signer with our new key id and key
            final Signature signature = new Signature(kid, HMAC_SHA256, null, "(request-target)", "date", "digest");
            final Signer signer = new Signer(key.getKey(), signature);

            // Create an hash our payload
            final String payload = "Isn't this cool?";
            final String digest = digest(payload, "SHA-256");

            // Create the headers for the request
            final Map<String, String> headers = new HashMap<>();
            headers.put("Date", now());
            headers.put("Content-Type", "text/plain");
            headers.put("Digest", "sha-256=" + digest);
            headers.put("Authorization", "bearer " + accessToken);
            headers.put("Signature", signer.sign("POST", "/hello/jason", headers).toString().replace("Signature ", ""));

            final Response response = gateway.path("/hello/jason").request()
                    .headers(new MultivaluedHashMap<>(headers))
                    .post(entity(payload, MediaType.TEXT_PLAIN_TYPE));

            assertEquals(200, response.getStatus());
            assertEquals("Hello, jason!  You sent 16 bytes.", response.readEntity(String.class));
        }
    }

    private String digest(final String payload, final String algorithm) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(algorithm);
            final byte[] bytes = digest.digest(payload.getBytes());
            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown digest: " + algorithm);
        }
    }

    private static SecretKeySpec secretKey(final String string, final Algorithm algorithm) {
        final byte[] keyValue = string.getBytes();
        return new SecretKeySpec(keyValue, algorithm.getJmvName());
    }

    private static String now() {
        final String dateFormatPattern = "EEE, dd MMM yyyy HH:mm:ss zzz";
        return new SimpleDateFormat(dateFormatPattern, Locale.US).format(new Date());
    }

    public static EntityReference asReference(final OAuth2ProfileItem item) {
        return EntityReference.builder()
                .id(item.getId())
                .name(item.getName())
                .displayName(item.getDisplayName())
                .build();
    }

    /**
     * We boot our little test service in a small TomEE server and return it
     */
    public static Tomcat startTestService() throws Exception {
        // Build a test app
        final File appJar = Archive.archive()
                .add(HowdyService.class)
                .add(SignatureGrantWithHmacKeyTest.class)
                .asJar();

        // Boot a TomEE with the test app
        return Tomcat.tomee71plus()
                .add("webapps/test/WEB-INF/beans.xml", "")
                .add("webapps/test/WEB-INF/lib/app.jar", appJar)
                .build();
    }

    /**
     * Small little test service 
     */
    @Lock(READ)
    @Singleton
    @Path("/howdy")
    public static class HowdyService {

        @POST
        @Path("{name}")
        @Consumes("*/*")
        @Produces(MediaType.TEXT_PLAIN)
        public String post(final @PathParam("name") String name, final String body) {
            return String.format("Hello, %s!  You sent %s bytes.", name, body.length());
        }

    }
}
