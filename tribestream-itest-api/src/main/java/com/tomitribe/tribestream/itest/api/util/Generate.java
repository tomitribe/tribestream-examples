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
package com.tomitribe.tribestream.itest.api.util;

import com.github.javafaker.Faker;
import com.tomitribe.tribestream.restapi.model.account.AccountItem;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * The intention of this class is to strengthen our testing by supplying random
 * data that fits our various policies for passwords, labels, usernames, etc.
 */
public class Generate {

    private final static Faker faker = new Faker();

    private Generate() {
    }

    /**
     * Passwords can be 8 to 64 characters long by default
     * Allows: Digits, Special characters, Lowercase and Uppercase
     */
    public static String password() {
        final List<CharacterRule> rules = new ArrayList<>();
        rules.add(new CharacterRule(EnglishCharacterData.Digit, 2));
        rules.add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
        rules.add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
        final PasswordGenerator generator = new PasswordGenerator();
        final int range = range(8, 64);
        return generator.generatePassword(range, rules);
    }

    public static String username() {
        return faker().name().username();
    }

    public static String keyid() {
        return UUID.randomUUID().toString();
    }

    public static Faker faker() {
        return faker;
    }

    /**
     * Usernames can be 2 to 128 characters long by default
     * Allows: Digits, Lowercase and Uppercase
     */
    public static String email() {
        return faker.internet().emailAddress();
    }

    public static AccountItem.AccountItemBuilder account() {
        return AccountItem.builder()
                .username(faker().name().username())
                .displayName(faker().name().fullName())
                .email(faker().internet().emailAddress());
    }

    public static int range(int min, int max) {
        return ThreadLocalRandom.current().nextInt(min, max);
    }

    public static long range(long min, long max) {
        return ThreadLocalRandom.current().nextLong(min, max);
    }
}
