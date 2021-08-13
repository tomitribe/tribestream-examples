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

import com.tomitribe.trixie.junit.CleanOnExit;
import com.tomitribe.trixie.junit.Pipe;
import com.tomitribe.trixie.junit.Ports;
import com.tomitribe.trixie.junit.ServerBuilder;
import com.tomitribe.trixie.junit.StartupFailedException;
import com.tomitribe.trixie.junit.TarGzs;
import org.tomitribe.swizzle.stream.StreamBuilder;
import org.tomitribe.util.Files;
import org.tomitribe.util.IO;
import org.tomitribe.util.JarLocation;
import org.tomitribe.util.hash.XxHash64;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * TODO: Cassandra needs random ports
 * TODO: Hazelcast needs random ports
 */
public class Tribestream implements Supplier<URI> {

    private final File home;
    private final int port;
    private final Process process;

    private Tribestream(final File home, final int port, final Process process) {
        this.home = home;
        this.port = port;
        this.process = process;
    }

    @Override
    public URI get() {
        return toURI();
    }

    public URI toURI() {
        return URI.create("http://localhost:" + port);
    }

    public File getHome() {
        return home;
    }

    public int getPort() {
        return port;
    }

    public Process getProcess() {
        return process;
    }

    public void shutdown() {
        try {
            process.destroy();
            process.waitFor();
        } catch (Exception e) {
            throw new IllegalStateException("Shutdown failed", e);
        }
    }

    public static Builder tribestream() throws Exception {
        final String version = System.getProperty("itest.tribestream.version", Version.VERSION);
        return of(mvn("tribestream-api-gateway", version, "tar.gz"));
    }

    private static File mvn(final String artifact, final String version, final String packaging) {

        File file = JarLocation.jarLocation(XxHash64.class);
        while (!file.getName().equals("org")) {
            file = file.getParentFile();
        }

        final File tarGz = Files.file(file.getParentFile(), "com/tomitribe/tribestream", artifact, version, String.format("%s-%s.%s", artifact, version, packaging));
        Files.exists(tarGz);
        Files.file(tarGz);
        Files.readable(tarGz);
        return tarGz;
    }

    public static Builder of(final String mavenCoordinates) throws Exception {
        return new Builder(mavenCoordinates);
    }

    public static Builder of(final File archive) throws Exception {
        return new Builder(archive);
    }

    public static class Builder extends ServerBuilder<Builder> {

        private int http;
        private int shutdown;
        private int ajp;
        private boolean deleteOnExit = true;

        public Builder(final String mavenCoordinates) throws IOException {
            super(mavenCoordinates);
            await(3, TimeUnit.MINUTES);
        }

        public Builder(final File archive) throws IOException {
            super(archive);
            await(3, TimeUnit.MINUTES);
        }

        public boolean deleteOnExit() {
            return this.deleteOnExit;
        }

        public Builder deleteOnExit(final boolean deleteOnExit) {
            this.deleteOnExit = deleteOnExit;
            return this;
        }

        public int http() {
            return this.http;
        }

        public int shutdown() {
            return this.shutdown;
        }

        public int ajp() {
            return this.ajp;
        }

        public Builder http(final int http) {
            this.http = http;
            return this;
        }

        public Builder shutdown(final int shutdown) {
            this.shutdown = shutdown;
            return this;
        }

        public Builder ajp(final int ajp) {
            this.ajp = ajp;
            return this;
        }

        public Builder debug() {
            return debug(5005);
        }

        public Builder debug(final int port) {
            return env("JAVA_OPTS", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=" + port);
        }


        public Builder hazelcast(final int port) {
            home(home -> setHazelcastPort(home, port));
            return this;
        }

        private void setHazelcastPort(final File home, final int port) {

            // by default the gateway will grab the hazelcast.xml and boot up the cluster using that file so we are good
            // not that tomee.xml allows to change the default hazelcast.xml file to something else.
            // make sure to change this logic if the default changes

            try {
                final File xml = Files.file(home, "conf", "hazelcast.xml");
                final String config = IO.slurp(xml)
                        .replaceAll("(<port auto-increment=\"true\" port-count=\"128\">)[0-9]+(</port>)", "$1" + port + "$2");
                IO.copy(IO.read(config), xml);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private int select(int a, int b) {
            return a > 1 ? a : b;
        }

        public Builder update() {
            home(this::update);
            return this;
        }

        private void update(final File home) {
            final File repository = JarLocation.jarLocation(XxHash64.class)
                    .getParentFile() // jar
                    .getParentFile() // version dir
                    .getParentFile() // tomitribe-util
                    .getParentFile() // tomitribe
                    .getParentFile();// org

            final File com = Files.file(repository, "com", "tomitribe");
            final File org = Files.file(repository, "org", "tomitribe");

            final Map<String, File> map = new HashMap<>();

            Stream.concat(
                    Files.collect(com, ".*\\.jar").stream(),
                    Files.collect(org, ".*\\.jar").stream()
            ).forEach(file -> map.put(file.getName(), file));

            final File lib = new File(home, "lib");
            for (final File jar : Files.collect(lib, ".*\\.jar")) {
                final File file = map.get(jar.getName());
                if (file != null && file.lastModified() > jar.lastModified()) {
                    try {
                        System.out.printf("Updating %s%n", jar.getName());
                        IO.copy(file, jar);
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                }
            }
        }

        public Tribestream build() throws IOException {

            applyBuilderConsumers();

            final CleanOnExit cleanOnExit = new CleanOnExit();
//            final File tmpdir = Files.tmpdir();
            final File tmpdir = deleteOnExit ? cleanOnExit.clean(Files.tmpdir()) : Files.tmpdir();

            final File home;
            { // extract the server
                home = new File(tmpdir, "gateway");
                Files.mkdir(home);
                TarGzs.untargz(archive, home, true, filter);
            }

            { // randomize Hazelcast port in the hazelcast.xml
                final int port = Ports.allocate();
                setHazelcastPort(home, port);
            }

            final int cassandraPort;
            { // randomize Cassandra ports and properly configure tomee.xml to point to the right instance
                // pointing to a different keyspace could work if we could make sure the cassandra instance is big enough
                // to handle running integration tests in parallel. Also we would need to decouple Cassandra lifecycle from
                // the Gateway. Currently it's lazily loaded from the tribestream.sh so when the Gateway stops, Cassandra also stops
                final Iterator<Integer> ports = Ports.allocate(4).iterator();
                cassandraPort = ports.next();

                // todo why do we have a yaml file under conf/ whereas the one used is the one from cassandra/conf???
                updateFile(content -> content.replace("native_transport_port: 9042", "native_transport_port: " + cassandraPort + "")
                                .replace("storage_port: 7000", "storage_port: " + ports.next() + "")
                                .replace("rpc_port: 9160", "rpc_port: " + ports.next() + "")
                                .replace("ssl_storage_port: 7001", "ssl_storage_port: " + ports.next() + ""),
                        home, "cassandra", "conf", "cassandra.yaml");

            }

            {
                final Iterator<Integer> ports = Ports.allocate(1).iterator();
                updateFile(content -> content.replace("JMX_PORT=\"7199\"", "JMX_PORT=\"" + ports.next() + "\""),
                        home, "cassandra", "conf", "cassandra-env.sh");

            }

            {
                // make sure to update Cassandra authorities in tomee.xml or we'll for sure connect to the wrong cassandra instance
                updateFile(content -> content.replace("cassandraAuthorities = localhost:9042", "cassandraAuthorities = localhost:" + cassandraPort + ""),
                        home, "conf", "tomee.xml");
            }

            applyModifications(home);

            final int http;
            { // set random ports
                final Iterator<Integer> ports = Ports.allocate(3).iterator();
                http = select(this.http, ports.next());

                updateFile(content -> content.replace("8080", http + "")
                                .replace("8005", select(shutdown, ports.next()) + "")
                                .replace("8009", select(ajp, ports.next()) + ""),
                        home, "conf", "server.xml");
            }

            applyHomeConsumers(home);

            final File catalinaSh = Files.file(home, "bin", "tribestream.sh");

            final ProcessBuilder builder = new ProcessBuilder()
                    .directory(home)
                    .command(catalinaSh.getAbsolutePath());

            builder.environment().putAll(env);

            if (list) Files.visit(tmpdir, Tribestream::print);

            final Process process = cleanOnExit.clean(builder.start());

            final CountDownLatch startup = new CountDownLatch(1);

            final StreamBuilder inputStream = StreamBuilder.create(process.getInputStream());
            final StreamBuilder errorStream = StreamBuilder.create(process.getErrorStream())
                    .watch("Server startup in ", startup::countDown);

            for (final Consumer<StreamBuilder> watch : watches) {
                watch.accept(inputStream);
            }

            for (final Consumer<StreamBuilder> watch : watches) {
                watch.accept(errorStream);
            }

            final Future<Pipe> stout = Pipe.pipe(inputStream.get(), System.out);
            final Future<Pipe> sterr = Pipe.pipe(errorStream.get(), System.err);

            try {
                if (!startup.await(await.getTime(), await.getUnit())) {
                    throw new StartupFailedException("Waited " + await.toString());
                }
            } catch (InterruptedException e) {
                throw new StartupFailedException(e);
            }

            return new Tribestream(home, http, process);
        }
    }

    private static void updateFile(final Function<String, String> processor, final File base, final String... parts) {
        final File file = Files.file(base, parts);

        try {
            final String updatedFileContent = processor.apply(IO.slurp(file));
            IO.copy(IO.read(updatedFileContent), file);

        } catch (final IOException e) {
            throw new IllegalArgumentException("Unable to update file " + file, e);
        }
    }

    private static boolean print(final File file) {
        System.out.println(file.getAbsolutePath());
        return true;
    }

}
