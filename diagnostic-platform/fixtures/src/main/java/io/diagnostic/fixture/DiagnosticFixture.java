package io.diagnostic.fixture;

import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

public final class DiagnosticFixture {
    private static final String WORKLOAD_CLASS = "io.diagnostic.fixture.Workload";

    private DiagnosticFixture() {
    }

    public static void main(String[] args) throws Exception {
        Workload workload = new Workload();
        workload.handleRequest(false);
        Object isolated = new WorkloadLoader().loadClass(WORKLOAD_CLASS)
                .getDeclaredConstructor().newInstance();
        startLoad(workload,Boolean.getBoolean("diagnostic.fixture.measure"));
        startBlockedThread();
        System.out.println("FIXTURE_READY");
        new CountDownLatch(1).await();
        System.out.println(isolated);
    }

    private static void startLoad(Workload workload, boolean measure) {
        Thread load = new Thread(() -> {
            boolean shouldFail = false;
            long[] samples = new long[16];
            int count = 0;
            int errors = 0;
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    long start = System.nanoTime();
                    try {
                        workload.handleRequest(shouldFail);
                    } catch (IllegalStateException expected) {
                        errors++;
                        if (!shouldFail) {
                            throw expected;
                        }
                    }
                    if (measure) {
                        samples[count++] = System.nanoTime() - start;
                        if (count == samples.length) {
                            Arrays.sort(samples);
                            System.out.println("FIXTURE_WINDOW " + System.currentTimeMillis() + " " + count + " "
                                    + errors + " " + samples[(int) Math.ceil(.95 * count) - 1]);
                            count = 0;
                            errors = 0;
                        }
                    }
                    shouldFail = !shouldFail;
                    Thread.sleep(120);
                }
            } catch (InterruptedException stop) {
                Thread.currentThread().interrupt();
            }
        }, "fixture-load");
        load.setDaemon(true);
        load.start();
    }

    private static void startBlockedThread() throws InterruptedException {
        Object monitor = new Object();
        CountDownLatch acquired = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            synchronized (monitor) {
                acquired.countDown();
                try {
                    new CountDownLatch(1).await();
                } catch (InterruptedException stop) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "fixture-lock-holder");
        holder.setDaemon(true);
        holder.start();
        acquired.await();
        Thread blocked = new Thread(() -> {
            synchronized (monitor) {
                // Acquired only if the holder exits.
            }
        }, "fixture-lock-blocked");
        blocked.setDaemon(true);
        blocked.start();
    }

    private static final class WorkloadLoader extends ClassLoader {
        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!WORKLOAD_CLASS.equals(name)) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    try (InputStream bytes = getParent().getResourceAsStream(
                            name.replace('.', '/') + ".class")) {
                        if (bytes == null) {
                            throw new ClassNotFoundException(name);
                        }
                        java.io.ByteArrayOutputStream copy = new java.io.ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int count;
                        while ((count = bytes.read(buffer)) != -1) {
                            copy.write(buffer, 0, count);
                        }
                        byte[] data = copy.toByteArray();
                        loaded = defineClass(name, data, 0, data.length);
                    } catch (java.io.IOException error) {
                        throw new ClassNotFoundException(name, error);
                    }
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }
    }
}
