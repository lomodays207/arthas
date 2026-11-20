package io.diagnostic.fixture;

public final class Workload {
    public String handleRequest(boolean shouldFail) throws InterruptedException {
        return handleRequest(shouldFail, 35);
    }

    public String handleRequest(boolean shouldFail, long latencyMillis) throws InterruptedException {
        Thread.sleep(latencyMillis);
        if (shouldFail) {
            throw new IllegalStateException("synthetic fixture failure");
        }
        return "synthetic fixture success";
    }

    public String idleProbe() {
        return "intentionally not invoked";
    }
}
