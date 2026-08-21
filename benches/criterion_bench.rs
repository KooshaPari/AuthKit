//! Criterion benchmarks for `InMemorySessionStore` operations.
//!
//! Run with: `cargo bench --bench criterion_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use authkit::{InMemorySessionStore, SessionStore};
use rand::Rng;

fn bench_bind(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_store/bind");
    for token_len in [8, 32, 64, 128] {
        let state_token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(token_len)
            .map(char::from)
            .collect();
        let session_id = "bench-session";

        group.bench_with_input(
            BenchmarkId::new("state_token_len", token_len),
            &state_token,
            |b, state| {
                let store = InMemorySessionStore::new();
                b.iter(|| {
                    store.bind_state(black_box(state), black_box(session_id)).unwrap();
                });
            },
        );
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_store/verify");

    // Benchmark: verify a bound state (happy path — cache-hit-like)
    {
        let store = InMemorySessionStore::new();
        store.bind_state("bench-state", "bench-session").unwrap();

        group.bench_function("verify_bound", |b| {
            b.iter(|| {
                store.verify_state(black_box("bench-state"), black_box("bench-session")).unwrap();
            });
        });
    }

    // Benchmark: verify a state that does NOT exist (miss path)
    {
        let store = InMemorySessionStore::new();

        group.bench_function("verify_missing", |b| {
            b.iter(|| {
                store.verify_state(black_box("no-such-state"), black_box("no-such-session"))
                    .unwrap();
            });
        });
    }

    // Benchmark: verify with varying state-token lengths to exercise string
    // comparison cost.
    for token_len in [8, 32, 64, 128] {
        let state_token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(token_len)
            .map(char::from)
            .collect();

        let store = InMemorySessionStore::new();
        store.bind_state(&state_token, "bench-session").unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify_bound_token_len", token_len),
            &state_token,
            |b, state| {
                b.iter(|| {
                    store.verify_state(black_box(state), black_box("bench-session")).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_revoke(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_store/revoke");

    // Benchmark: revoke an existing binding
    {
        group.bench_function("revoke_existing", |b| {
            let store = InMemorySessionStore::new();
            store.bind_state("bench-revoke", "bench-session").unwrap();

            b.iter_custom(|iters| {
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    store.bind_state("bench-revoke", "bench-session").unwrap();
                    let start = std::time::Instant::now();
                    store.revoke_state(black_box("bench-revoke")).unwrap();
                    total += start.elapsed();
                }
                total
            });
        });
    }

    // Benchmark: revoke a non-existent binding (no-op path)
    {
        let store = InMemorySessionStore::new();

        group.bench_function("revoke_missing", |b| {
            b.iter(|| {
                store.revoke_state(black_box("no-such-state")).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_store/mixed");

    group.bench_function("bind_verify_revoke_cycle", |b| {
        let store = InMemorySessionStore::new();
        let mut counter: u64 = 0;

        b.iter(|| {
            counter += 1;
            let state = format!("state-{counter}");
            store.bind_state(&state, "session").unwrap();
            let _ = store.verify_state(&state, "session").unwrap();
            store.revoke_state(&state).unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_bind,
    bench_verify,
    bench_revoke,
    bench_mixed_workload,
);
criterion_main!(benches);
