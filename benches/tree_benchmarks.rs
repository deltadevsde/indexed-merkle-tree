use criterion::{black_box, criterion_group, criterion_main, Criterion};
use indexed_merkle_tree::{node::Node, sha256_mod, tree::IndexedMerkleTree, Hash};
use rand::Rng;

fn create_random_test_hash() -> Hash {
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 32] = rng.gen();
    sha256_mod(&random_bytes)
}

fn create_test_hash(value: u8) -> Hash {
    Hash::new([value; 32])
}

const SIZES: [usize; 3] = {
    // For CI/by default we only go from 2^10 to 2^12
    // modify this to include more sizes if you want to run locally
    let mut sizes = [0; 3];
    let mut i = 0;
    while i < 3 {
        sizes[i] = 1 << (i + 10);
        i += 1;
    }
    sizes
};

fn bench_tree_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Tree Creation");
    for size in SIZES.iter() {
        group.bench_with_input(format!("size_{}", size), size, |b, &size| {
            b.iter(|| IndexedMerkleTree::new_with_size(black_box(size)).unwrap());
        });
    }
    group.finish();
}

fn bench_node_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("Node Insertion");
    for size in SIZES.iter() {
        group.bench_with_input(format!("size_{}", size), size, |b, &size| {
            let mut tree = IndexedMerkleTree::new_with_size(size).unwrap();
            let mut new_node = Node::new_leaf(
                true,
                create_test_hash(1),
                create_test_hash(2),
                create_test_hash(3),
            );
            b.iter(|| {
                let _ = tree.insert_node(black_box(&mut new_node));
                // Reset the tree after each iteration
                tree = IndexedMerkleTree::new_with_size(size).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_non_membership_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Non-Membership Proof");
    group.warm_up_time(std::time::Duration::from_secs(5));

    for &size in SIZES.iter() {
        group.bench_with_input(format!("size_{}", size), &size, |b, &size| {
            // Setup: Create the tree and insert nodes once
            let mut tree = IndexedMerkleTree::new_with_size(size).unwrap();
            for i in 0..size / 2 {
                let mut node = Node::new_leaf(
                    true,
                    create_random_test_hash(),
                    create_random_test_hash(),
                    create_test_hash(1),
                );
                tree.insert_node(&mut node).unwrap();
            }

            b.iter_with_setup(
                || {
                    Node::new_leaf(
                        true,
                        create_random_test_hash(),
                        create_random_test_hash(),
                        create_random_test_hash(),
                    )
                },
                |non_existent_node| {
                    tree.generate_non_membership_proof(black_box(&non_existent_node))
                        .unwrap()
                },
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_tree_creation,
    bench_node_insertion,
    bench_non_membership_proof
);
criterion_main!(benches);
