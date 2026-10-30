use pq_libpep::core::rlwe_he::RlweHe;

#[derive(Debug)]
struct Bpr12Cost {
    input_bits: usize,
    cc_multiplications: usize,
    abstract_tree_depth: usize,
    relinearizations: usize,
    abstract_modulus_switch_layers: usize,
    base_polynomials: usize,
}

#[derive(Debug)]
struct SelectorCost {
    input_bits: usize,
    cc_multiplications: String,
    multiplicative_depth: usize,
    relinearizations: String,
    modulus_switch_levels: usize,
    plaintext_leaves: String,
}

#[derive(Debug)]
struct CurrentHeBudget {
    round_levels_observed: usize,
    product_levels_minimum: usize,
    synthesis_levels_optimistic: usize,

    // Observed on the existing N=2 toy synthesis:
    // nine-limb negacyclic product + direct rounding.
    toy_synthesis_levels_observed: usize,

    recursive_layers: usize,
    prf_levels_optimistic: usize,

    // Naively extrapolates the measured toy cost across
    // all recursive layers. This is a projection, not a
    // measurement of the full PRF.
    prf_levels_from_observed_toy: usize,

    available_levels: usize,
}

fn log2_power_of_two(value: usize) -> usize {
    assert!(
        value > 0 && value.is_power_of_two(),
        "value must be a positive power of two"
    );
    value.trailing_zeros() as usize
}

fn bpr12_cost(bits: usize) -> Bpr12Cost {
    assert!(
        bits > 0 && bits.is_power_of_two(),
        "BPR12 input size must be a positive power of two"
    );

    let abstract_tree_depth = log2_power_of_two(bits);
    let cc_multiplications = bits - 1;

    Bpr12Cost {
        input_bits: bits,
        cc_multiplications,
        abstract_tree_depth,
        relinearizations: cc_multiplications,
        abstract_modulus_switch_layers: abstract_tree_depth,
        base_polynomials: 2 * bits,
    }
}

fn selector_cost(bits: usize) -> SelectorCost {
    assert!(bits > 0, "selector input size must be greater than zero");

    // A full binary lookup tree requires 2^bits plaintext leaves.
    // Its selection circuit has bits - 1 multiplicative levels.
    let multiplicative_depth = bits.saturating_sub(1);

    SelectorCost {
        input_bits: bits,
        cc_multiplications: format!("2^{} - 1", bits - 1),
        multiplicative_depth,
        relinearizations: format!("2^{} - 1", bits - 1),
        modulus_switch_levels: multiplicative_depth,
        plaintext_leaves: format!("2^{}", bits),
    }
}

fn current_he_budget(input_bits: usize) -> CurrentHeBudget {
    // Previously measured on the N=256 coefficient-wise rounding test:
    // round_one_level_homomorphic entered at level 0 and returned at level 8.
    // This is an observation for that implementation, not a theoretical
    // lower bound for every possible rounding circuit.
    const OBSERVED_ROUND_LEVELS: usize = 8;

    // A ciphertext-ciphertext multiplication consumes at least one level
    // in the current HE implementation.
    const PRODUCT_LEVELS_MINIMUM: usize = 1;

    // Previously measured by:
    // test_encrypted_bpr12_synthesize_nine_limbs_negacyclic_n2
    //
    // The N=2 toy synthesis finished at level 40, using a custom
    // 41-prime RNS chain. It is not an N=256 measurement.
    const OBSERVED_TOY_SYNTHESIS_LEVELS: usize = 40;

    let evaluator = RlweHe::new();
    let recursive_layers = log2_power_of_two(input_bits);

    // Optimistic estimate only:
    // one level for a product + eight observed rounding levels.
    //
    // It excludes the actual cost of a complete, correctly carried
    // radix-17 synthesis circuit and must not be treated as an
    // implementation of the BPR12 synthesizer.
    let synthesis_levels_optimistic = PRODUCT_LEVELS_MINIMUM + OBSERVED_ROUND_LEVELS;

    let prf_levels_optimistic = recursive_layers * synthesis_levels_optimistic;

    // Simple extrapolation of the existing N=2 toy circuit over
    // the abstract recursive layers. This is intentionally naive:
    // it is useful to expose the depth mismatch, not to predict
    // the exact depth of a future optimized PRF.
    let prf_levels_from_observed_toy = recursive_layers * OBSERVED_TOY_SYNTHESIS_LEVELS;

    CurrentHeBudget {
        round_levels_observed: OBSERVED_ROUND_LEVELS,
        product_levels_minimum: PRODUCT_LEVELS_MINIMUM,
        synthesis_levels_optimistic,
        toy_synthesis_levels_observed: OBSERVED_TOY_SYNTHESIS_LEVELS,
        recursive_layers,
        prf_levels_optimistic,
        prf_levels_from_observed_toy,
        available_levels: evaluator.max_level(),
    }
}

fn print_bpr12(cost: &Bpr12Cost) {
    println!("----------------------------------------------");
    println!("BPR12 ABSTRACT RECURSIVE TREE");
    println!("input bits                  = {}", cost.input_bits);
    println!("internal synthesis nodes    = {}", cost.cc_multiplications);
    println!("abstract tree depth         = {}", cost.abstract_tree_depth);
    println!("relinearizations (one/node) = {}", cost.relinearizations);
    println!(
        "abstract tree layers        = {}",
        cost.abstract_modulus_switch_layers
    );
    println!("base polynomials             = {}", cost.base_polynomials);
}

fn print_selector(cost: &SelectorCost) {
    println!("----------------------------------------------");
    println!("GENERIC OBLIVIOUS SELECTOR TREE");
    println!("input bits                  = {}", cost.input_bits);
    println!("CC multiplications          = {}", cost.cc_multiplications);
    println!(
        "multiplicative depth        = {}",
        cost.multiplicative_depth
    );
    println!("relinearizations             = {}", cost.relinearizations);
    println!(
        "modulus-switch levels       = {}",
        cost.modulus_switch_levels
    );
    println!("plaintext leaves             = {}", cost.plaintext_leaves);
}

fn print_current_he_budget(budget: &CurrentHeBudget) {
    println!("----------------------------------------------");
    println!("CURRENT HE DEPTH BUDGET");
    println!(
        "round levels observed             = {}",
        budget.round_levels_observed
    );
    println!(
        "minimum product levels            = {}",
        budget.product_levels_minimum
    );
    println!(
        "optimistic levels per synthesis   = {}",
        budget.synthesis_levels_optimistic
    );
    println!(
        "observed N=2 toy synthesis levels = {}",
        budget.toy_synthesis_levels_observed
    );
    println!(
        "recursive PRF layers              = {}",
        budget.recursive_layers
    );
    println!(
        "optimistic PRF depth estimate     = {}",
        budget.prf_levels_optimistic
    );
    println!(
        "naive toy-path PRF estimate       = {}",
        budget.prf_levels_from_observed_toy
    );
    println!(
        "available default HE levels       = {}",
        budget.available_levels
    );

    println!();
    println!("INTERPRETATION");
    println!("The optimistic estimate excludes important synthesis costs.");
    println!("The measured N=2 toy synthesis finishes at level 40.");
    println!("The naive eight-layer projection is not a measured PRF circuit.");
    println!("Neither estimate demonstrates a working N=256 encrypted PRF.");
}

#[test]
fn compare_prf_circuit_costs() {
    println!();
    println!("==============================================");
    println!("        PRF / HE CIRCUIT COST COMPARISON");
    println!("==============================================");

    for bits in [1usize, 2, 4, 8] {
        println!();
        println!("==============================================");
        println!("INPUT SIZE = {} BITS", bits);
        println!("==============================================");

        print_bpr12(&bpr12_cost(bits));
        print_selector(&selector_cost(bits));
    }

    println!();
    println!("==============================================");
    println!("256-BIT CASE");
    println!("==============================================");

    let bpr12 = bpr12_cost(256);
    let selector = selector_cost(256);
    let he_budget = current_he_budget(256);

    print_bpr12(&bpr12);
    print_selector(&selector);
    print_current_he_budget(&he_budget);

    // Abstract BPR12 tree cost.
    assert_eq!(bpr12.cc_multiplications, 255);
    assert_eq!(bpr12.abstract_tree_depth, 8);

    // Previously measured arithmetic depths.
    assert_eq!(he_budget.round_levels_observed, 8);
    assert_eq!(he_budget.toy_synthesis_levels_observed, 40);

    // The abstract PRF has eight recursive layers for 256 input bits.
    assert_eq!(he_budget.recursive_layers, 8);

    assert_eq!(
        he_budget.prf_levels_optimistic,
        8 * he_budget.synthesis_levels_optimistic
    );

    assert_eq!(
        he_budget.prf_levels_from_observed_toy,
        he_budget.recursive_layers * he_budget.toy_synthesis_levels_observed
    );

    // Even the optimistic projection must be compared to the real
    // default chain rather than assumed to fit.
    assert!(
        he_budget.prf_levels_optimistic > he_budget.available_levels,
        "The optimistic full-PRF estimate unexpectedly fits the default chain; review this model"
    );

    assert!(
        he_budget.prf_levels_from_observed_toy > he_budget.available_levels,
        "The naive toy-path projection unexpectedly fits the default chain"
    );

    // The generic selector tree is exponentially large.
    assert_eq!(selector.multiplicative_depth, 255);

    println!();
    println!("==============================================");
    println!("FINAL INTERPRETATION");
    println!("==============================================");
    println!("BPR12 has 255 abstract internal synthesis nodes and depth 8.");
    println!("The existing N=2 synthesis consumed 40 HE levels.");
    println!(
        "The default chain exposes {} levels.",
        he_budget.available_levels
    );
    println!(
        "The naive eight-layer toy-path projection is {} levels.",
        he_budget.prf_levels_from_observed_toy
    );
    println!("This projection is a warning about depth, not a measured full-PRF cost.");
    println!("The N=256 encrypted synthesis and recursive PRF are not yet complete.");
    println!("NEXT: redesign synthesis depth before generalizing the circuit to N=256.");
    println!("The generic selector alternative would require 2^256 plaintext leaves.");
}

#[test]
fn report_naive_n256_full_limb_convolution_cost() {
    const N: usize = 256;

    // Existing implementation costs, relative to the input level.
    const SCALAR_PRODUCT_LEVELS: usize = 19;
    const CARRY_SAVE_GROUP_LEVELS: usize = 14;
    const NINE_LIMB_PREFIX_ADD_LEVELS: usize = 9;
    const ONE_LEVEL_ROUNDING_LEVELS: usize = 8;

    const DIGIT_PRODUCTS_PER_SCALAR_PRODUCT: usize = 45;
    const MAX_PRODUCTS_PER_CARRY_SAVE_GROUP: usize = 4;

    let coefficient_pairs = N * N;
    let encrypted_digit_products = coefficient_pairs * DIGIT_PRODUCTS_PER_SCALAR_PRODUCT;

    // Each output coefficient receives N signed scalar products.
    let groups_per_output =
        (N + MAX_PRODUCTS_PER_CARRY_SAVE_GROUP - 1) / MAX_PRODUCTS_PER_CARRY_SAVE_GROUP;

    let total_carry_save_groups = N * groups_per_output;

    // Current bounded implementation:
    // group four products, then merge the normalized groups using
    // balanced levels of nine-limb prefix addition.
    let mut groups_remaining = groups_per_output;
    let mut merge_rounds = 0usize;

    while groups_remaining > 1 {
        groups_remaining = (groups_remaining + 1) / 2;
        merge_rounds += 1;
    }

    let product_level = SCALAR_PRODUCT_LEVELS;
    let grouped_level = product_level + CARRY_SAVE_GROUP_LEVELS;

    let merged_level = grouped_level + merge_rounds * NINE_LIMB_PREFIX_ADD_LEVELS;

    let final_level = merged_level + ONE_LEVEL_ROUNDING_LEVELS;

    let required_rns_primes = final_level + 1;

    println!("==============================================");
    println!("NAIVE N=256 NINE-LIMB CONVOLUTION ESTIMATE");
    println!("==============================================");
    println!("Polynomial dimension             = {N}");
    println!("Coefficient pairs                = {coefficient_pairs}");
    println!("Digit-product circuits per pair  = {DIGIT_PRODUCTS_PER_SCALAR_PRODUCT}");
    println!("Total digit-product circuits     = {encrypted_digit_products}");
    println!("Products per carry-save group    = {MAX_PRODUCTS_PER_CARRY_SAVE_GROUP}");
    println!("Carry-save groups per coefficient= {groups_per_output}");
    println!("Total carry-save groups          = {total_carry_save_groups}");
    println!("Merge rounds                     = {merge_rounds}");
    println!("Level after scalar product       = {product_level}");
    println!("Level after carry-save grouping  = {grouped_level}");
    println!("Level after merging              = {merged_level}");
    println!("Level after one-level rounding   = {final_level}");
    println!("Required RNS primes (projection) = {required_rns_primes}");
    println!();
    println!("This is a projection for the naive grouped implementation,");
    println!("not a measured benchmark or a lower bound on every design.");
    println!("It excludes security parameter validation and memory costs.");

    assert_eq!(coefficient_pairs, 65_536);
    assert_eq!(encrypted_digit_products, 2_949_120);
    assert_eq!(groups_per_output, 64);
    assert_eq!(total_carry_save_groups, 16_384);
    assert_eq!(merge_rounds, 6);
    assert_eq!(grouped_level, 33);
    assert_eq!(merged_level, 87);
    assert_eq!(final_level, 95);
    assert_eq!(required_rns_primes, 96);
}
