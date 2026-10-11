#[derive(Debug)]
struct Bpr12Cost {
    input_bits: usize,
    cc_multiplications: usize,
    multiplicative_depth: usize,
    relinearizations: usize,
    modulus_switch_levels: usize,
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

    /*
     * BPR12 structure:
     *
     * input bits:
     *
     *   b0  b1  b2  ...  b_(n-1)
     *   ↓
     *   n leaf positions
     *
     * Each internal tree node performs one polynomial
     * multiplication:
     *
     *     left * right
     *
     * A balanced binary tree with n leaves has:
     *
     *     n - 1
     *
     * internal nodes.
     *
     * Therefore:
     *
     *     CC multiplications = n - 1
     *
     * For powers of two:
     *
     *     multiplicative depth = log2(n)
     */

    let depth = log2_power_of_two(bits);

    let cc_multiplications = bits - 1;

    /*
     * Every CC multiplication is followed by
     * relinearization in our current HE design.
     */
    let relinearizations = cc_multiplications;

    /*
     * One modulus-switch step per multiplicative layer.
     */
    let modulus_switch_levels = depth;

    /*
     * The BPR12 base stores s0 and s1 for every
     * input position.
     *
     * Therefore there are:
     *
     *     2 * bits
     *
     * base polynomials.
     */
    let base_polynomials = 2 * bits;

    Bpr12Cost {
        input_bits: bits,
        cc_multiplications,
        multiplicative_depth: depth,
        relinearizations,
        modulus_switch_levels,
        base_polynomials,
    }
}

fn selector_cost(bits: usize) -> SelectorCost {
    assert!(
        bits > 0,
        "selector input size must be greater than zero"
    );

    /*
     * A generic oblivious lookup tree has:
     *
     *     2^bits
     *
     * plaintext leaves.
     *
     * The first level performs:
     *
     *     ciphertext * plaintext
     *
     * so it does NOT consume CC multiplicative depth.
     *
     * Every following level performs:
     *
     *     ciphertext * ciphertext
     *
     * There are therefore:
     *
     *     2^(bits-1) - 1
     *
     * CC multiplications.
     *
     * The number of CC levels is:
     *
     *     bits - 1
     */

    let multiplicative_depth =
        bits.saturating_sub(1);

    /*
     * For normal test sizes we can print the exact
     * number. For 256 bits we keep it symbolic because
     * 2^256 does not fit in usize/u128.
     */
    let cc_multiplications =
        format!("2^{} - 1", bits - 1);

    let relinearizations =
        format!("2^{} - 1", bits - 1);

    let plaintext_leaves =
        format!("2^{}", bits);

    SelectorCost {
        input_bits: bits,
        cc_multiplications,
        multiplicative_depth,
        relinearizations,
        modulus_switch_levels: multiplicative_depth,
        plaintext_leaves,
    }
}

fn print_bpr12(cost: &Bpr12Cost) {
    println!("----------------------------------------------");
    println!("BPR12 / RECURSIVE RLWR TREE");
    println!("input bits             = {}", cost.input_bits);
    println!(
        "CC multiplications     = {}",
        cost.cc_multiplications
    );
    println!(
        "multiplicative depth   = {}",
        cost.multiplicative_depth
    );
    println!(
        "relinearizations       = {}",
        cost.relinearizations
    );
    println!(
        "modulus-switch levels  = {}",
        cost.modulus_switch_levels
    );
    println!(
        "base polynomials       = {}",
        cost.base_polynomials
    );
}

fn print_selector(cost: &SelectorCost) {
    println!("----------------------------------------------");
    println!("GENERIC OBLIVIOUS SELECTOR TREE");
    println!("input bits             = {}", cost.input_bits);
    println!(
        "CC multiplications     = {}",
        cost.cc_multiplications
    );
    println!(
        "multiplicative depth   = {}",
        cost.multiplicative_depth
    );
    println!(
        "relinearizations       = {}",
        cost.relinearizations
    );
    println!(
        "modulus-switch levels  = {}",
        cost.modulus_switch_levels
    );
    println!(
        "plaintext leaves       = {}",
        cost.plaintext_leaves
    );
}

#[test]
fn compare_prf_circuit_costs() {
    println!();
    println!("==============================================");
    println!("        PRF / HE CIRCUIT COST COMPARISON");
    println!("==============================================");

    /*
     * Small concrete cases.
     */
    for bits in [1usize, 2, 4, 8] {
        println!();
        println!("==============================================");
        println!("INPUT SIZE = {} BITS", bits);
        println!("==============================================");

        let bpr12 = bpr12_cost(bits);
        let selector = selector_cost(bits);

        print_bpr12(&bpr12);
        print_selector(&selector);
    }

    /*
     * Important real case:
     *
     * 256-bit PRF input.
     */
    println!();
    println!("==============================================");
    println!("256-BIT CASE");
    println!("==============================================");

    let bpr12 = bpr12_cost(256);
    let selector = selector_cost(256);

    print_bpr12(&bpr12);
    print_selector(&selector);

    println!();
    println!("==============================================");
    println!("INTERPRETATION");
    println!("==============================================");

    println!(
        "BPR12 uses a balanced recursive tree over the 256 input positions."
    );

    println!(
        "Therefore BPR12 requires 255 ciphertext-ciphertext multiplications."
    );

    println!(
        "Its multiplicative depth is only 8."
    );

    println!();

    println!(
        "The generic selector has lower CC multiplication count only"
    );

    println!(
        "in relative terms, but requires 2^256 plaintext leaves and"
    );

    println!(
        "has multiplicative depth 255."
    );

    println!();

    println!(
        "Therefore the generic selector is NOT a practical replacement"
    );

    println!(
        "for BPR12 at 256-bit input size."
    );
}