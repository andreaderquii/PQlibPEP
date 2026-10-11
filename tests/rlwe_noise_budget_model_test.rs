fn bits_of_headroom(noise_ratio: f64) -> f64 {
    assert!(
        noise_ratio > 0.0,
        "noise ratio must be positive"
    );

    -noise_ratio.log2()
}

fn consumed_bits(previous_ratio: f64, next_ratio: f64) -> f64 {
    bits_of_headroom(previous_ratio)
        - bits_of_headroom(next_ratio)
}

#[test]
fn estimate_required_modulus_for_bpr12_depth_8() {
    println!();
    println!("==============================================");
    println!("      EMPIRICAL BGV NOISE-BUDGET MODEL");
    println!("==============================================");

    /*
     * Measurements obtained from the current
     * rlwe_bgv_noise_diagnostic_test.
     *
     * These are normalized:
     *
     *     noise_ratio = noise / (q/2)
     */

    let x_ratio = 1.3271342266417467e-16;
    let x2_ratio = 1.1834343987138994e-12;
    let x4_ratio = 7.106352730795611e-7;
    let x8_ratio = 0.9954731597801565;

    let headroom_x = bits_of_headroom(x_ratio);
    let headroom_x2 = bits_of_headroom(x2_ratio);
    let headroom_x4 = bits_of_headroom(x4_ratio);
    let headroom_x8 = bits_of_headroom(x8_ratio);

    println!("Measured noise headroom:");
    println!(
        "  x      = {:.3} bits",
        headroom_x
    );
    println!(
        "  x^2    = {:.3} bits",
        headroom_x2
    );
    println!(
        "  x^4    = {:.3} bits",
        headroom_x4
    );
    println!(
        "  x^8    = {:.3} bits",
        headroom_x8
    );

    let cost_x_to_x2 =
        consumed_bits(x_ratio, x2_ratio);

    let cost_x2_to_x4 =
        consumed_bits(x2_ratio, x4_ratio);

    let cost_x4_to_x8 =
        consumed_bits(x4_ratio, x8_ratio);

    println!();
    println!("Observed budget consumption:");
    println!(
        "  x   -> x^2 = {:.3} bits",
        cost_x_to_x2
    );
    println!(
        "  x^2 -> x^4 = {:.3} bits",
        cost_x2_to_x4
    );
    println!(
        "  x^4 -> x^8 = {:.3} bits",
        cost_x4_to_x8
    );

    /*
     * Use the last two levels as the conservative
     * empirical estimate for later levels.
     *
     * The reason:
     *
     *     x^2 -> x^4  ~19.2 bits
     *     x^4 -> x^8  ~20.4 bits
     *
     * which suggests that later levels are costing
     * roughly 20 bits of normalized budget.
     */
    let later_level_cost =
        (cost_x2_to_x4 + cost_x4_to_x8) / 2.0;

    println!();
    println!(
        "Estimated later-level cost = {:.3} bits",
        later_level_cost
    );

    /*
     * BPR12 for 256 input bits has:
     *
     *     depth = log2(256) = 8
     *
     * We already measured x -> x^8, which is
     * three ciphertext-ciphertext multiplications.
     *
     * Therefore five more multiplicative levels
     * are required to reach depth 8.
     */
    const CURRENT_DEPTH: usize = 3;
    const TARGET_DEPTH: usize = 8;

    let remaining_depth =
        TARGET_DEPTH - CURRENT_DEPTH;

    let estimated_extra_budget =
        later_level_cost
            * remaining_depth as f64;

    let current_headroom =
        headroom_x;

    let estimated_total_budget =
        current_headroom
            + estimated_extra_budget;

    println!();
    println!("Depth model:");
    println!(
        "  current tested depth       = {}",
        CURRENT_DEPTH
    );
    println!(
        "  target BPR12 depth         = {}",
        TARGET_DEPTH
    );
    println!(
        "  remaining levels           = {}",
        remaining_depth
    );

    println!();
    println!("Estimated modulus budget:");
    println!(
        "  current usable headroom    = {:.3} bits",
        current_headroom
    );
    println!(
        "  additional budget required = {:.3} bits",
        estimated_extra_budget
    );
    println!(
        "  estimated total            = {:.3} bits",
        estimated_total_budget
    );

    /*
     * Add an engineering margin.
     *
     * This is NOT a cryptographic security parameter.
     * It is only a prototype noise margin.
     */
    let safety_margin_20 =
        estimated_total_budget + 20.0;

    let safety_margin_40 =
        estimated_total_budget + 40.0;

    println!();
    println!("Prototype engineering estimates:");
    println!(
        "  +20-bit margin = {:.1} bits",
        safety_margin_20
    );
    println!(
        "  +40-bit margin = {:.1} bits",
        safety_margin_40
    );

    println!();
    println!("Approximate target:");
    println!(
        "  total modulus size ≈ 170-200 bits"
    );

    println!();
    println!("IMPORTANT:");
    println!(
        "This is an empirical estimate from the current prototype."
    );
    println!(
        "It is NOT a secure BGV parameter set."
    );
    println!(
        "The purpose is to decide whether RNS/multi-modulus"
    );
    println!(
        "is technically justified."
    );
}