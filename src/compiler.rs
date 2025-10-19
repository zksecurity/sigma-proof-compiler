use crate::{
    absorb::{SymInstance, SymWitness},
    equations::{SymPoint, SymScalar},
    errors::{SigmaProofError, SigmaProofResult},
    transcript::ProofTranscript,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};

/// Escape a variable name for LaTeX and wrap in texttt
fn latex_var(name: &str) -> String {
    let escaped = name.replace('_', "\\_");
    format!("\\texttt{{{}}}", escaped)
}

/// Convert a SymPoint expression to LaTeX notation with context
fn sympoint_to_latex_with_context(
    point: &SymPoint,
    var_names: &[&str],
    is_instance: bool,
) -> String {
    match point {
        SymPoint::Const(p) => {
            if *p == RISTRETTO_BASEPOINT_POINT {
                // The base point G is always G unless we're in a specific context
                "G".to_string()
            } else {
                "P".to_string() // Some other point (could be a public key or other point)
            }
        }
        SymPoint::Var(Some(_)) => "P".to_string(), // Variable point
        SymPoint::Var(None) => "?".to_string(),    // Uninstantiated variable point
        SymPoint::Add(p1, p2) => {
            format!(
                "({} + {})",
                sympoint_to_latex_with_context(p1, var_names, is_instance),
                sympoint_to_latex_with_context(p2, var_names, is_instance)
            )
        }
        SymPoint::Sub(p1, p2) => {
            format!(
                "({} - {})",
                sympoint_to_latex_with_context(p1, var_names, is_instance),
                sympoint_to_latex_with_context(p2, var_names, is_instance)
            )
        }
        SymPoint::Neg(p) => {
            format!(
                "(-{})",
                sympoint_to_latex_with_context(p, var_names, is_instance)
            )
        }
        SymPoint::Scale(s, p) => {
            // Check if p is one of our dummy instance points
            let point_str = match p.as_ref() {
                SymPoint::Const(pt) if *pt == Scalar::from(2u64) * RISTRETTO_BASEPOINT_POINT => {
                    latex_var("pubkey")
                }
                SymPoint::Const(pt) if *pt == Scalar::from(3u64) * RISTRETTO_BASEPOINT_POINT => {
                    latex_var("commitment")
                }
                SymPoint::Const(pt) if *pt == Scalar::from(4u64) * RISTRETTO_BASEPOINT_POINT => {
                    latex_var("handle")
                }
                _ => sympoint_to_latex_with_context(p, var_names, is_instance),
            };
            format!("{} \\cdot {}", symscalar_to_latex(s, var_names), point_str)
        }
    }
}

/// Convert a SymPoint expression to LaTeX notation (wrapper for backwards compatibility)
fn sympoint_to_latex(point: &SymPoint, var_names: &[&str]) -> String {
    sympoint_to_latex_with_context(point, var_names, false)
}

/// Convert a SymScalar expression to LaTeX notation
fn symscalar_to_latex(scalar: &SymScalar, var_names: &[&str]) -> String {
    match scalar {
        SymScalar::Const(s) => {
            // Try to match against common small values
            if *s == Scalar::from(1u64) {
                "1".to_string()
            } else if *s == Scalar::from(2u64) {
                "2".to_string()
            } else if *s == Scalar::from(3u64) {
                "3".to_string()
            } else if *s == Scalar::from(4u64) {
                "4".to_string()
            } else if *s == Scalar::from(5u64) {
                "5".to_string()
            } else {
                "c".to_string() // Some constant
            }
        }
        SymScalar::Var(Some(s)) => {
            // Try to match against dummy values 1, 2, 3, etc.
            if *s == Scalar::from(1u64) && !var_names.is_empty() {
                latex_var(var_names[0])
            } else if *s == Scalar::from(2u64) && var_names.len() > 1 {
                latex_var(var_names[1])
            } else if *s == Scalar::from(3u64) && var_names.len() > 2 {
                latex_var(var_names[2])
            } else if *s == Scalar::from(4u64) && var_names.len() > 3 {
                latex_var(var_names[3])
            } else if *s == Scalar::from(5u64) && var_names.len() > 4 {
                latex_var(var_names[4])
            } else {
                "v".to_string() // Some variable
            }
        }
        SymScalar::Var(None) => "?".to_string(), // Uninstantiated
        SymScalar::Add(s1, s2) => {
            format!(
                "({} + {})",
                symscalar_to_latex(s1, var_names),
                symscalar_to_latex(s2, var_names)
            )
        }
        SymScalar::Sub(s1, s2) => {
            format!(
                "({} - {})",
                symscalar_to_latex(s1, var_names),
                symscalar_to_latex(s2, var_names)
            )
        }
        SymScalar::Neg(s) => {
            format!("(-{})", symscalar_to_latex(s, var_names))
        }
        SymScalar::Mul(s1, s2) => {
            format!(
                "({} \\cdot {})",
                symscalar_to_latex(s1, var_names),
                symscalar_to_latex(s2, var_names)
            )
        }
    }
}

pub trait SigmaProof {
    const LABEL: &'static [u8];

    type WITNESS: SymWitness;
    type INSTANCE: SymInstance;

    fn f(instance: &Self::INSTANCE) -> Vec<SymPoint>;

    fn psi(witness: &Self::WITNESS, instance: &Self::INSTANCE) -> Vec<SymPoint>;

    fn prove(witness: &Self::WITNESS, instance: &Self::INSTANCE) -> SigmaProofResult<Vec<u8>> {
        // init transcript
        let mut transcript = ProofTranscript::new_prover(Self::LABEL);

        // absorb instance, not f(instance)
        for point in instance.points() {
            transcript.common_absorb_point(b"", &point.evaluate()?);
        }
        for scalar in instance.scalars() {
            transcript.common_absorb_scalar(b"", &scalar.evaluate()?);
        }

        // round 1
        let rng = &mut rand::rngs::OsRng;
        let alphas = Self::WITNESS::rand(rng);
        let commited_alphas = Self::psi(&alphas, instance);
        for point in &commited_alphas {
            transcript.prover_absorb_point(b"r", &point.evaluate()?);
        }

        // round 2
        let e = transcript.challenge(b"e");

        // round 3
        for z_i in witness
            .values()?
            .into_iter()
            .zip(alphas.values()?)
            .map(|(s, a)| s * e + a)
        {
            transcript.prover_absorb_scalar(b"z", &z_i);
        }

        Ok(transcript.finalize())
    }

    fn verify(instance: &Self::INSTANCE, proof: &[u8]) -> Result<(), SigmaProofError> {
        // sanity check
        if proof.len() % 32 != 0 {
            return Err(SigmaProofError::TranscriptFinalizationFailed);
        }

        // init transcript
        let mut transcript = ProofTranscript::new_verifier(Self::LABEL, proof);

        // evaluate f(instance)
        let big_x_points: Vec<_> = Self::f(instance)
            .into_iter()
            .map(|p| p.evaluate())
            .collect::<Result<Vec<_>, _>>()?;

        // absorb instance, not f(instance)
        for point in instance.points() {
            transcript.common_absorb_point(b"", &point.evaluate()?);
        }
        for scalar in instance.scalars() {
            transcript.common_absorb_scalar(b"", &scalar.evaluate()?);
        }

        // -> A
        let big_a = transcript
            .verifier_receive_points(b"r", big_x_points.len())
            .ok_or(SigmaProofError::TranscriptError)?;

        // <- challenge
        let e = transcript.challenge(b"e");

        // -> sigma
        let sigmas = transcript
            .verifier_receives_all_scalars(b"z")
            .ok_or(SigmaProofError::TranscriptError)?;
        println!("sigmas received: {}", sigmas.len());
        let sigmas_as_input = Self::WITNESS::from_values(&sigmas)?;

        let psi_output = Self::psi(&sigmas_as_input, instance);

        // checks
        if big_x_points.len() != psi_output.len() {
            return Err(SigmaProofError::PsiOutputLengthMismatch);
        }

        for ((big_x_i, big_a_i), psi_i) in big_x_points.iter().zip(&big_a).zip(&psi_output) {
            let rhs = big_a_i + e * big_x_i;
            if psi_i.evaluate()? != rhs {
                return Err(SigmaProofError::EquationCheckFailed);
            }
        }

        Ok(())
    }

    /// Generate a specification document in Markdown+LaTeX format
    fn spec() -> String {
        let psi_in_len = Self::WITNESS::num_scalars();
        let f_scalars_in = Self::INSTANCE::num_scalars();
        let f_points_in = Self::INSTANCE::num_points();

        let protocol_name = String::from_utf8_lossy(Self::LABEL);

        // Generate dummy witness with sequential scalars 1, 2, 3, etc.
        let dummy_scalars: Vec<Scalar> = (1..=psi_in_len).map(|i| Scalar::from(i as u64)).collect();
        let dummy_witness = match Self::WITNESS::from_values(&dummy_scalars) {
            Ok(w) => w,
            Err(_) => {
                // Fallback if we can't create dummy witness
                return format!(
                    r#"#### {}
Error: Could not generate symbolic analysis for this protocol."#,
                    protocol_name
                );
            }
        };

        // Generate dummy instance with sequential scalars and distinct points
        let dummy_f_scalars_in: Vec<Scalar> =
            (1..=f_scalars_in).map(|i| Scalar::from(i as u64)).collect();
        // Use different multiples of G for different instance points to distinguish them
        let dummy_instance_points: Vec<RistrettoPoint> = (0..f_points_in)
            .map(|i| Scalar::from((i + 2) as u64) * RISTRETTO_BASEPOINT_POINT)
            .collect();
        let dummy_instance =
            match Self::INSTANCE::from_values(&dummy_f_scalars_in, &dummy_instance_points) {
                Ok(i) => i,
                Err(_) => {
                    // Fallback if we can't create dummy instance
                    return format!(
                        r#"#### {}
Error: Could not generate symbolic analysis for this protocol."#,
                        protocol_name
                    );
                }
            };

        // Get variable names for the witness
        let var_names: Vec<&str> = (0..psi_in_len)
            .map(|i| Self::WITNESS::get_var_name(i))
            .collect();

        // Get instance field names for better output
        let instance_field_names = Self::INSTANCE::get_field_names();

        // Symbolically evaluate f function (instance function)
        let f_result = Self::f(&dummy_instance);

        // Convert f result to LaTeX with field name tracking
        let f_equations: Vec<String> = f_result
            .iter()
            .map(|point| {
                // For each output, try to match it to an instance field
                match point {
                    SymPoint::Const(p) if *p == Scalar::from(2u64) * RISTRETTO_BASEPOINT_POINT => {
                        // First instance point field
                        if instance_field_names.len() > f_scalars_in {
                            latex_var(&instance_field_names[f_scalars_in])
                        } else {
                            "P_1".to_string()
                        }
                    }
                    SymPoint::Const(p) if *p == Scalar::from(3u64) * RISTRETTO_BASEPOINT_POINT => {
                        // Second instance point field
                        if instance_field_names.len() > f_scalars_in + 1 {
                            latex_var(&instance_field_names[f_scalars_in + 1])
                        } else {
                            "P_2".to_string()
                        }
                    }
                    SymPoint::Const(p) if *p == Scalar::from(4u64) * RISTRETTO_BASEPOINT_POINT => {
                        // Third instance point field
                        if instance_field_names.len() > f_scalars_in + 2 {
                            latex_var(&instance_field_names[f_scalars_in + 2])
                        } else {
                            "P_3".to_string()
                        }
                    }
                    _ => sympoint_to_latex_with_context(point, &var_names, true),
                }
            })
            .collect();

        // Symbolically evaluate psi function
        let psi_result = Self::psi(&dummy_witness, &dummy_instance);

        // Convert psi result to LaTeX
        let psi_equations: Vec<String> = psi_result
            .iter()
            .map(|point| sympoint_to_latex(point, &var_names))
            .collect();

        let checks = psi_equations
            .iter()
            .zip(f_equations.iter())
            .map(|(psi, f)| format!("* ${} = {}$", psi, f))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"The Sigma protocol is labeled as `{protocol_name}`.

The **witness** is defined as $\mathbf \omega = \{{ {witness_field_names} \}}$.

The **instance** is defined as $\mathbf X = \{{ {instance_field_names} \}}$.

The sigma protocol allows us to prove knowledge of $\mathbf \omega$ such that  $\psi(\mathbf \omega) = f(\mathbf X)$.

The homomorphism $\psi$ is defined as:

$$
\begin{{aligned}}
\psi : \mathbb{{F}}^{{{psi_in_len}}} &\to \mathbb{{G}}^{{{psi_out_len}}} \\
\mathbf \omega &\mapsto ({psi_latex})
\end{{aligned}}
$$

The transformation $f$ is defined as:

$$
\begin{{aligned}}
f : \mathbb{{F}}^{{{f_scalars_in}}} \times \mathbb{{G}}^{{{f_points_in}}} &\to \mathbb{{G}}^{{{psi_out_len}}} \\
\mathbf X &\mapsto ({f_latex})
\end{{aligned}}
$$

In other words, the following is being proven:

{checks}
"#,
            psi_out_len = f_result.len(),
            psi_latex = psi_equations.join(", "),
            f_latex = f_equations.join(", "),
            witness_field_names = var_names
                .iter()
                .map(|name| latex_var(name))
                .collect::<Vec<_>>()
                .join(", "),
            instance_field_names = Self::INSTANCE::get_field_names()
                .iter()
                .map(|name| latex_var(name))
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}
