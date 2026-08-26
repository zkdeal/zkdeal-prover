use super::DynResidue;
use crate::modular::pow::multi_exponentiate_montgomery_form_array;
#[cfg(feature = "alloc")]
use crate::modular::pow::multi_exponentiate_montgomery_form_slice;
use crate::{modular::pow::pow_montgomery_form, MultiExponentiateBoundedExp, PowBoundedExp, Uint};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

impl<const LIMBS: usize> DynResidue<LIMBS> {
    /// Raises to the `exponent` power.
    pub fn pow<const RHS_LIMBS: usize>(&self, exponent: &Uint<RHS_LIMBS>) -> DynResidue<LIMBS> {
        self.pow_bounded_exp(exponent, Uint::<RHS_LIMBS>::BITS)
    }

    /// Raises to the `exponent` power,
    /// with `exponent_bits` representing the number of (least significant) bits
    /// to take into account for the exponent.
    ///
    /// NOTE: `exponent_bits` may be leaked in the time pattern.
    pub fn pow_bounded_exp<const RHS_LIMBS: usize>(
        &self,
        exponent: &Uint<RHS_LIMBS>,
        exponent_bits: usize,
    ) -> Self {
        Self {
            montgomery_form: pow_montgomery_form(
                &self.montgomery_form,
                exponent,
                exponent_bits,
                &self.residue_params.modulus,
                &self.residue_params.r,
                self.residue_params.mod_neg_inv,
            ),
            residue_params: self.residue_params,
        }
    }
}

impl<const LIMBS: usize, const RHS_LIMBS: usize> PowBoundedExp<Uint<RHS_LIMBS>>
    for DynResidue<LIMBS>
{
    fn pow_bounded_exp(&self, exponent: &Uint<RHS_LIMBS>, exponent_bits: usize) -> Self {
        self.pow_bounded_exp(exponent, exponent_bits)
    }
}

impl<const N: usize, const LIMBS: usize, const RHS_LIMBS: usize>
    MultiExponentiateBoundedExp<Uint<RHS_LIMBS>, [(Self, Uint<RHS_LIMBS>); N]>
    for DynResidue<LIMBS>
{
    fn multi_exponentiate_bounded_exp(
        bases_and_exponents: &[(Self, Uint<RHS_LIMBS>); N],
        exponent_bits: usize,
    ) -> Self {
        const_assert_ne!(N, 0, "bases_and_exponents must not be empty");
        let residue_params = bases_and_exponents[0].0.residue_params;

        let mut bases_and_exponents_montgomery_form =
            [(Uint::<LIMBS>::ZERO, Uint::<RHS_LIMBS>::ZERO); N];

        let mut i = 0;
        while i < N {
            let (base, exponent) = bases_and_exponents[i];
            bases_and_exponents_montgomery_form[i] = (base.montgomery_form, exponent);
            i += 1;
        }

        Self {
            montgomery_form: multi_exponentiate_montgomery_form_array(
                &bases_and_exponents_montgomery_form,
                exponent_bits,
                &residue_params.modulus,
                &residue_params.r,
                residue_params.mod_neg_inv,
            ),
            residue_params,
        }
    }
}

#[cfg(feature = "alloc")]
impl<const LIMBS: usize, const RHS_LIMBS: usize>
    MultiExponentiateBoundedExp<Uint<RHS_LIMBS>, [(Self, Uint<RHS_LIMBS>)]> for DynResidue<LIMBS>
{
    fn multi_exponentiate_bounded_exp(
        bases_and_exponents: &[(Self, Uint<RHS_LIMBS>)],
        exponent_bits: usize,
    ) -> Self {
        assert!(
            !bases_and_exponents.is_empty(),
            "bases_and_exponents must not be empty"
        );
        let residue_params = bases_and_exponents[0].0.residue_params;

        let bases_and_exponents: Vec<(Uint<LIMBS>, Uint<RHS_LIMBS>)> = bases_and_exponents
            .iter()
            .map(|(base, exp)| (base.montgomery_form, *exp))
            .collect();
        Self {
            montgomery_form: multi_exponentiate_montgomery_form_slice(
                &bases_and_exponents,
                exponent_bits,
                &residue_params.modulus,
                &residue_params.r,
                residue_params.mod_neg_inv,
            ),
            residue_params,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        modular::runtime_mod::{DynResidue, DynResidueParams},
        U256,
    };

    #[test]
    fn test_powmod_small_base() {
        let params = DynResidueParams::new(&U256::from_be_hex(
            "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B",
        ));

        let base = U256::from(105u64);
        let base_mod = DynResidue::new(&base, params);

        let exponent =
            U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");

        let res = base_mod.pow(&exponent);

        let expected =
            U256::from_be_hex("7B2CD7BDDD96C271E6F232F2F415BB03FE2A90BD6CCCEA5E94F1BFD064993766");
        assert_eq!(res.retrieve(), expected);
    }

    #[test]
    fn test_powmod_small_exponent() {
        let params = DynResidueParams::new(&U256::from_be_hex(
            "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B",
        ));

        let base =
            U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
        let base_mod = DynResidue::new(&base, params);

        let exponent = U256::from(105u64);

        let res = base_mod.pow(&exponent);

        let expected =
            U256::from_be_hex("89E2A4E99F649A5AE2C18068148C355CA927B34A3245C938178ED00D6EF218AA");
        assert_eq!(res.retrieve(), expected);
    }

    #[test]
    fn test_powmod_zero_exponent() {
        let params = DynResidueParams::new(&U256::from_be_hex(
            "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B",
        ));

        let base =
            U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
        let base_mod = DynResidue::new(&base, params);

        let res = base_mod.pow(&U256::ZERO);

        assert_eq!(res.retrieve(), U256::ONE);
    }

    #[test]
    fn test_powmod() {
        let params = DynResidueParams::new(&U256::from_be_hex(
            "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B",
        ));

        let base =
            U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
        let base_mod = DynResidue::new(&base, params);

        let exponent =
            U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");

        let res = base_mod.pow(&exponent);

        let expected =
            U256::from_be_hex("3681BC0FEA2E5D394EB178155A127B0FD2EF405486D354251C385BDD51B9D421");
        assert_eq!(res.retrieve(), expected);
    }
}
