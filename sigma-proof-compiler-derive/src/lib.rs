use proc_macro::TokenStream;

mod sym_instance;
mod sym_witness;

#[proc_macro_derive(SymInstance)]
pub fn derive_sym_instance(input: TokenStream) -> TokenStream {
    sym_instance::derive_sym_instance_impl(input)
}

#[proc_macro_derive(SymWitness)]
pub fn derive_sym_witness(input: TokenStream) -> TokenStream {
    sym_witness::derive_sym_witness_impl(input)
}
