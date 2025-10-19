use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

fn is_sym_witness_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let ident = &segment.ident;
            return ident == "SymScalar" || ident == "SymWitness";
        }
    }
    false
}

pub fn derive_sym_witness_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    match &input.data {
        Data::Struct(data) => {
            // Validate fields and generate rand() body
            let rand_body = match &data.fields {
                Fields::Named(fields) => {
                    // Validate all fields are SymScalar or SymWitness
                    for field in &fields.named {
                        if !is_sym_witness_type(&field.ty) {
                            let field_name = field.ident.as_ref().unwrap();
                            let ty = &field.ty;
                            panic!(
                                "Field '{}' has type '{}' which is not SymScalar or SymWitness",
                                field_name,
                                quote!(#ty)
                            );
                        }
                    }

                    // Generate field initializers for rand()
                    let field_inits = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        quote! {
                            #field_name: SymWitness::rand(rng)
                        }
                    });

                    quote! {
                        Self {
                            #(#field_inits),*
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    // Validate all fields are SymScalar or SymWitness
                    for (i, field) in fields.unnamed.iter().enumerate() {
                        if !is_sym_witness_type(&field.ty) {
                            let ty = &field.ty;
                            panic!(
                                "Field {} has type '{}' which is not SymScalar or SymWitness",
                                i,
                                quote!(#ty)
                            );
                        }
                    }

                    // Generate tuple struct initialization for rand()
                    let field_inits = (0..fields.unnamed.len()).map(|_| {
                        quote! { SymWitness::rand(rng) }
                    });

                    quote! {
                        Self(#(#field_inits),*)
                    }
                }
                Fields::Unit => {
                    quote! { Self }
                }
            };

            // Generate values() method body
            let values_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_values = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_type = &field.ty;

                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    // For SymScalar, check if it's instantiated and use evaluate()
                                    return quote! {
                                        match &self.#field_name {
                                            crate::equations::SymScalar::Var(None) => return Err(crate::errors::SigmaProofError::UninstantiatedScalar),
                                            _ => values.push(self.#field_name.evaluate()?),
                                        }
                                    };
                                }
                            }
                        }

                        // For SymWitness types, call values() recursively
                        quote! {
                            values.extend(self.#field_name.values()?);
                        }
                    });

                    quote! {
                        let mut values = Vec::new();
                        #(#field_values)*
                        Ok(values)
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_values = fields.unnamed.iter().enumerate().map(|(i, field)| {
                        let index = syn::Index::from(i);
                        let field_type = &field.ty;

                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    // For SymScalar, check if it's instantiated and use evaluate()
                                    return quote! {
                                        match &self.#index {
                                            crate::equations::SymScalar::Var(None) => return Err(crate::errors::SigmaProofError::UninstantiatedScalar),
                                            _ => values.push(self.#index.evaluate()?),
                                        }
                                    };
                                }
                            }
                        }

                        // For SymWitness types, call values() recursively
                        quote! {
                            values.extend(self.#index.values()?);
                        }
                    });

                    quote! {
                        let mut values = Vec::new();
                        #(#field_values)*
                        Ok(values)
                    }
                }
                Fields::Unit => {
                    quote! { Ok(Vec::new()) }
                }
            };

            // Generate from_values() method body
            let from_values_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_assignments = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_type = &field.ty;

                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    return quote! {
                                        #field_name: {
                                            if cursor.position() >= scalars.len() as u64 {
                                                return Err(crate::errors::SigmaProofError::InsufficientScalars);
                                            }
                                            let field_values = SymWitness::from_values(&scalars[cursor.position() as usize..cursor.position() as usize + 1])?;
                                            cursor.set_position(cursor.position() + 1);
                                            field_values
                                        }
                                    };
                                }
                            }
                        }

                        // For SymWitness types, try to consume from remaining buffer
                        quote! {
                            #field_name: {
                                let remaining = &scalars[cursor.position() as usize..];
                                let field_values = SymWitness::from_values(remaining)?;
                                let field_scalar_count = field_values.values()?.len();
                                cursor.set_position(cursor.position() + field_scalar_count as u64);
                                field_values
                            }
                        }
                    });

                    quote! {
                        let mut cursor = std::io::Cursor::new(());
                        cursor.set_position(0);
                        let result = Self {
                            #(#field_assignments),*
                        };
                        if cursor.position() == scalars.len() as u64 {
                            Ok(result)
                        } else {
                            Err(crate::errors::SigmaProofError::TooManyScalars {
                                expected: cursor.position() as usize,
                                actual: scalars.len(),
                            })
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_assignments = fields.unnamed.iter().enumerate().map(|(_i, field)| {
                        let field_type = &field.ty;

                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    return quote! {
                                        {
                                            if cursor.position() >= scalars.len() as u64 {
                                                return Err(crate::errors::SigmaProofError::InsufficientScalars);
                                            }
                                            let field_values = SymWitness::from_values(&scalars[cursor.position() as usize..cursor.position() as usize + 1])?;
                                            cursor.set_position(cursor.position() + 1);
                                            field_values
                                        }
                                    };
                                }
                            }
                        }

                        // For SymWitness types, try to consume from remaining buffer
                        quote! {
                            {
                                let remaining = &scalars[cursor.position() as usize..];
                                let field_values = SymWitness::from_values(remaining)?;
                                let field_scalar_count = field_values.values()?.len();
                                cursor.set_position(cursor.position() + field_scalar_count as u64);
                                field_values
                            }
                        }
                    });

                    quote! {
                        let mut cursor = std::io::Cursor::new(());
                        cursor.set_position(0);
                        let result = Self(#(#field_assignments),*);
                        if cursor.position() == scalars.len() as u64 {
                            Ok(result)
                        } else {
                            Err(crate::errors::SigmaProofError::TooManyScalars {
                                expected: cursor.position() as usize,
                                actual: scalars.len(),
                            })
                        }
                    }
                }
                Fields::Unit => {
                    quote! {
                        if scalars.is_empty() {
                            Ok(Self)
                        } else {
                            Err(crate::errors::SigmaProofError::TooManyScalars {
                                expected: 0,
                                actual: scalars.len(),
                            })
                        }
                    }
                }
            };

            // Generate get_var_name() method body
            let get_var_name_body = match &data.fields {
                Fields::Named(fields) => {
                    let match_arms = fields.named.iter().enumerate().map(|(i, field)| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_name_str = field_name.to_string();
                        let field_type = &field.ty;

                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    return quote! {
                                        #i => #field_name_str,
                                    };
                                }
                            }
                        }

                        // For SymWitness types, we need to handle recursively
                        // This is complex, so for now we'll generate a placeholder
                        quote! {
                            #i => "nested_field",
                        }
                    });

                    quote! {
                        match index {
                            #(#match_arms)*
                            _ => "unknown",
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let match_arms = fields.unnamed.iter().enumerate().map(|(i, field)| {
                        let field_type = &field.ty;

                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    let field_name = format!("field_{}", i);
                                    return quote! {
                                        #i => #field_name,
                                    };
                                }
                            }
                        }

                        // For SymWitness types
                        quote! {
                            #i => "nested_field",
                        }
                    });

                    quote! {
                        match index {
                            #(#match_arms)*
                            _ => "unknown",
                        }
                    }
                }
                Fields::Unit => {
                    quote! {
                        "unit"
                    }
                }
            };

            // Generate num_scalars() method body
            let num_scalars_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_counts = fields.named.iter().map(|field| {
                        let field_type = &field.ty;
                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    return quote! { 1 };
                                }
                            }
                        }
                        // For SymWitness types
                        quote! { #field_type::num_scalars() }
                    });

                    quote! {
                        0 #(+ #field_counts)*
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_counts = fields.unnamed.iter().map(|field| {
                        let field_type = &field.ty;
                        if let syn::Type::Path(type_path) = field_type {
                            if let Some(segment) = type_path.path.segments.last() {
                                if segment.ident == "SymScalar" {
                                    return quote! { 1 };
                                }
                            }
                        }
                        // For SymWitness types
                        quote! { #field_type::num_scalars() }
                    });

                    quote! {
                        0 #(+ #field_counts)*
                    }
                }
                Fields::Unit => {
                    quote! { 0 }
                }
            };

            let expanded = quote! {
                impl #impl_generics crate::absorb::sealed_witness::Sealed for #name #ty_generics #where_clause {}

                impl #impl_generics SymWitness for #name #ty_generics #where_clause {
                    fn rand<R: rand_core::CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
                        #rand_body
                    }

                    fn values(&self) -> crate::errors::SigmaProofResult<Vec<curve25519_dalek::Scalar>> {
                        #values_body
                    }

                    fn from_values(scalars: &[curve25519_dalek::Scalar]) -> crate::errors::SigmaProofResult<Self> {
                        #from_values_body
                    }

                    fn num_scalars() -> usize {
                        #num_scalars_body
                    }

                    fn get_var_name(index: usize) -> &'static str {
                        #get_var_name_body
                    }
                }
            };

            TokenStream::from(expanded)
        }
        Data::Enum(_) => {
            panic!("SymWitness derive macro does not support enums");
        }
        Data::Union(_) => {
            panic!("SymWitness derive macro does not support unions");
        }
    }
}
