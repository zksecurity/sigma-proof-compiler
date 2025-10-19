use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

fn is_sym_instance_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let ident = &segment.ident;
            return ident == "SymScalar" || ident == "SymPoint" || ident == "SymInstance";
        }
    }
    false
}

fn is_sym_type(ty: &Type) -> Option<&str> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            let ident = &segment.ident;
            if ident == "SymScalar" {
                return Some("scalar");
            } else if ident == "SymPoint" {
                return Some("point");
            }
        }
    }
    None
}

pub fn derive_sym_instance_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    match &input.data {
        Data::Struct(data) => {
            match &data.fields {
                Fields::Named(fields) => {
                    for field in &fields.named {
                        if !is_sym_instance_type(&field.ty) {
                            let field_name = field.ident.as_ref().unwrap();
                            let ty = &field.ty;
                            panic!(
                                "Field '{}' has type '{}' which is not SymScalar, SymPoint, or SymInstance",
                                field_name,
                                quote!(#ty)
                            );
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    for (i, field) in fields.unnamed.iter().enumerate() {
                        if !is_sym_instance_type(&field.ty) {
                            let ty = &field.ty;
                            panic!(
                                "Field {} has type '{}' which is not SymScalar, SymPoint, or SymInstance",
                                i,
                                quote!(#ty)
                            );
                        }
                    }
                }
                Fields::Unit => {}
            }

            // Generate num_scalars() method body
            let num_scalars_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_counts = fields.named.iter().map(|field| {
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! { 1 },
                            Some("point") => quote! { 0 },
                            _ => quote! { #field_type::num_scalars() },
                        }
                    });

                    quote! {
                        0 #(+ #field_counts)*
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_counts = fields.unnamed.iter().map(|field| {
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! { 1 },
                            Some("point") => quote! { 0 },
                            _ => quote! { #field_type::num_scalars() },
                        }
                    });

                    quote! {
                        0 #(+ #field_counts)*
                    }
                }
                Fields::Unit => {
                    quote! { 0 }
                }
            };

            // Generate num_points() method body
            let num_points_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_counts = fields.named.iter().map(|field| {
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! { 0 },
                            Some("point") => quote! { 1 },
                            _ => quote! { #field_type::num_points() },
                        }
                    });

                    quote! {
                        0 #(+ #field_counts)*
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_counts = fields.unnamed.iter().map(|field| {
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! { 0 },
                            Some("point") => quote! { 1 },
                            _ => quote! { #field_type::num_points() },
                        }
                    });

                    quote! {
                        0 #(+ #field_counts)*
                    }
                }
                Fields::Unit => {
                    quote! { 0 }
                }
            };

            // Generate get_field_names() method body
            let get_field_names_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_names: Vec<String> = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        field_name.to_string()
                    }).collect();

                    let name_literals = field_names.iter().map(|n| quote! { #n });
                    quote! {
                        vec![#(#name_literals),*]
                    }
                }
                Fields::Unnamed(fields) => {
                    // For unnamed fields, generate generic names
                    let field_names: Vec<String> = (0..fields.unnamed.len())
                        .map(|i| format!("field_{}", i))
                        .collect();
                    let name_literals = field_names.iter().map(|n| quote! { #n });
                    quote! {
                        vec![#(#name_literals),*]
                    }
                }
                Fields::Unit => {
                    quote! {
                        vec![]
                    }
                }
            };

            // Generate from_values() method body
            let from_values_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_assignments = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! {
                                #field_name: {
                                    if scalar_cursor >= scalars.len() {
                                        return Err(crate::errors::SigmaProofError::InsufficientScalars);
                                    }
                                    let val = SymInstance::from_values(&scalars[scalar_cursor..scalar_cursor+1], &[])?;
                                    scalar_cursor += 1;
                                    val
                                }
                            },
                            Some("point") => quote! {
                                #field_name: {
                                    if point_cursor >= points.len() {
                                        return Err(crate::errors::SigmaProofError::InsufficientPoints);
                                    }
                                    let val = SymInstance::from_values(&[], &points[point_cursor..point_cursor+1])?;
                                    point_cursor += 1;
                                    val
                                }
                            },
                            _ => quote! {
                                #field_name: {
                                    let field_scalars = #field_type::num_scalars();
                                    let field_points = #field_type::num_points();
                                    let val = #field_type::from_values(
                                        &scalars[scalar_cursor..scalar_cursor+field_scalars],
                                        &points[point_cursor..point_cursor+field_points]
                                    )?;
                                    scalar_cursor += field_scalars;
                                    point_cursor += field_points;
                                    val
                                }
                            },
                        }
                    });

                    quote! {
                        let mut scalar_cursor = 0;
                        let mut point_cursor = 0;
                        let result = Self {
                            #(#field_assignments),*
                        };

                        if scalar_cursor == scalars.len() && point_cursor == points.len() {
                            Ok(result)
                        } else {
                            Err(crate::errors::SigmaProofError::TooManyScalars {
                                expected: scalar_cursor,
                                actual: scalars.len(),
                            })
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_assignments = fields.unnamed.iter().map(|field| {
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! {
                                {
                                    if scalar_cursor >= scalars.len() {
                                        return Err(crate::errors::SigmaProofError::InsufficientScalars);
                                    }
                                    let val = SymInstance::from_values(&scalars[scalar_cursor..scalar_cursor+1], &[])?;
                                    scalar_cursor += 1;
                                    val
                                }
                            },
                            Some("point") => quote! {
                                {
                                    if point_cursor >= points.len() {
                                        return Err(crate::errors::SigmaProofError::InsufficientPoints);
                                    }
                                    let val = SymInstance::from_values(&[], &points[point_cursor..point_cursor+1])?;
                                    point_cursor += 1;
                                    val
                                }
                            },
                            _ => quote! {
                                {
                                    let field_scalars = #field_type::num_scalars();
                                    let field_points = #field_type::num_points();
                                    let val = #field_type::from_values(
                                        &scalars[scalar_cursor..scalar_cursor+field_scalars],
                                        &points[point_cursor..point_cursor+field_points]
                                    )?;
                                    scalar_cursor += field_scalars;
                                    point_cursor += field_points;
                                    val
                                }
                            },
                        }
                    });

                    quote! {
                        let mut scalar_cursor = 0;
                        let mut point_cursor = 0;
                        let result = Self(#(#field_assignments),*);

                        if scalar_cursor == scalars.len() && point_cursor == points.len() {
                            Ok(result)
                        } else {
                            Err(crate::errors::SigmaProofError::TooManyScalars {
                                expected: scalar_cursor,
                                actual: scalars.len(),
                            })
                        }
                    }
                }
                Fields::Unit => {
                    quote! {
                        if scalars.is_empty() && points.is_empty() {
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

            // Generate scalars() method body
            let scalars_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_extractions = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! {
                                result.push(self.#field_name.clone());
                            },
                            Some("point") => quote! {},
                            _ => quote! {
                                result.extend(self.#field_name.scalars());
                            },
                        }
                    });

                    quote! {
                        let mut result = Vec::new();
                        #(#field_extractions)*
                        result
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_extractions = fields.unnamed.iter().enumerate().map(|(i, field)| {
                        let index = syn::Index::from(i);
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! {
                                result.push(self.#index.clone());
                            },
                            Some("point") => quote! {},
                            _ => quote! {
                                result.extend(self.#index.scalars());
                            },
                        }
                    });

                    quote! {
                        let mut result = Vec::new();
                        #(#field_extractions)*
                        result
                    }
                }
                Fields::Unit => {
                    quote! { Vec::new() }
                }
            };

            // Generate points() method body
            let points_body = match &data.fields {
                Fields::Named(fields) => {
                    let field_extractions = fields.named.iter().map(|field| {
                        let field_name = field.ident.as_ref().unwrap();
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! {},
                            Some("point") => quote! {
                                result.push(self.#field_name.clone());
                            },
                            _ => quote! {
                                result.extend(self.#field_name.points());
                            },
                        }
                    });

                    quote! {
                        let mut result = Vec::new();
                        #(#field_extractions)*
                        result
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_extractions = fields.unnamed.iter().enumerate().map(|(i, field)| {
                        let index = syn::Index::from(i);
                        let field_type = &field.ty;
                        match is_sym_type(field_type) {
                            Some("scalar") => quote! {},
                            Some("point") => quote! {
                                result.push(self.#index.clone());
                            },
                            _ => quote! {
                                result.extend(self.#index.points());
                            },
                        }
                    });

                    quote! {
                        let mut result = Vec::new();
                        #(#field_extractions)*
                        result
                    }
                }
                Fields::Unit => {
                    quote! { Vec::new() }
                }
            };

            let expanded = quote! {
                impl #impl_generics crate::absorb::sealed_instance::Sealed for #name #ty_generics #where_clause {}

                impl #impl_generics SymInstance for #name #ty_generics #where_clause {
                    fn num_scalars() -> usize {
                        #num_scalars_body
                    }

                    fn num_points() -> usize {
                        #num_points_body
                    }

                    fn from_values(scalars: &[curve25519_dalek::Scalar], points: &[curve25519_dalek::RistrettoPoint]) -> crate::errors::SigmaProofResult<Self> {
                        #from_values_body
                    }

                    fn get_field_names() -> Vec<&'static str> {
                        #get_field_names_body
                    }

                    fn scalars(&self) -> Vec<crate::equations::SymScalar> {
                        #scalars_body
                    }

                    fn points(&self) -> Vec<crate::equations::SymPoint> {
                        #points_body
                    }
                }
            };

            TokenStream::from(expanded)
        }
        Data::Enum(_) => {
            panic!("SymInstance derive macro does not support enums");
        }
        Data::Union(_) => {
            panic!("SymInstance derive macro does not support unions");
        }
    }
}