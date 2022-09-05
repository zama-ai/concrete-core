use quote::__private::{Ident, TokenStream};
use quote::{format_ident, quote};

const BEGIN_TAG: &str = "//@begin_gen:";
const END_TAG: &str = "//@end_gen";

pub struct GeneratedFileContent<'a, 'b> {
    pub above: &'a str,
    pub begin_tag: &'a str,
    pub content: &'b str,
    pub end_tag: &'a str,
    pub below: &'a str,
}

pub fn do_generate() -> bool {
    option_env!("CONCRETE_CORE_GENERATE").is_some()
}

pub fn get_tags(scope: &str) -> (String, String) {
    (format!("{BEGIN_TAG} {scope}"), format!("{END_TAG}"))
}

pub fn read_this_file(file_macro_call: &str) -> String {
    let path = std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .join(file_macro_call);
    std::fs::read_to_string(path).unwrap()
}

pub fn write_this_file<'a, 'b>(file_macro_call: &str, content: GeneratedFileContent<'a, 'b>) {
    let path = std::env::current_dir()
        .unwrap()
        .parent()
        .unwrap()
        .join(file_macro_call);
    let GeneratedFileContent {
        above,
        begin_tag,
        content,
        end_tag,
        below,
    } = content;
    std::fs::write(
        path,
        format!("{above}\n{begin_tag}\n{content}\n{end_tag}\n{below}"),
    )
    .unwrap();
}

pub fn split_on_gen_tag<'a>(scope: &str, file_content: &'a str) -> GeneratedFileContent<'a, 'a> {
    let (begin_tag, end_tag) = get_tags(scope);
    let begin_tag = file_content.matches(&begin_tag).next().unwrap();
    let end_tag = file_content.matches(&end_tag).next().unwrap();
    let (above, remainder) = file_content.split_once(&begin_tag).unwrap();
    let (content, below) = remainder.split_once(&end_tag).unwrap();
    GeneratedFileContent {
        above,
        begin_tag,
        content,
        end_tag,
        below,
    }
}

pub fn generate_priv_api(owned_name: Ident) -> TokenStream {
    let view_name = format_ident!("{}View", owned_name);
    let mut_view_name = format_ident!("{}MutView", owned_name);
    quote! {
        #[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct #owned_name<Scalar: UnsignedInteger>{
            pub(crate) tensor: Tensor<Vec<Scalar>>
        }

        impl<Scalar: UnsignedInteger> #owned_name<Scalar> {
            pub fn from_vec(c: Vec<Scalar>) -> #owned_name<Scalar> {
                Self {
                    tensor: Tensor::from_container(c)
                }
            }

            pub fn into_vec(self) -> Vec<Scalar> {
                self.tensor.into_container()
            }

            pub fn as_view(&self) -> #view_name<Scalar> {
                #view_name{
                    tensor: Tensor::from_container(self.tensor.as_container().as_slice())
                }
            }

            pub fn as_mut_view(&mut self) -> #mut_view_name<Scalar> {
                #mut_view_name{
                    tensor: Tensor::from_container(self.tensor.as_mut_container().as_mut_slice())
                }
            }
        }

        #[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
        #[derive(Debug, PartialEq, Eq)]
        pub struct #mut_view_name<'a, Scalar: UnsignedInteger>{
            pub(crate) tensor: Tensor<&'a mut [Scalar]>
        }

        impl<'a, Scalar: UnsignedInteger> #mut_view_name<'a, Scalar> {
            pub fn from_mut_slice(c: &'a mut [Scalar]) -> #mut_view_name<'a, Scalar> {
                Self {
                    tensor: Tensor::from_container(c)
                }
            }

            pub fn into_mut_slice(self) -> &'a mut [Scalar] {
                self.tensor.into_container()
            }

            pub fn as_view(&'a self) -> #view_name<'a, Scalar> {
                #view_name{
                    tensor: Tensor::from_container(self.tensor.as_container().as_slice())
                }
            }
        }


        #[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct #view_name<'a, Scalar: UnsignedInteger>{
            pub(crate) tensor: Tensor<&'a [Scalar]>
        }


        impl<'a, Scalar: UnsignedInteger> #view_name<'a, Scalar> {
            pub fn from_slice(c: &'a[Scalar]) -> #view_name<'a, Scalar> {
                Self {
                    tensor: Tensor::from_container(c)
                }
            }

            pub fn into_slice(self) -> &'a[Scalar] {
                self.tensor.into_container()
            }

        }
    }
}
