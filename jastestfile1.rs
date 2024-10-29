use std::env;

// ruleid: args-os
//let args = env::args_os();
let args: Vec<String> = env::args().map(|arg| arg.into_string().unwrap()).collect();
