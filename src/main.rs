#![allow(warnings)]

use anyhow::{anyhow, Result};
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use keepass::{
    Database,
    Entry, // Result
    // Error,
    NodeRef,
};
use libreauth::oath::TOTPBuilder;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::io::{self, Write};
use std::path::Path;
use std::time::SystemTime;
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use url::Url;

shadow_rs::shadow!(build);

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
    /// emacs-friendly output
    #[clap(long = "emacs", short = 'e', default_value = "false", global = true)]
    emacs: bool,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Field {
    Username,
    Password,
    Title,
    Description,
    URL,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
    /// List All
    #[clap(alias = "ls")]
    List {
        /// enable when creation
        #[clap(long = "password", short = 'p', default_value = "false")]
        show_password: bool,
        /// show fields in order
        #[clap(long = "field", short = 'f', num_args = 0..)]
        // fields: Option<Vec<Field>>,
        fields: Option<Vec<String>>,
    },
    /// Get one by id which is printed by list command
    #[clap(alias = "g")]
    Get {
        id: u64,
        /// show fields in order
        #[clap(long = "field", short = 'f', num_args = 0..)]
        // fields: Option<Vec<Field>>,
        fields: Option<Vec<String>>,
    },
    /// server mode
    #[clap(alias = "s")]
    Server,
}

#[derive(Debug)]
pub struct KPClient<'a> {
    db: &'a Database,
    id_map: BTreeMap<u64, &'a Entry>,
}

fn field_name_map(name: &str) -> &str {
    if name == "title" {
        "Title"
    } else if name == "username" {
        "UserName"
    } else if name == "url" {
        "URL"
    } else if name == "notes" {
        "Notes"
    } else if name == "password" {
        "Password"
    } else {
        name
    }
}

fn print_otp(e: &Entry) -> Result<()> {
    // NOTE: there are two types of otp secret in the database
    // one is in the url (e.g. otpauth://....)
    // another one is in the attribute "TOTP Seed"
    if let Some(v) = e.get("otp") {
        let otp_url = v;
        let url = Url::parse(otp_url)?;
        let mut pairs = url.query_pairs();
        let map = BTreeMap::from_iter(pairs);
        let secret = map.get("secret").ok_or(anyhow!("no secret"))?;
        let code = TOTPBuilder::new()
            .base32_key(&secret)
            .finalize()
            .unwrap()
            .generate();
        debug!("otp: {v} {url:#?} {map:#?} {secret} {code}");
        print!("{code} ");
    } else if let Some(v) = e.get("TOTP Seed") {
        // NOTE: some secret are space separted
        let clean: &str = &v.split_ascii_whitespace().collect::<Vec<&str>>().join("");
        let code = TOTPBuilder::new()
            .base32_key(&clean)
            .finalize()
            .unwrap()
            .generate();
        print!("{code} ");
    } else {
        print!("nil ")
    }
    Ok(())
}

fn print_field(e: &Entry, field: &String) -> Result<()> {
    let ff = field_name_map(field.as_str());
    if ff == "otp" {
        print_otp(e)?;
        return Ok(());
    }
    let val = e.get(ff);
    debug!("{:#?} {:#?}", field, val);
    if let Some(v) = val {
        print!("{v} ");
    } else {
        print!("nil ");
    }
    Ok(())
}

fn print_entry(e: &Entry, fields: &Option<Vec<String>>, id: Option<u64>) -> Result<()> {
    debug!("{:#?}", &e);
    if let Some(id) = id {
        print!("{id} ");
    }

    if let Some(fs) = fields.as_ref() {
        for f in fs.iter() {
            print_field(e, f)?;
        }
    } else {
        let title = e.get_title().unwrap();
        let user = e.get_username().unwrap();
        let pass = e.get_password().unwrap();
        print!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
    };
    println!("");
    Ok(())
}

impl<'a, 'b> KPClient<'a> {
    pub fn new(db: &'a Database) -> Result<Self> {
        let mut id_map = BTreeMap::new();
        let mut id = 0;
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    debug!("Saw group '{0}'", g.name);
                }
                NodeRef::Entry(e) => {
                    debug!("{:#?}", &e);
                    id_map.insert(id, e);
                    id += 1;
                }
            };
        }
        Ok(Self { db, id_map })
    }

    pub fn do_list(&'a self, fields: &Option<Vec<String>>) -> Result<()> {
        for (k, v) in self.id_map.iter() {
            debug!("{} {:#?}", k, v);
            print_entry(v, fields, Some(*k));
        }
        Ok(())
    }

    pub fn do_get(&'a self, id: u64, fields: &Option<Vec<String>>) -> Result<()> {
        let entry = self.id_map.get(&id);
        if let Some(e) = entry {
            debug!("{:#?}", e);
            print_entry(e, fields, None);
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    debug!("args {:#?}", args);
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(convert_filter(args.verbose.log_level_filter())))
        .init();
    // Open KeePass database
    let path = std::path::Path::new("/Users/fuyu0425/keepass/fast.kdbx");
    // let password =
    //     rpassword::prompt_password("Password (or blank for none): ").expect("Read password");
    let password = "12345678";
    // let db = Database::open(&mut File::open(path)?, Some("12345678"), None)?;

    let db = Database::open(&mut File::open(path)?, Some(password), None)?;
    let mut kp_client = KPClient::new(&db)?;
    match &args.action {
        Action::List {
            show_password,
            fields,
        } => kp_client.do_list(fields)?,
        Action::Get { id, fields } => kp_client.do_get(*id, fields)?,
        Action::Server => {
            let mut rl = Editor::<()>::new()?;
            loop {
                let readline = rl.readline(">> ");
                match readline {
                    Ok(line) => {
                        // rl.add_history_entry(line.as_str());
                        let mut _v_args_line: Vec<&str> = line.trim().split(' ').collect();
                        debug!("{:#?}", &_v_args_line);
                        let mut v_args_line = vec![" "];
                        v_args_line.append(&mut _v_args_line);
                        let args_line = Args::try_parse_from(&v_args_line)?;
                        debug!("{:#?}", &args_line);
                        match &args_line.action {
                            Action::List {
                                show_password,
                                fields,
                            } => kp_client.do_list(fields)?,
                            Action::Get { id, fields } => kp_client.do_get(*id, fields)?,
                            Action::Server => {
                                println!("cannot call server in server")
                            }
                            _ => todo!(),
                        }
                    }
                    Err(ReadlineError::Interrupted) => {
                        println!("CTRL-C");
                        break;
                    }
                    Err(ReadlineError::Eof) => {
                        println!("CTRL-D");
                        break;
                    }
                    Err(err) => {
                        println!("Error: {:?}", err);
                        break;
                    }
                }
            }
        }
        _ => todo!(),
    };
    Ok(())
}

fn convert_filter(filter: log::LevelFilter) -> tracing_subscriber::filter::LevelFilter {
    match filter {
        log::LevelFilter::Off => tracing_subscriber::filter::LevelFilter::OFF,
        log::LevelFilter::Error => tracing_subscriber::filter::LevelFilter::ERROR,
        log::LevelFilter::Warn => tracing_subscriber::filter::LevelFilter::WARN,
        log::LevelFilter::Info => tracing_subscriber::filter::LevelFilter::INFO,
        log::LevelFilter::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
        log::LevelFilter::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
    }
}
