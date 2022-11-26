#![allow(warnings)]

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use keepass::{Database, Entry, NodeRef};
use libreauth::oath::TOTPBuilder;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::char;
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

const COOKIE_PRE: char = 254 as char;
const COOKIE_POST: char = 255 as char;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
    /// emacs-friendly output
    #[clap(long = "emacs", short = 'e', default_value = "false", global = true)]
    emacs: bool,

    /// show; used for callback in emacs
    #[clap(long = "show", short = 's', default_value = "false", global = true)]
    show: bool,

    /// show; used for callback in emacs
    #[clap(long = "meesage", short = 'm', global = true)]
    message: Option<String>,

    /// keepass database path
    #[clap(long = "database", short = 'd')]
    database: Option<String>,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

#[derive(clap::Subcommand, Debug, Clone)]
enum Action {
    /// List All
    #[clap(alias = "ls")]
    List {
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
    /// quit server
    #[clap(alias = "q")]
    Quit,
}

#[derive(Debug)]
pub struct KPClient<'a> {
    db: &'a Database,
    id_map: BTreeMap<u64, &'a Entry>,
}

#[derive(Debug, Clone)]
pub enum Field {
    Username(String),
    Password(String),
    Title(String),
    Description(String),
    Url(String),
    Otp(String),
    HasOtp(bool),
}

#[derive(Debug)]
pub struct ParsedEntry {
    pub fields: Vec<Field>,
}

impl ParsedEntry {
    pub fn to_emacs(&self) -> Result<String> {
        let mut ret = String::new();
        Ok(ret)
    }
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

fn has_otp(e: &Entry) -> Result<bool> {
    let mut ret = false;
    if let Some(v) = e.get("otp") {
        ret = true;
    } else if let Some(v) = e.get("TOTP Seed") {
        ret = true;
    }
    Ok(ret)
}

fn print_otp(e: &Entry) -> Result<Vec<String>> {
    // NOTE: there are two types of otp secret in the database
    // one is in the url (e.g. otpauth://....)
    // another one is in the attribute "TOTP Seed"
    let mut ret: Vec<String> = vec![];
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
        ret.push(format!("\"{}\"", code));
    } else if let Some(v) = e.get("TOTP Seed") {
        // NOTE: some secret are space separted
        let clean: &str = &v.split_ascii_whitespace().collect::<Vec<&str>>().join("");
        let code = TOTPBuilder::new()
            .base32_key(&clean)
            .finalize()
            .unwrap()
            .generate();
        ret.push(format!("\"{}\"", code));
    } else {
        ret.push("\"None\"".to_string());
    }
    Ok(ret)
}

fn print_field(e: &Entry, field: &String) -> Result<Vec<String>> {
    let mut ret: Vec<String> = vec![];
    let ff = field_name_map(field.as_str());
    if ff == "otp" {
        ret.append(&mut print_otp(e)?);
        return Ok(ret);
    } else if ff == "has-otp" {
        let has = has_otp(&e)?;
        if has {
            ret.push("\"yes\"".to_string())
        } else {
            ret.push("\"no\"".to_string())
        }
        return Ok(ret);
    }
    let val = e.get(ff);
    debug!("{:#?} {:#?}", field, val);
    if let Some(v) = val {
        ret.push(format!("\"{}\"", v.to_string()));
        // ret.push(v.to_string());
    } else {
        ret.push("\"None\"".to_string());
    }
    Ok(ret)
}

fn print_entry(e: &Entry, fields: &Option<Vec<String>>, id: Option<u64>) -> Result<Vec<String>> {
    let mut ret: Vec<String> = vec![];
    debug!("{:#?}", &e);
    ret.push("(".to_string());
    if let Some(id) = id {
        ret.push(id.to_string());
    }

    if let Some(fs) = fields.as_ref() {
        for f in fs.iter() {
            ret.append(&mut print_field(e, f)?);
        }
    } else {
        let title = e.get_title().unwrap();
        let user = e.get_username().unwrap();
        let pass = e.get_password().unwrap();
        print!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
    };
    ret.push(")".to_string());
    Ok(ret)
}

fn print_with_cookie(s: &String) {
    // NOTE: newline is already in s
    let len = s.len();
    print!("{}{:x}{}{}", COOKIE_PRE, len, COOKIE_POST, s);
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

    pub fn do_list(
        &'a self,
        fields: &Option<Vec<String>>,
        show: bool,
        msg: &Option<String>,
    ) -> Result<()> {
        let mut output = String::new();
        output.push('(');
        output.push_str(":list ");
        output.push('(');
        let mut first = true;
        for (k, v) in self.id_map.iter() {
            if !first {
                // output.push('\n');
                output.push(' ');
            }
            debug!("{} {:#?}", k, v);
            let ret = print_entry(v, fields, Some(*k))?;
            output.push_str(ret.join(" ").as_str());
            first = false;
        }
        output.push(')');
        if show {
            output.push_str(" :show t");
        } else {
            output.push_str(" :show nil");
        }
        if let Some(msg) = msg.as_ref() {
            output.push_str(format!(" :message \"{}\"", &msg).as_str());
        }
        output.push(')');
        output.push('\n');
        print_with_cookie(&output);
        Ok(())
    }

    pub fn do_get(
        &'a self,
        id: u64,
        fields: &Option<Vec<String>>,
        show: bool,
        msg: &Option<String>,
    ) -> Result<()> {
        let mut output = String::new();
        output.push('(');
        output.push_str(":get ");
        output.push('(');
        let entry = self.id_map.get(&id);
        if let Some(e) = entry {
            debug!("{:#?}", e);
            let ret = print_entry(e, fields, None)?;
            output.push_str(ret.join(" ").as_str());
        }
        output.push(')');
        if show {
            output.push_str(" :show t");
        } else {
            output.push_str(" :show nil");
        }
        if let Some(msg) = msg.as_ref() {
            output.push_str(format!(" :message \"{}\"", &msg).as_str());
        }
        output.push(')');
        output.push('\n');
        print_with_cookie(&output);
        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    debug!("args {:#?}", args);
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(convert_filter(args.verbose.log_level_filter())))
        .init();

    if args.database.is_none() {
        bail!("Please specifiy database file through --database or -d")
    }

    // Open KeePass database
    let binding = args.database.unwrap();
    let path = std::path::Path::new(&binding);
    let password = if !args.emacs {
        rpassword::prompt_password("Password (or blank for none): ").expect("Read password")
    } else {
        let mut t = String::new();
        io::stdin().read_line(&mut t);
        t.trim_end().to_string()
    };
    let password = password.as_str();
    // debug!("passowrd {:#?}", password);

    let db = Database::open(&mut File::open(path)?, Some(password), None)?;
    let mut kp_client = KPClient::new(&db)?;

    match &args.action {
        Action::List { fields } => kp_client.do_list(fields, args.show, &args.message)?,
        Action::Get { id, fields } => kp_client.do_get(*id, fields, args.show, &args.message)?,
        Action::Server => {
            let mut rl = Editor::<()>::new()?;
            loop {
                let readline = rl.readline(if !&args.emacs { ">> " } else { "" });
                match readline {
                    Ok(line) => {
                        rl.add_history_entry(line.as_str());
                        let mut _v_args_line: Vec<String> = shellwords::split(&line)?;
                        debug!("{:#?}", &_v_args_line);
                        let mut v_args_line = vec![" ".to_string()];
                        v_args_line.append(&mut _v_args_line);
                        let args_line = Args::try_parse_from(&v_args_line)?;
                        debug!("{:#?}", &args_line);
                        match &args_line.action {
                            Action::List { fields } => {
                                kp_client.do_list(fields, args_line.show, &args_line.message)?
                            }
                            Action::Get { id, fields } => {
                                kp_client.do_get(*id, fields, args_line.show, &args_line.message)?
                            }
                            Action::Server => {
                                println!("cannot call server in server")
                            }
                            Action::Quit => {
                                break;
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
