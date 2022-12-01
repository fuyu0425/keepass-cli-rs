#![allow(warnings)]

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use directories::{BaseDirs, ProjectDirs, UserDirs};
use is_terminal::IsTerminal;
use keepass::{Database, Entry, Icon, NodeRef};
use lexpr::{print, sexp, Value};
use libreauth::oath::TOTPBuilder;
use once_cell::sync::OnceCell;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::char;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info};
use tracing_core::Level;
use tracing_subscriber::{filter, prelude::*};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use url::Url;
shadow_rs::shadow!(build);

const COOKIE_PRE: char = 254 as char;
const COOKIE_POST: char = 255 as char;

/// project directories
static PROJECT_DIRS: OnceCell<ProjectDirs> = OnceCell::new();

fn get_project_dirs() -> &'static ProjectDirs {
    &PROJECT_DIRS.get().unwrap()
}

fn get_data_dir() -> &'static Path {
    &PROJECT_DIRS.get().unwrap().data_dir()
}

fn get_custom_icon_dir() -> PathBuf {
    let data_dir = get_data_dir();
    let custom_icon_path = data_dir.join("custom_icons");
    custom_icon_path
}

fn get_custom_icon_path(uuid: &String) -> PathBuf {
    let custom_icon_dir = get_custom_icon_dir();
    let bytes = base64::decode(uuid).unwrap();
    let new_id = base58::ToBase58::to_base58(bytes.as_slice());
    custom_icon_dir.join(new_id)
}

fn get_builtin_icon_dir() -> PathBuf {
    let data_dir = get_data_dir();
    let icon_path = data_dir.join("icons");
    icon_path
}

fn get_builtin_icon_path(id: u8) -> PathBuf {
    let builtin_icon_dir = get_builtin_icon_dir();
    let icon_file = format!("{:02}.{}", id, "svg");
    builtin_icon_dir.join(icon_file)
}

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

    /// copy; used for callback in emacs
    #[clap(long = "copy", short = 'c', default_value = "false", global = true)]
    copy: bool,

    /// show; used for callback in emacs
    #[clap(long = "meesage", short = 'm', global = true)]
    message: Option<String>,

    /// keepass database path
    #[clap(long = "database", short = 'd')]
    database: Option<String>,

    /// icons
    #[clap(long = "icon", short = 'i', default_value = "false", global = true)]
    icon: bool,

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
    /// reload database
    #[clap(alias = "r")]
    Reload,
    /// quit server
    #[clap(alias = "q")]
    Quit,
}

#[derive(Debug)]
pub struct KPClient<'a> {
    db_manager: &'a DatabaseManager<'a>,
    id_map: BTreeMap<u64, &'a Entry>,
}

#[derive(Debug, Clone)]
pub enum Field {
    Username(String),
    Password(String),
    Title(String),
    Note(String),
    Url(String),
    Otp(String),
    Unimplemented,
}

impl Field {
    pub fn index(&self) -> String {
        match self {
            Self::Username(_) => "username",
            Self::Password(_) => "password",
            Self::Title(_) => "title",
            Self::Note(_) => "note",
            Self::Url(_) => "url",
            Self::Otp(_) => "otp",
            Self::Unimplemented => todo!(),
        }
        .to_string()
    }

    pub fn to_string(&self) -> String {
        match self {
            Self::Username(v) => v,
            Self::Password(v) => v,
            Self::Title(v) => v,
            Self::Note(v) => v,
            Self::Url(v) => v,
            Self::Otp(v) => v,
            Self::Unimplemented => todo!(),
        }
        .to_string()
    }

    /// username => :username
    pub fn to_sexp_value(&self) -> Value {
        Value::keyword(self.to_string())
    }
}

#[derive(Debug, Default)]
pub struct ParsedEntry {
    pub id: u64,
    pub fields: BTreeMap<String, Field>,
    pub has_otp: bool,
    pub icon: Icon,
}

impl ParsedEntry {
    /// fields: order of fields when printing
    pub fn to_sexp_value(&self, fields: &Option<Vec<String>>) -> Result<Value> {
        let mut values: Vec<Value> = vec![];
        if let Some(fields) = fields {
            for field in fields.iter() {
                if field == "id" {
                    values.push(self.id.into());
                } else if field == "otp" {
                    values.push(Value::string(self.get_otp_code()?));
                } else if field == "has-otp" {
                    values.push(Value::Bool(self.has_otp));
                } else if field == "icon" {
                    let value = match &self.icon {
                        Icon::IconID(id) => {
                            Value::string(get_builtin_icon_path(*id).display().to_string())
                        }
                        Icon::CustomIcon(uuid) => {
                            Value::string(get_custom_icon_path(uuid).display().to_string())
                        }
                        Icon::None => {
                            // NOTE: 0 as default icon for keepassxc
                            Value::string(get_builtin_icon_path(0).display().to_string())
                        }
                    };
                    values.push(value);
                } else {
                    let val = self.fields.get(field);
                    if let Some(v) = val {
                        values.push(Value::string(v.to_string()));
                    } else {
                        bail!("unsuppored field {}", field)
                    }
                }
            }
        }
        Ok(Value::list(values))
    }
    pub fn to_emacs(&self, fields: &Option<Vec<String>>) -> Result<String> {
        let mut ret = String::new();
        Ok(ret)
    }
    pub fn get_otp_code(&self) -> Result<String> {
        let secret = self
            .fields
            .get(&"otp".to_string())
            .ok_or(anyhow!("otp not found"))?;
        let code = TOTPBuilder::new()
            .base32_key(&secret.to_string())
            .finalize()
            .unwrap()
            .generate();
        Ok(code)
    }
}

#[derive(Debug, Default)]
pub struct Response {
    pub ty: String,
    pub entries: Vec<ParsedEntry>,
    pub show: bool,
    pub copy: bool,
    pub message: Option<String>,
    pub otp_expire: Option<u64>,
    pub server_message: Option<String>,
}

impl Response {
    pub fn new(ty: String) -> Self {
        Self {
            ty,
            ..Default::default()
        }
    }

    pub fn to_sexp_value(&self, fields: &Option<Vec<String>>) -> Result<Value> {
        let mut ret: Value;
        let mut value_entries: Vec<Value> = vec![];
        let mut field_sexps: Vec<Value> = vec![];
        for entry in self.entries.iter() {
            let vsexp = entry.to_sexp_value(fields)?;
            value_entries.push(vsexp);
        }

        if let Some(fields) = fields.as_ref() {
            for field in fields.iter() {
                let fsexp = Value::keyword(field.to_string());
                field_sexps.push(fsexp);
            }
        }

        let mut retv: Vec<Value> = vec![];
        retv.push(Value::keyword(self.ty.to_string()));
        retv.push(Value::Bool(true));
        retv.push(Value::keyword("field"));
        retv.push(Value::list(field_sexps));
        retv.push(Value::keyword("data"));
        retv.push(Value::list(value_entries));
        retv.push(Value::keyword("show"));
        retv.push(Value::Bool(self.show));
        retv.push(Value::keyword("copy"));
        retv.push(Value::Bool(self.copy));
        if let Some(msg) = &self.message {
            retv.push(Value::keyword("msg"));
            retv.push(Value::string(msg.to_string()));
        }
        if let Some(server_msg) = &self.server_message {
            retv.push(Value::keyword("server-msg"));
            retv.push(Value::string(server_msg.to_string()));
        }
        Ok(Value::list(retv))
    }
    pub fn to_emacs(&self, fields: &Option<Vec<String>>) -> Result<String> {
        let s = self.to_sexp_value(fields)?;
        let ret = lexpr::to_string_custom(&s, print::Options::elisp())?;
        let len = ret.len();
        let ret = format!("{}{:x}{}{}\n", COOKIE_PRE, len + 1, COOKIE_POST, ret).to_string();
        Ok(ret)
    }
    pub fn add_entry(&mut self, e: &Entry, id: u64) -> Result<()> {
        let mut pe = ParsedEntry::try_from(e)?;
        pe.id = id;
        self.entries.push(pe);
        Ok(())
    }

    pub fn add_parsed_entry(&mut self, e: ParsedEntry) -> Result<()> {
        self.entries.push(e);
        Ok(())
    }
}

impl TryFrom<&Entry> for ParsedEntry {
    type Error = anyhow::Error;
    fn try_from(e: &Entry) -> Result<Self> {
        let mut fields: BTreeMap<String, Field> = BTreeMap::new();
        let mut has_otp = false;
        for key in e.fields.keys() {
            let f = match key.as_str() {
                "Title" => Field::Title(e.get_title().unwrap().to_string()),
                "UserName" => Field::Username(e.get_username().unwrap().to_string()),
                "Password" => Field::Password(e.get_password().unwrap().to_string()),
                "Notes" => Field::Note(e.get("Notes").unwrap().to_string()),
                "URL" => Field::Url(e.get("URL").unwrap().to_string()),
                "otp" => {
                    has_otp = true;
                    let otp_url = e.get("otp").unwrap();
                    let secret = otp_url_to_secret(otp_url)?;
                    Field::Otp(secret)
                }
                "TOTP Seed" => {
                    has_otp = true;
                    let otp_seed = e.get("TOTP Seed").unwrap();
                    let secret = otp_seed_to_secret(otp_seed)?;
                    Field::Otp(secret)
                }
                _ => Field::Unimplemented,
            };
            if !matches!(f, Field::Unimplemented) {
                fields.insert(f.index(), f);
            }
        }
        let mut icon = e.icon.clone();
        Ok(Self {
            fields,
            has_otp,
            icon,
            ..Default::default()
        })
    }
}

impl TryFrom<&Entry> for Response {
    type Error = anyhow::Error;
    fn try_from(e: &Entry) -> Result<Self> {
        let parsed_entry = ParsedEntry::try_from(e)?;
        Ok(Self {
            entries: vec![parsed_entry],
            ..Default::default()
        })
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

fn otp_url_to_secret(otp_url: &str) -> Result<String> {
    let url = Url::parse(otp_url)?;
    let mut pairs = url.query_pairs();
    let map = BTreeMap::from_iter(pairs);
    let secret = map.get("secret").ok_or(anyhow!("no secret"))?;
    Ok(secret.to_string())
}

fn otp_seed_to_secret(otp_seed: &str) -> Result<String> {
    let secret: &str = &otp_seed
        .split_ascii_whitespace()
        .collect::<Vec<&str>>()
        .join("");
    Ok(secret.to_string())
}

/// A proxy to offical keepassxc-cli which has more power
/// that can edit databases.
#[derive(Debug)]
pub struct KPXCProxy<'a> {
    pub path: &'a Path,
    pub password: String,
}

impl<'a> KPXCProxy<'a> {
    pub fn new(path: &'a Path, password: String) -> Self {
        Self { path, password }
    }

    pub fn edit(&self, e: &Entry) -> Result<()> {
        // TODO: make the sure the entry name is unique in the database
        // because official cli still does not support editing based on uuid
        Ok(())
    }

    /// generate process arguments to keepassxc-cli
    pub fn call(&self) -> Result<()> {
        // pipe password to stdin
        Ok(())
    }
}

impl<'a, 'b> KPClient<'a> {
    pub fn new(db_manager: &'a DatabaseManager) -> Result<Self> {
        let mut id_map = BTreeMap::new();
        Ok(Self { db_manager, id_map })
    }
    pub fn reload(&mut self) {
        let mut id = 0;
        self.id_map.clear();
        for node in &self.db_manager.db.root {
            match node {
                // FIXME: should call recursively to support nested groups
                NodeRef::Group(g) => {
                    debug!("Saw group '{0}'", g.name);
                }
                NodeRef::Entry(e) => {
                    debug!("{:#?}", &e);
                    self.id_map.insert(id, e);
                    id += 1;
                }
            };
        }
    }

    pub fn load_icons(&'a self) -> Result<()> {
        let custom_icon_path = get_custom_icon_dir();
        debug!("cicon {custom_icon_path:#?}");
        fs::create_dir_all(&custom_icon_path)?;
        for (uuid, icon_data) in self.db_manager.db.meta.custom_icons.iter() {
            // uuid is base64, which is not good!
            // transform it to base58 instead; can also be base62
            let bytes = base64::decode(uuid).unwrap();
            let new_id = base58::ToBase58::to_base58(bytes.as_slice());
            debug!("old {uuid} new {new_id}");
            let image_path = custom_icon_path.join(&new_id);
            if !image_path.try_exists()? {
                let icon_bytes = base64::decode(icon_data).unwrap();
                fs::write(image_path, icon_bytes);
            }
        }
        Ok(())
    }

    pub fn do_list(
        &'a self,
        fields: &Option<Vec<String>>,
        show: bool,
        copy: bool,
        msg: Option<String>,
    ) -> Result<()> {
        let mut res = Response::new("list".to_string());
        res.show = show;
        res.copy = copy;
        res.message = msg;
        for (k, e) in self.id_map.iter() {
            res.add_entry(*e, *k);
        }
        print!("{}", res.to_emacs(fields)?);
        Ok(())
    }

    pub fn do_get(
        &'a self,
        id: u64,
        fields: &Option<Vec<String>>,
        show: bool,
        copy: bool,
        msg: Option<String>,
    ) -> Result<()> {
        let entry = self.id_map.get(&id);
        let mut res = Response::new("get".to_string());
        res.show = show;
        res.copy = copy;
        res.message = msg;
        if let Some(e) = entry {
            res.add_entry(*e, id);
        }
        if let Some(fields) = fields {
            if (fields.contains(&"otp".to_string())) {
                let timestamp = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let remaining_time = 30 - (timestamp % 30);
                res.otp_expire = Some(remaining_time as u64);
                res.server_message =
                    Some(format!("OTP expires in {} seconds.", remaining_time).to_string());
            }
        }
        print!("{}", res.to_emacs(fields)?);
        Ok(())
    }
}

#[derive(Debug)]
pub struct DatabaseManager<'a> {
    pub path: &'a Path,
    pub password: String,
    pub db: Database,
}

impl<'a> DatabaseManager<'a> {
    pub fn new(path: &'a Path, password: String) -> Result<Self> {
        let db = Database::open(&mut File::open(path)?, Some(password.as_str()), None)?;
        // debug!("{:#?}", &db);
        // std::process::exit(0);
        Ok(Self { path, password, db })
    }
    pub fn reload(&mut self) -> Result<()> {
        let new_db = Database::open(
            &mut File::open(self.path)?,
            Some(self.password.as_str()),
            None,
        )?;
        debug!("update db!");
        self.db = new_db;
        Ok(())
    }
}

fn main() -> Result<()> {
    if let Some(proj_dirs) = ProjectDirs::from("", "", "keepass-cli") {
        PROJECT_DIRS.set(proj_dirs).unwrap();
    }

    let args = Args::parse();

    let filter = filter::Targets::new()
        .with_target(
            "keepass_cli",
            convert_filter(args.verbose.log_level_filter()),
        )
        .with_target("rustyline", Level::ERROR);

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    debug!("args {:#?}", args);

    if args.database.is_none() {
        bail!("Please specifiy database file through --database or -d")
    }

    // Open KeePass database
    let binding = args.database.unwrap();
    let path = std::path::Path::new(&binding);
    let password = if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        rpassword::prompt_password("Password (or blank for none): ").expect("Read password")
    } else {
        let mut t = String::new();
        io::stdin().read_line(&mut t);
        t.trim_end().to_string()
    };
    // let password = password.as_str();
    // debug!("passowrd {:#?}", password);

    let mut db_manager = DatabaseManager::new(path, password)?;
    db_manager.reload();
    let mut kp_client = KPClient::new(&db_manager)?;

    if args.icon {
        kp_client.load_icons();
        // return Ok(());
    }

    match &args.action {
        Action::List { fields } => {
            kp_client.reload();
            kp_client.do_list(fields, args.show, args.copy, args.message)?
        }
        Action::Get { id, fields } => {
            kp_client.reload();
            kp_client.do_get(*id, fields, args.show, args.copy, args.message)?
        }

        Action::Server => {
            let mut rl = Editor::<()>::new()?;
            let mut reload = false;
            loop {
                if reload {
                    db_manager.reload();
                    reload = false;
                }
                let mut kp_client = KPClient::new(&db_manager)?;
                kp_client.reload();
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
                                Action::List { fields } => kp_client.do_list(
                                    fields,
                                    args_line.show,
                                    args_line.copy,
                                    args_line.message,
                                )?,
                                Action::Get { id, fields } => kp_client.do_get(
                                    *id,
                                    fields,
                                    args_line.show,
                                    args_line.copy,
                                    args_line.message,
                                )?,
                                Action::Reload => {
                                    reload = true;
                                    break;
                                }
                                Action::Server => {
                                    println!("cannot call server in server")
                                }
                                Action::Quit => {
                                    return Ok(());
                                }
                                _ => todo!(),
                            }
                        }
                        Err(ReadlineError::Interrupted) => {
                            println!("CTRL-C");
                            return Ok(());
                        }
                        Err(ReadlineError::Eof) => {
                            println!("CTRL-D");
                            return Ok(());
                        }
                        Err(err) => {
                            println!("Error: {:?}", err);
                            return Ok(());
                        }
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
