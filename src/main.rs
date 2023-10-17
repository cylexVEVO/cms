use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::DateTime;
use clap::{Parser, Subcommand};
use futures::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Binary, Bson, Document},
    options::{FindOptions, IndexOptions},
    Client, Collection, Database, IndexModel,
};
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::OsRng,
};
use ring::hmac::{self, Key};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read, Write},
    net::SocketAddr,
};
use thiserror::Error;

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    GenerateApiKey {
        #[arg(short, long)]
        perms: Vec<ApiKeyPermission>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum ApiKeyPermission {
    Create,
    Read,
}

impl From<String> for ApiKeyPermission {
    fn from(value: String) -> Self {
        match value.as_str() {
            "create" => Self::Create,
            "read" => Self::Read,
            _ => panic!("invalid permission"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiKey {
    _id: ObjectId,
    key: Bson,
    perms: Vec<ApiKeyPermission>,
}

#[derive(Error, Debug)]
enum Error {
    #[error("io error")]
    IoError(#[from] io::Error),
    #[error("ring error")]
    RingError,
    #[error("auth required")]
    AuthRequired,
}

impl Into<StatusCode> for Error {
    fn into(self) -> StatusCode {
        match self {
            Self::AuthRequired => StatusCode::UNAUTHORIZED,
            Self::IoError(_) | Self::RingError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn get_signing_key() -> Result<Key, Error> {
    fn gen_and_save_key() -> Result<Key, Error> {
        let mut file = File::create("./cms-aksk.key")?;
        let rng = ring::rand::SystemRandom::new();
        let key_value: [u8; ring::digest::SHA256_OUTPUT_LEN] = match ring::rand::generate(&rng) {
            Ok(key_value) => key_value.expose(),
            Err(_) => return Err(Error::RingError),
        };
        file.write_all(&key_value)?;

        Ok(hmac::Key::new(hmac::HMAC_SHA256, &key_value))
    }

    match File::open("./cms-aksk.key") {
        Ok(mut file) => {
            let mut buf = vec![0; ring::digest::SHA256_OUTPUT_LEN];
            match file.read_exact(&mut buf) {
                Ok(_) => Ok(hmac::Key::new(hmac::HMAC_SHA256, &buf)),
                Err(_) => gen_and_save_key(),
            }
        }
        Err(_) => gen_and_save_key(),
    }
}

async fn verify_api_key(
    coll: &Collection<ApiKey>,
    required_perms: Vec<ApiKeyPermission>,
    api_key: &String,
) -> Result<bool, Error> {
    let signed_key = hmac::sign(&get_signing_key()?, api_key.as_bytes());
    Ok(match coll.find_one(doc! { "key": Bson::Binary(Binary { bytes: signed_key.as_ref().to_vec(), subtype: mongodb::bson::spec::BinarySubtype::Generic }) }, None)
        .await
        .unwrap() {
            Some(found_key) => {
                required_perms.iter().all(|p| found_key.perms.contains(p))
            },
            None => false
        })
}

async fn verify_api_key_header(
    db: &Database,
    headers: &HeaderMap,
    required_perms: Vec<ApiKeyPermission>,
) -> Result<bool, Error> {
    Ok(match headers.get("api-key") {
        Some(api_key) => {
            let coll = db.collection::<ApiKey>("api_keys");
            verify_api_key(
                &coll,
                required_perms,
                &api_key.to_str().unwrap().to_string(),
            )
            .await?
        }
        None => false,
    })
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().unwrap();
    let client = Client::with_uri_str(std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let db = client.database("cms");
    db.collection::<Model>("models")
        .create_index(
            IndexModel::builder()
                .keys(doc! {
                    "slug": 1
                })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None,
        )
        .await
        .unwrap();
    db.collection::<Model>("api_keys")
        .create_index(
            IndexModel::builder()
                .keys(doc! {
                    "key": 1
                })
                .build(),
            None,
        )
        .await
        .unwrap();

    let args = Args::parse();

    match args.command {
        Some(Command::GenerateApiKey { perms }) => {
            let api_key_string = Alphanumeric.sample_string(&mut OsRng, 48);
            let key = get_signing_key().expect("failed to get signing key");
            let signed_key = hmac::sign(&key, api_key_string.as_bytes());

            let api_key = ApiKey {
                _id: ObjectId::new(),
                key: Bson::Binary(Binary {
                    bytes: signed_key.as_ref().to_vec(),
                    subtype: mongodb::bson::spec::BinarySubtype::Generic,
                }),
                perms,
            };

            let coll = db.collection::<ApiKey>("api_keys");
            coll.insert_one(api_key, None).await.unwrap();

            println!("{}", api_key_string);

            std::process::exit(0);
        }
        None => {}
    }

    let app = Router::new()
        .route("/models", post(create_model).get(list_models))
        .route("/models/:slug", get(list_model))
        .route(
            "/models/:slug/entries",
            post(create_entry).get(list_entries),
        )
        .with_state(db);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Model {
    _id: ObjectId,
    name: String,
    slug: String,
    fields: Vec<ModelField>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ModelField {
    name: String,
    slug: String,
    kind: ModelFieldType,
    options: Option<ModelFieldOptions>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ModelFieldType {
    Text,
    Number,
    DateTime,
    Boolean,
    Enum(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ModelFieldOptions {
    Text {
        min_length: Option<u64>,
        max_length: Option<u64>,
    },
    Number {
        min: Option<i64>,
        max: Option<i64>,
    },
    DateTime {
        not_before: Option<String>,
        not_after: Option<String>,
    },
    Enum {
        allow_multiple: Option<bool>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Entry {
    _id: ObjectId,
    model_id: ObjectId,
    fields: HashMap<String, EntryField>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum EntryField {
    Text(String),
    Number(i64),
    DateTime(String),
    Boolean(bool),
    Enum(Vec<String>),
}

#[derive(Deserialize, Debug)]
struct CreateModel {
    name: String,
    slug: String,
    fields: Vec<ModelField>,
}

async fn create_model(
    State(db): State<Database>,
    headers: HeaderMap,
    Json(input): Json<CreateModel>,
) -> Result<Json<Model>, StatusCode> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Create]).await {
        Ok(true) => {}
        Ok(false) => return Err(Error::AuthRequired.into()),
        Err(err) => return Err(err.into()),
    }

    // ensure all fields have unique names and slugs
    let mut seen_names = HashSet::new();
    let mut seen_slugs = HashSet::new();

    for field in &input.fields {
        if seen_names.contains(&field.name) {
            panic!("duplicate field name");
        }

        if seen_slugs.contains(&field.slug) {
            panic!("duplicate field slug");
        }

        // validate field options
        match (&field.options, &field.kind) {
            (
                Some(ModelFieldOptions::Text {
                    min_length,
                    max_length,
                }),
                &ModelFieldType::Text,
            ) => {
                // make sure max length is not less than min, and vice versa
                if let (Some(min_length), Some(max_length)) = (min_length, max_length) {
                    if min_length > max_length {
                        panic!("min_length must be less than max_length");
                    }
                }
            }
            (Some(ModelFieldOptions::Number { min, max }), &ModelFieldType::Number) => {
                // make sure max length is not less than min, and vice versa
                if let (Some(min), Some(max)) = (min, max) {
                    if min > max {
                        panic!("min must be less than max");
                    }
                }
            }
            (
                Some(ModelFieldOptions::DateTime {
                    not_before,
                    not_after,
                }),
                &ModelFieldType::DateTime,
            ) => {
                // validate dates
                if let Some(not_before) = not_before {
                    match DateTime::parse_from_rfc3339(&not_before) {
                        Ok(_) => {}
                        Err(_) => panic!("invalid field value"),
                    }
                }

                if let Some(not_after) = not_after {
                    match DateTime::parse_from_rfc3339(&not_after) {
                        Ok(_) => {}
                        Err(_) => panic!("invalid field value"),
                    }
                }

                if let (Some(not_before), Some(not_after)) = (not_before, not_after) {
                    let (not_before, not_after) = (
                        DateTime::parse_from_rfc3339(&not_before).unwrap(),
                        DateTime::parse_from_rfc3339(&not_after).unwrap(),
                    );

                    if not_before > not_after {
                        panic!("not_before must be before not_after");
                    }
                }
            }
            (
                Some(ModelFieldOptions::Enum { allow_multiple: _ }),
                &ModelFieldType::Enum(ref variants),
            ) => {
                // ensure all variants are unique
                let mut seen_variants = HashSet::new();

                for variant in variants {
                    if seen_variants.contains(variant) {
                        panic!("duplicate enum variant");
                    }

                    seen_variants.insert(variant);
                }
            }
            (None, _) => {}
            _ => panic!("invalid field options"),
        }

        seen_names.insert(&field.name);
        seen_slugs.insert(&field.slug);
    }

    let model = Model {
        _id: ObjectId::new(),
        name: input.name,
        slug: input.slug,
        fields: input.fields,
    };

    let coll = db.collection::<Model>("models");
    coll.insert_one(&model, None).await.unwrap();

    Ok(Json(model))
}

async fn list_models(
    State(db): State<Database>,
    headers: HeaderMap,
) -> Result<Json<Vec<Model>>, StatusCode> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Read]).await {
        Ok(true) => {}
        Ok(false) => return Err(Error::AuthRequired.into()),
        Err(err) => return Err(err.into()),
    }

    let coll = db.collection::<Model>("models");
    Ok(Json(
        coll.find(doc! {}, None)
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap(),
    ))
}

async fn list_model(
    State(db): State<Database>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Model>, StatusCode> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Read]).await {
        Ok(true) => {}
        Ok(false) => return Err(Error::AuthRequired.into()),
        Err(err) => return Err(err.into()),
    }

    let coll = db.collection::<Model>("models");
    Ok(Json(
        coll.find_one(doc! { "slug": slug }, None)
            .await
            .unwrap()
            .unwrap(),
    ))
}

// TODO: update model
// TODO: delete model

#[derive(Serialize, Deserialize, Debug)]
struct CreateEntry {
    fields: HashMap<String, EntryField>,
}

async fn create_entry(
    State(db): State<Database>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CreateEntry>,
) -> Result<Json<Entry>, StatusCode> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Create]).await {
        Ok(true) => {}
        Ok(false) => return Err(Error::AuthRequired.into()),
        Err(err) => return Err(err.into()),
    }

    let coll = db.collection::<Model>("models");
    let model = coll
        .find_one(doc! { "slug": slug }, None)
        .await
        .unwrap()
        .unwrap();

    let mut fields = HashMap::new();

    // ensure entry has the same fields as model
    let mut model_fields: Vec<&String> = model.fields.iter().map(|f| &f.slug).collect();
    let mut entry_fields: Vec<&String> = input.fields.iter().map(|f| f.0).collect();

    model_fields.sort();
    entry_fields.sort();

    if model_fields != entry_fields {
        panic!("entry fields must match model fields");
    }

    for (name, value) in input.fields {
        let model_field = model.fields.iter().find(|f| f.slug == name).unwrap();
        let mut value = value;

        // ensure field kind matches definition
        match (&value, &model_field.kind) {
            (EntryField::Text(text), ModelFieldType::Text) => {
                // validate field value against field options
                match &model_field.options {
                    Some(ModelFieldOptions::Text {
                        min_length,
                        max_length,
                    }) => {
                        if let Some(min_length) = min_length {
                            if &(text.len() as u64) < min_length {
                                panic!("value is too short");
                            }
                        }

                        if let Some(max_length) = max_length {
                            if &(text.len() as u64) > max_length {
                                panic!("value is too long");
                            }
                        }
                    }
                    None => {}
                    _ => panic!("invalid field options"),
                }
            }
            (EntryField::Number(value), ModelFieldType::Number) => match &model_field.options {
                Some(ModelFieldOptions::Number { min, max }) => {
                    if let Some(min) = min {
                        if value < min {
                            panic!("value is too small");
                        }
                    }

                    if let Some(max) = max {
                        if value > max {
                            panic!("value is too large");
                        }
                    }
                }
                None => {}
                _ => panic!("invalid field options"),
            },
            (EntryField::DateTime(date), ModelFieldType::DateTime) => {
                // ensure date is valid
                match DateTime::parse_from_rfc3339(&date) {
                    Ok(date) => {
                        match &model_field.options {
                            Some(ModelFieldOptions::DateTime {
                                not_before,
                                not_after,
                            }) => {
                                if let Some(not_before) = not_before {
                                    let not_before =
                                        DateTime::parse_from_rfc3339(&not_before).unwrap();

                                    if date < not_before {
                                        panic!("date is before not_before");
                                    }
                                }

                                if let Some(not_after) = not_after {
                                    let not_after =
                                        DateTime::parse_from_rfc3339(&not_after).unwrap();

                                    if date > not_after {
                                        panic!("date is after not_after");
                                    }
                                }
                            }
                            None => {}
                            _ => panic!("invalid field options"),
                        }

                        value = EntryField::DateTime(date.to_rfc3339())
                    }
                    Err(_) => panic!("invalid field value"),
                }
            }
            (EntryField::Boolean(_), ModelFieldType::Boolean) => {}
            (EntryField::Enum(selected_variants), ModelFieldType::Enum(enum_variants)) => {
                // ensure selection count is valid with enum options
                match &model_field.options {
                    Some(ModelFieldOptions::Enum { allow_multiple }) => {
                        if !allow_multiple.unwrap_or(false) && selected_variants.len() > 1 {
                            panic!("too many selected variants");
                        }
                    }
                    None => {
                        // no `options` on an enum is the same as `allow_multiple` being `false`
                        if selected_variants.len() > 1 {
                            panic!("too many selected variants");
                        }
                    }
                    _ => panic!("invalid field options"),
                }

                // ensure specified variants are part of enum
                if !selected_variants.iter().all(|f| enum_variants.contains(f)) {
                    panic!("invalid field value");
                }

                // ensure all selected variants are unique
                let mut seen_variants = HashSet::new();

                for variant in selected_variants {
                    if seen_variants.contains(variant) {
                        panic!("duplicate enum variant");
                    }

                    seen_variants.insert(variant);
                }
            }
            _ => panic!("invalid field value"),
        }

        fields.insert(name, value);
    }

    let entry = Entry {
        _id: ObjectId::new(),
        model_id: model._id,
        fields,
    };

    let coll = db.collection::<Entry>("entries");
    coll.insert_one(&entry, None).await.unwrap();

    Ok(Json(entry))
}

#[derive(Deserialize, Debug)]
struct ListEntries {
    id: Option<String>,
    select: Option<String>,
}

async fn list_entries(
    State(db): State<Database>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    query: Option<Query<ListEntries>>,
) -> Result<Json<Vec<Entry>>, StatusCode> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Read]).await {
        Ok(true) => {}
        Ok(false) => return Err(Error::AuthRequired.into()),
        Err(err) => return Err(err.into()),
    }

    let coll = db.collection::<Model>("models");
    let model = coll
        .find_one(doc! { "slug": slug }, None)
        .await
        .unwrap()
        .unwrap();

    let filter = match &query {
        Some(query) => {
            let mut filter = Document::new();

            if let Some(id) = &query.id {
                let ids: Vec<ObjectId> = id
                    .split(',')
                    .map(|id| ObjectId::parse_str(id).unwrap())
                    .collect();

                filter.insert("_id", doc! { "$in": ids });
            }

            filter
        }
        None => {
            doc! {
                "model_id": model._id
            }
        }
    };

    let options = match &query {
        Some(query) => {
            let mut projection = Document::new();

            if let Some(select) = &query.select {
                select.split(',').for_each(|field| {
                    // make sure field is in model
                    if model.fields.iter().find(|f| f.slug == field).is_none() {
                        panic!("field not in model");
                    }

                    projection.insert(format!("fields.{}", field), 1);
                });

                projection.insert("model_id", 1);
            }

            Some(FindOptions::builder().projection(projection).build())
        }
        None => None,
    };

    let coll = db.collection::<Entry>("entries");
    let entries = coll
        .find(filter, options)
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();

    Ok(Json(entries))
}

// TODO: update entries
// TODO: delete entries
