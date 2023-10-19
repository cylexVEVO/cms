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
    #[error("duplicate field name")]
    DuplicateFieldName,
    #[error("duplicate field slug")]
    DuplicateFieldSlug,
    #[error("min_length must be less than max_length")]
    InvalidLengthRange,
    #[error("min must be less than max")]
    InvalidValueRange,
    #[error("invalid field value")]
    InvalidFieldValue,
    #[error("not_before must be before not_after")]
    InvalidDateRange,
    #[error("duplicate enum variant")]
    DuplicateEnumVariant,
    #[error("invalid field options")]
    InvalidFieldOptions,
    #[error("entry fields must match model fields")]
    ModelEntryFieldsMismatch,
    #[error("value is too short")]
    ValueTooShort,
    #[error("value is too long")]
    ValueTooLong,
    #[error("value is too small")]
    ValueTooSmall,
    #[error("value is too large")]
    ValueTooLarge,
    #[error("variant is not part of enum")]
    UnknownEnumVariant,
    #[error("too many selected variants")]
    TooManyVariants,
    #[error("date is before not_before")]
    DateTooEarly,
    #[error("date is after not_after")]
    DateTooLate,
    #[error("field not in model")]
    UnknownField,
    #[error("unknown error")]
    MongoError(#[from] mongodb::error::Error),
    #[error("unknown error")]
    ToStrError(#[from] axum::http::header::ToStrError),
    #[error("unknown error")]
    UnknownError,
}

impl Into<(StatusCode, String)> for Error {
    fn into(self) -> (StatusCode, String) {
        match self {
            Self::IoError(_) | Self::RingError | Self::MongoError(_) | Self::ToStrError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            Self::AuthRequired => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            Self::DuplicateFieldName => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "duplicate field name".into(),
            ),
            Self::DuplicateFieldSlug => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "duplicate field slug".into(),
            ),
            Self::InvalidLengthRange => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "min_length must be less than max_length".into(),
            ),
            Self::InvalidValueRange => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "min must be less than max".into(),
            ),
            Self::InvalidFieldValue => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid field value".into(),
            ),
            Self::InvalidDateRange => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "not_before must be before not_after".into(),
            ),
            Self::DuplicateEnumVariant => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "duplicate enum variant".into(),
            ),
            Self::InvalidFieldOptions => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid field options".into(),
            ),
            Self::ModelEntryFieldsMismatch => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "entry fields must match model fields".into(),
            ),
            Self::ValueTooShort => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "value is too short".into(),
            ),
            Self::ValueTooLong => (StatusCode::UNPROCESSABLE_ENTITY, "value is too long".into()),
            Self::ValueTooSmall => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "value is too small".into(),
            ),
            Self::ValueTooLarge => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "value is too large".into(),
            ),
            Self::UnknownEnumVariant => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "variant is not part of enum".into(),
            ),
            Self::TooManyVariants => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "too many selected variants".into(),
            ),
            Self::DateTooEarly => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "date is before not_before".into(),
            ),
            Self::DateTooLate => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "date is after not_after".into(),
            ),
            Self::UnknownField => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "field not in model".into(),
            ),
            Self::UnknownError => (StatusCode::UNPROCESSABLE_ENTITY, "unknown error".into()),
        }
    }
}

impl<T> Into<Result<T, (StatusCode, String)>> for Error {
    fn into(self) -> Result<T, (StatusCode, String)> {
        return Err(self.into());
    }
}

// convert foreign results into our result type
// i didn't feel like figuring out the weird type stuff
// to just implement From<>
fn frtor<T, U>(parse_error: Result<T, U>) -> Result<T, (StatusCode, String)> {
    match parse_error {
        Ok(data) => return Ok(data),
        Err(_) => Error::UnknownError.into(),
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
        .await? {
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
            verify_api_key(&coll, required_perms, &api_key.to_str()?.to_string()).await?
        }
        None => false,
    })
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect("failed to get env vars");

    let client = Client::with_uri_str(
        std::env::var("DATABASE_URL").expect("failed to get DATABASE_URL env var"),
    )
    .await
    .expect("db connection failed");
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
        .expect("failed to create model slug idx");

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
        .expect("failed to create api_keys key idx");

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
            coll.insert_one(api_key, None)
                .await
                .expect("failed to create api key");

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
        .expect("failed to bind server");
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
) -> Result<Json<Model>, (StatusCode, String)> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Create]).await {
        Ok(true) => {}
        Ok(false) => return Error::AuthRequired.into(),
        Err(err) => return err.into(),
    }

    // ensure all fields have unique names and slugs
    let mut seen_names = HashSet::new();
    let mut seen_slugs = HashSet::new();

    for field in &input.fields {
        if seen_names.contains(&field.name) {
            return Error::DuplicateFieldName.into();
        }

        if seen_slugs.contains(&field.slug) {
            return Error::DuplicateFieldSlug.into();
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
                        return Error::InvalidLengthRange.into();
                    }
                }
            }
            (Some(ModelFieldOptions::Number { min, max }), &ModelFieldType::Number) => {
                // make sure max length is not less than min, and vice versa
                if let (Some(min), Some(max)) = (min, max) {
                    if min > max {
                        return Error::InvalidValueRange.into();
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
                        Err(_) => return Error::InvalidFieldValue.into(),
                    }
                }

                if let Some(not_after) = not_after {
                    match DateTime::parse_from_rfc3339(&not_after) {
                        Ok(_) => {}
                        Err(_) => return Error::InvalidFieldValue.into(),
                    }
                }

                if let (Some(not_before), Some(not_after)) = (not_before, not_after) {
                    let (not_before, not_after) = (
                        frtor(DateTime::parse_from_rfc3339(&not_before))?,
                        frtor(DateTime::parse_from_rfc3339(&not_after))?,
                    );

                    if not_before > not_after {
                        return Error::InvalidDateRange.into();
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
                        return Error::DuplicateEnumVariant.into();
                    }

                    seen_variants.insert(variant);
                }
            }
            (None, _) => {}
            _ => return Error::InvalidFieldOptions.into(),
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
    frtor(coll.insert_one(&model, None).await)?;

    Ok(Json(model))
}

async fn list_models(
    State(db): State<Database>,
    headers: HeaderMap,
) -> Result<Json<Vec<Model>>, (StatusCode, String)> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Read]).await {
        Ok(true) => {}
        Ok(false) => return Error::AuthRequired.into(),
        Err(err) => return err.into(),
    }

    let coll = db.collection::<Model>("models");

    Ok(Json(frtor(
        frtor(coll.find(doc! {}, None).await)?.try_collect().await,
    )?))
}

async fn list_model(
    State(db): State<Database>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Option<Model>>, (StatusCode, String)> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Read]).await {
        Ok(true) => {}
        Ok(false) => return Error::AuthRequired.into(),
        Err(err) => return err.into(),
    }

    let coll = db.collection::<Model>("models");
    Ok(Json(frtor(
        coll.find_one(doc! { "slug": slug }, None).await,
    )?))
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
) -> Result<Json<Option<Entry>>, (StatusCode, String)> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Create]).await {
        Ok(true) => {}
        Ok(false) => return Error::AuthRequired.into(),
        Err(err) => return err.into(),
    }

    let coll = db.collection::<Model>("models");
    let model = if let Some(model) = frtor(coll.find_one(doc! { "slug": slug }, None).await)? {
        model
    } else {
        return Ok(Json(None));
    };

    let mut fields = HashMap::new();

    // ensure entry has the same fields as model
    let mut model_fields: Vec<&String> = model.fields.iter().map(|f| &f.slug).collect();
    let mut entry_fields: Vec<&String> = input.fields.iter().map(|f| f.0).collect();

    model_fields.sort();
    entry_fields.sort();

    if model_fields != entry_fields {
        return Error::ModelEntryFieldsMismatch.into();
    }

    for (name, value) in input.fields {
        let model_field = if let Some(model_field) = model.fields.iter().find(|f| f.slug == name) {
            model_field
        } else {
            return Error::UnknownField.into();
        };
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
                                return Error::ValueTooShort.into();
                            }
                        }

                        if let Some(max_length) = max_length {
                            if &(text.len() as u64) > max_length {
                                return Error::ValueTooLong.into();
                            }
                        }
                    }
                    None => {}
                    _ => return Error::InvalidFieldOptions.into(),
                }
            }
            (EntryField::Number(value), ModelFieldType::Number) => match &model_field.options {
                Some(ModelFieldOptions::Number { min, max }) => {
                    if let Some(min) = min {
                        if value < min {
                            return Error::ValueTooSmall.into();
                        }
                    }

                    if let Some(max) = max {
                        if value > max {
                            return Error::ValueTooLarge.into();
                        }
                    }
                }
                None => {}
                _ => return Error::InvalidFieldOptions.into(),
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
                                        frtor(DateTime::parse_from_rfc3339(&not_before))?;

                                    if date < not_before {
                                        return Error::DateTooEarly.into();
                                    }
                                }

                                if let Some(not_after) = not_after {
                                    let not_after =
                                        frtor(DateTime::parse_from_rfc3339(&not_after))?;

                                    if date > not_after {
                                        return Error::DateTooLate.into();
                                    }
                                }
                            }
                            None => {}
                            _ => return Error::InvalidFieldOptions.into(),
                        }

                        value = EntryField::DateTime(date.to_rfc3339())
                    }
                    Err(_) => return Error::InvalidFieldValue.into(),
                }
            }
            (EntryField::Boolean(_), ModelFieldType::Boolean) => {}
            (EntryField::Enum(selected_variants), ModelFieldType::Enum(enum_variants)) => {
                // ensure selection count is valid with enum options
                match &model_field.options {
                    Some(ModelFieldOptions::Enum { allow_multiple }) => {
                        if !allow_multiple.unwrap_or(false) && selected_variants.len() > 1 {
                            return Error::TooManyVariants.into();
                        }
                    }
                    None => {
                        // no `options` on an enum is the same as `allow_multiple` being `false`
                        if selected_variants.len() > 1 {
                            return Error::TooManyVariants.into();
                        }
                    }
                    _ => return Error::InvalidFieldOptions.into(),
                }

                // ensure specified variants are part of enum
                if !selected_variants.iter().all(|f| enum_variants.contains(f)) {
                    return Error::UnknownEnumVariant.into();
                }

                // ensure all selected variants are unique
                let mut seen_variants = HashSet::new();

                for variant in selected_variants {
                    if seen_variants.contains(variant) {
                        return Error::DuplicateEnumVariant.into();
                    }

                    seen_variants.insert(variant);
                }
            }
            _ => return Error::InvalidFieldValue.into(),
        }

        fields.insert(name, value);
    }

    let entry = Entry {
        _id: ObjectId::new(),
        model_id: model._id,
        fields,
    };

    let coll = db.collection::<Entry>("entries");
    frtor(coll.insert_one(&entry, None).await)?;

    Ok(Json(Some(entry)))
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
) -> Result<Json<Vec<Entry>>, (StatusCode, String)> {
    match verify_api_key_header(&db, &headers, vec![ApiKeyPermission::Read]).await {
        Ok(true) => {}
        Ok(false) => return Error::AuthRequired.into(),
        Err(err) => return err.into(),
    }

    let coll = db.collection::<Model>("models");
    let model = if let Some(models) = frtor(coll.find_one(doc! { "slug": slug }, None).await)? {
        models
    } else {
        return Ok(Json(vec![]));
    };

    let filter = match &query {
        Some(query) => {
            let mut filter = Document::new();

            if let Some(id) = &query.id {
                let ids: Vec<ObjectId> = id
                    .split(',')
                    .map(|id| frtor(ObjectId::parse_str(id)).unwrap())
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
                for field in select.split(',') {
                    // make sure field is in model
                    if model.fields.iter().find(|f| f.slug == field).is_none() {
                        return Error::UnknownField.into();
                    }

                    projection.insert(format!("fields.{}", field), 1);
                }

                projection.insert("model_id", 1);
            }

            Some(FindOptions::builder().projection(projection).build())
        }
        None => None,
    };

    let coll = db.collection::<Entry>("entries");
    let entries = frtor(frtor(coll.find(filter, options).await)?.try_collect().await)?;

    Ok(Json(entries))
}

// TODO: update entries
// TODO: delete entries
