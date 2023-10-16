use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::DateTime;
use futures::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, Document},
    options::{FindOptions, IndexOptions},
    Client, Database, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

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
    Enum(String),
}

#[derive(Deserialize, Debug)]
struct CreateModel {
    name: String,
    slug: String,
    fields: Vec<ModelField>,
}

async fn create_model(State(db): State<Database>, Json(input): Json<CreateModel>) -> Json<Model> {
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

    Json(model)
}

async fn list_models(State(db): State<Database>) -> Json<Vec<Model>> {
    let coll = db.collection::<Model>("models");
    Json(
        coll.find(doc! {}, None)
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap(),
    )
}

async fn list_model(State(db): State<Database>, Path(slug): Path<String>) -> Json<Model> {
    let coll = db.collection::<Model>("models");
    Json(
        coll.find_one(doc! { "slug": slug }, None)
            .await
            .unwrap()
            .unwrap(),
    )
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
    Json(input): Json<CreateEntry>,
) -> Json<Entry> {
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
                    Ok(date) => value = EntryField::DateTime(date.to_rfc3339()),
                    Err(_) => panic!("invalid field value"),
                }
            }
            (EntryField::Boolean(_), ModelFieldType::Boolean) => {}
            (EntryField::Enum(variant), ModelFieldType::Enum(enum_variants)) => {
                // ensure specified variant is part of enum
                if !enum_variants.contains(variant) {
                    panic!("invalid field value");
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

    Json(entry)
}

#[derive(Deserialize, Debug)]
struct ListEntries {
    id: Option<String>,
    select: Option<String>,
}

async fn list_entries(
    State(db): State<Database>,
    Path(slug): Path<String>,
    query: Option<Query<ListEntries>>,
) -> Json<Vec<Entry>> {
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

    Json(entries)
}

// TODO: update entries
// TODO: delete entries
