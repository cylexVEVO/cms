use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::DateTime;
use futures::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::IndexOptions,
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum ModelFieldType {
    Text,
    Number,
    DateTime,
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

    for (name, value) in input.fields {
        let model_field = model.fields.iter().find(|f| f.slug == name).unwrap();
        let mut value = value;

        // ensure field kind matches definition
        match value {
            EntryField::Text(_) => match model_field.kind {
                ModelFieldType::Text => {}
                _ => panic!("invalid field value"),
            },
            EntryField::Number(_) => match model_field.kind {
                ModelFieldType::Number => {}
                _ => panic!("invalid field value"),
            },
            EntryField::DateTime(date) => match model_field.kind {
                ModelFieldType::DateTime => {
                    // ensure date is valid
                    match DateTime::parse_from_rfc3339(&date) {
                        Ok(date) => value = EntryField::DateTime(date.to_rfc3339()),
                        Err(_) => panic!("invalid field value"),
                    }
                }
                _ => panic!("invalid field value"),
            },
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
    id: String,
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

    let filter = match query {
        Some(query) => {
            doc! {
                "_id": ObjectId::parse_str(&query.id).unwrap()
            }
        }
        None => {
            doc! {
                "model_id": model._id
            }
        }
    };

    let coll = db.collection::<Entry>("entries");
    let entries = coll
        .find(filter, None)
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();

    Json(entries)
}

// TODO: update entries
// TODO: delete entries
