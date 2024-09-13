use rocket::launch;

mod web_routes;

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", web_routes::routes())
}
