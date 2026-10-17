use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use rowt_monitor::{app::{Action, App}, input, model::{Lane, Snapshot, Window}, source::{FixtureSource, Source}, ui};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

#[test]
fn subscription_completion_shows_whether_the_pool_changed() {
    struct Completed(&'static str);
    impl Source for Completed {
        fn poll(&mut self, window: Window, lane: Option<Lane>) -> Snapshot { FixtureSource::still().poll(window, lane) }
        fn drain_ctl(&self) -> Vec<rowt_monitor::source::CtlOutcome> {
            vec![rowt_monitor::source::CtlOutcome::Ok(self.0.into())]
        }
    }
    for message in ["subscriptions unchanged", "subscriptions updated: +1 added, -0 removed, 1 changed"] {
        let mut app = App::new(Box::new(Completed(message)));
        app.on_frame();
        assert_eq!(app.toast.as_ref().unwrap().0, message);
    }
}

struct Updating { calls: Arc<AtomicUsize> }
impl Source for Updating {
    fn poll(&mut self, window: Window, lane: Option<Lane>) -> Snapshot { FixtureSource::still().poll(window, lane) }
    fn update_subscriptions(&self) -> Result<(), &'static str> { self.calls.fetch_add(1, Ordering::SeqCst); Ok(()) }
    fn restart_in_flight(&self) -> bool { self.calls.load(Ordering::SeqCst) > 0 }
}

#[test]
fn uppercase_r_updates_subscriptions_and_repeated_requests_are_ignored() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut app = App::new(Box::new(Updating { calls: calls.clone() }));
    assert!(matches!(input::key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE), &app), Some(Action::ForceProbe)));
    let action = input::key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT), &app).unwrap();
    app.update(action);
    assert_eq!(app.toast.as_ref().unwrap().0, "updating subscriptions…");
    app.update(Action::UpdateSubscriptions);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(app.toast.as_ref().unwrap().0.contains("in progress"));
}

#[test]
fn update_key_is_text_in_search_and_inert_in_help() {
    let mut app = App::new(Box::new(FixtureSource::still()));
    app.update(Action::SearchOpen);
    assert!(matches!(input::key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT), &app), Some(Action::SearchInput('R'))));
    app.update(Action::SearchCancel);
    app.help = true;
    assert!(input::key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT), &app).is_none());
}

#[test]
fn subscription_hint_follows_reprobe_in_footer_and_help() {
    let mut app = App::new(Box::new(FixtureSource::still()));
    for width in [40, 96, 150, 212] {
        let mut term = Terminal::new(TestBackend::new(width, 40)).unwrap();
        term.draw(|f| { let area = f.area(); ui::draw_footer(f.buffer_mut(), area, &app); }).unwrap();
        let text: String = term.backend().buffer().content.iter().map(|c| c.symbol()).collect();
        assert!(text.find("r reprobe").unwrap() < text.find("R subs").unwrap(), "{text}");
        assert!(text.contains("?"));
    }
    app.help = true;
    let mut term = Terminal::new(TestBackend::new(150, 40)).unwrap();
    term.draw(|f| { let area = f.area(); ui::draw(f.buffer_mut(), area, &app, false); }).unwrap();
    let text: String = term.backend().buffer().content.iter().map(|c| c.symbol()).collect();
    assert!(text.find("re-probe servers now").unwrap() < text.find("update subscriptions now").unwrap());
}
