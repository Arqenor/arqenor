mod app;
mod network;
mod ui;

use anyhow::Result;
use app::{App, Tab};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut app = App::new().await?;
    let res     = run_app(&mut term, &mut app).await;

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    if let Err(e) = res {
        eprintln!("Error: {e}");
    }
    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    term:  &mut Terminal<B>,
    app:   &mut App,
) -> Result<()> {
    loop {
        term.draw(|f| ui::draw(f, app))?;

        app.tick(); // poll network scan results

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            // ── Filter mode ───────────────────────────────────────────────
            if app.filter_mode {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => {
                        app.filter_mode = false;
                    }
                    KeyCode::Backspace => {
                        app.filter.pop();
                        app.selected = 0;
                    }
                    KeyCode::Char(c) => {
                        app.filter.push(c);
                        app.selected = 0;
                    }
                    _ => {}
                }
                continue;
            }

            // ── Normal mode ───────────────────────────────────────────────
            match key.code {
                // Quit
                KeyCode::Char('q') | KeyCode::Char('Q') => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,

                // Navigation
                KeyCode::Down  | KeyCode::Char('j') => app.next(),
                KeyCode::Up    | KeyCode::Char('k') => app.prev(),

                // Tab switching
                KeyCode::Tab | KeyCode::Right => app.switch_tab(app.tab.next()),
                KeyCode::BackTab | KeyCode::Left => app.switch_tab(app.tab.prev()),
                KeyCode::Char('1') => app.switch_tab(Tab::Processes),
                KeyCode::Char('2') => app.switch_tab(Tab::Persistence),
                KeyCode::Char('3') => app.switch_tab(Tab::Network),

                // Filter
                KeyCode::Char('/') => {
                    app.filter_mode = true;
                    app.filter.clear();
                }
                KeyCode::Esc => {
                    app.filter.clear();
                    app.selected = 0;
                }

                // Refresh host data
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    app.refresh().await?;
                }

                // Network scan
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    app.switch_tab(app::Tab::Network);
                    app.net.start_scan();
                }

                _ => {}
            }
        }
    }
    Ok(())
}
