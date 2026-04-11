mod app;
mod grpc_client;
mod network;
mod ui;

use anyhow::Result;
use app::{App, SortCol, Tab};
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
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut app = App::new().await?;
    let res = run_app(&mut term, &mut app).await;

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;

    if let Err(e) = res {
        eprintln!("Error: {e}");
    }
    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
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

            // ── Action menu mode ──────────────────────────────────────────
            if app.action_menu {
                match key.code {
                    KeyCode::Char('k') | KeyCode::Char('K') => app.kill_selected(),
                    KeyCode::Char('h') | KeyCode::Char('H') => app.hash_selected(),
                    KeyCode::Char('c') | KeyCode::Char('C') => app.copy_path_selected(),
                    KeyCode::Esc => {
                        app.action_menu = false;
                    }
                    _ => {}
                }
                continue;
            }
            // ── Action result dismiss ─────────────────────────────────────
            if app.action_result.is_some() {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ')) {
                    app.action_result = None;
                }
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
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.prev(),

                // Tab switching
                KeyCode::Tab | KeyCode::Right => app.switch_tab(app.tab.next()),
                KeyCode::BackTab | KeyCode::Left => app.switch_tab(app.tab.prev()),
                KeyCode::Char('1') => app.switch_tab(Tab::Processes),
                KeyCode::Char('2') => app.switch_tab(Tab::Persistence),
                KeyCode::Char('3') => app.switch_tab(Tab::Network),
                KeyCode::Char('4') => app.switch_tab(Tab::Connections),
                KeyCode::Char('5') => app.switch_tab(Tab::Alerts),

                // Detail panel toggle
                KeyCode::Enter => {
                    if app.tab == Tab::Processes {
                        app.detail_open = !app.detail_open;
                    }
                }

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

                // Action menu (Processes tab only)
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    if app.tab == Tab::Processes && app.selected_process().is_some() {
                        app.action_menu = true;
                    }
                }

                // Baseline toggle (Processes tab only)
                KeyCode::Char('w') | KeyCode::Char('W') => {
                    if app.tab == Tab::Processes {
                        app.toggle_baseline();
                    }
                }

                // Sort columns (Processes tab only)
                KeyCode::Char('F') | KeyCode::Char('f') => {
                    if app.tab == Tab::Processes {
                        app.toggle_sort(SortCol::Risk);
                    }
                }
                KeyCode::Char('P') => {
                    if app.tab == Tab::Processes {
                        app.toggle_sort(SortCol::Pid);
                    }
                }
                KeyCode::Char('N') => {
                    if app.tab == Tab::Processes {
                        app.toggle_sort(SortCol::Name);
                    }
                }
                KeyCode::Char('X') => {
                    if app.tab == Tab::Processes {
                        app.toggle_sort(SortCol::Path);
                    }
                }

                // Tree mode toggle (Processes tab only)
                KeyCode::Char('t') | KeyCode::Char('T') => {
                    if app.tab == Tab::Processes {
                        app.tree_mode = !app.tree_mode;
                        app.selected = 0;
                        app.proc_state.select(Some(0));
                    }
                }

                KeyCode::Char('l') | KeyCode::Char('L') => {
                    if app.tab == Tab::Connections {
                        app.hide_loopback = !app.hide_loopback;
                        app.selected = 0;
                        app.conn_state.select(Some(0));
                    }
                }

                _ => {}
            }
        }
    }
    Ok(())
}
