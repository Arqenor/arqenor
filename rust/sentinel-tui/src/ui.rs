use crate::{
    app::{App, RiskLevel, ScanState, SortCol, SortDir, Tab, TreeRow},
    network::{HostRisk, OsGuess},
};
use sentinel_core::models::connection::{ConnState, Proto};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, Tabs,
    },
    Frame,
};

// ─── Palette ───────────────────────────────────────────────────────────────────
const C_BG:       Color = Color::Reset;
const C_BORDER:   Color = Color::DarkGray;
const C_HEADER:   Color = Color::Cyan;
const C_SELECTED: Color = Color::Rgb(30, 50, 80);
const C_NORMAL:   Color = Color::White;
const C_DIM:      Color = Color::DarkGray;
const C_CRIT:     Color = Color::Rgb(255, 50, 50);
const C_HIGH:     Color = Color::Red;
const C_MED:      Color = Color::Yellow;
const C_LOW:      Color = Color::Green;
const C_INFO:     Color = Color::Cyan;

/// Returns (display_string, color) for a process exe path.
/// None paths are classified as [kernel] or [protected] so users understand why.
fn process_path_cell(pid: u32, name: &str, exe_path: Option<&str>, cmdline: Option<&str>) -> (&'static str, Color) {
    if exe_path.is_some() {
        return ("", Color::Reset); // caller handles the real path
    }
    let is_kernel = pid == 0
        || pid == 4 // NT Kernel & System on Windows
        || name == "System"
        || name == "Idle"
        || name == "Registry"
        || name == "Memory Compression"
        || name.starts_with('[') // Linux kernel threads: [kworker/0:1], [migration/0]…
        || cmdline.map(|c| c.trim().is_empty()).unwrap_or(true); // no cmdline → kernel thread
    if is_kernel {
        ("[kernel]", C_DIM)
    } else {
        ("[protected]", C_MED)
    }
}

fn annotate_addr(addr: &str) -> String {
    let port: u16 = addr.rsplit(':').next()
        .and_then(|p| p.trim_end_matches(']').parse().ok())
        .unwrap_or(0);
    let svc = port_service(port);
    if svc.is_empty() { addr.to_string() } else { format!("{}/{}", addr, svc) }
}

fn port_service(port: u16) -> &'static str {
    match port {
        21    => "ftp",
        22    => "ssh",
        23    => "telnet",
        25    => "smtp",
        53    => "dns",
        80    => "http",
        110   => "pop3",
        135   => "msrpc",
        139   => "netbios",
        443   => "https",
        445   => "smb",
        1433  => "mssql",
        3306  => "mysql",
        3389  => "rdp",
        5900  => "vnc",
        8080  => "http-alt",
        8443  => "https-alt",
        _     => "",
    }
}

fn risk_color(risk: &RiskLevel) -> Color {
    match risk {
        RiskLevel::Normal   => C_DIM,
        RiskLevel::Low      => C_LOW,
        RiskLevel::Medium   => C_MED,
        RiskLevel::High     => C_HIGH,
        RiskLevel::Critical => C_CRIT,
    }
}

fn risk_bar(score: u8) -> String {
    let filled = (score.min(10) as usize).min(5);
    let empty  = 5 - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

// ─── Main draw ─────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.size();

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(3), // tabs
            Constraint::Min(0),    // body
            Constraint::Length(1), // status bar
        ])
        .split(area);

    draw_header(f, app, root[0]);
    draw_tabs(f, app, root[1]);
    draw_body(f, app, root[2]);
    draw_statusbar(f, app, root[3]);
    if app.filter_mode { draw_filter_popup(f, app, area); }
    if app.action_menu || app.action_result.is_some() { draw_action_menu(f, app, area); }
}

// ─── Header ────────────────────────────────────────────────────────────────────

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let (crit, high, med, low) = app.counts();
    let now = chrono::Local::now().format("%H:%M:%S").to_string();
    let platform = std::env::consts::OS.to_uppercase();

    let title = Line::from(vec![
        Span::styled("  ▓▓ SENTINEL  ", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Span::styled("│ ", Style::default().fg(C_BORDER)),
        Span::styled(platform, Style::default().fg(C_DIM)),
        Span::styled("  │  ", Style::default().fg(C_BORDER)),
        Span::styled(format!("{} procs", app.processes.len()), Style::default().fg(C_NORMAL)),
        Span::styled("  │  ", Style::default().fg(C_BORDER)),
        if crit > 0 {
            Span::styled(format!("CRIT:{crit}"), Style::default().fg(C_CRIT).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("CRIT:0", Style::default().fg(C_DIM))
        },
        Span::raw("  "),
        if high > 0 {
            Span::styled(format!("HIGH:{high}"), Style::default().fg(C_HIGH).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("HIGH:0", Style::default().fg(C_DIM))
        },
        Span::raw("  "),
        if med > 0 {
            Span::styled(format!("MED:{med}"), Style::default().fg(C_MED))
        } else {
            Span::styled("MED:0", Style::default().fg(C_DIM))
        },
        Span::raw("  "),
        if low > 0 {
            Span::styled(format!("LOW:{low}"), Style::default().fg(C_LOW))
        } else {
            Span::styled("LOW:0", Style::default().fg(C_DIM))
        },
        Span::styled("  │  ", Style::default().fg(C_BORDER)),
        // VPN indicator
        if let Some(ref vpn) = app.vpn {
            Span::styled(
                format!("🔒 {}  {}  ", vpn.name, vpn.tunnel),
                Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled("  No VPN  ", Style::default().fg(C_DIM))
        },
        Span::styled(format!("│  {now}  "), Style::default().fg(C_DIM)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_HEADER))
        .style(Style::default().bg(C_BG));

    let paragraph = Paragraph::new(title).block(block);
    f.render_widget(paragraph, area);
}

// ─── Tabs ──────────────────────────────────────────────────────────────────────

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let net_label = match &app.net.scan_state {
        ScanState::Scanning { .. } => format!(" Network (scanning…) "),
        _ => format!(" Network ({}) ", app.net.hosts.len()),
    };
    let titles = vec![
        format!(" Processes ({}) ", app.processes.len()),
        format!(" Persistence ({}) ", app.persistence.len()),
        net_label,
        format!(" Connections ({}) ", app.connections.len()),
        format!(" Alerts ({}) ", app.alerts.len()),
    ];
    let selected = match app.tab {
        Tab::Processes   => 0,
        Tab::Persistence => 1,
        Tab::Network     => 2,
        Tab::Connections => 3,
        Tab::Alerts      => 4,
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(C_BORDER)),
        )
        .style(Style::default().fg(C_DIM))
        .highlight_style(
            Style::default()
                .fg(C_HEADER)
                .add_modifier(Modifier::BOLD),
        )
        .divider(Span::styled("│", Style::default().fg(C_BORDER)));

    f.render_widget(tabs, area);
}

// ─── Body dispatch ─────────────────────────────────────────────────────────────

fn draw_body(f: &mut Frame, app: &mut App, area: Rect) {
    match app.tab {
        Tab::Processes   => draw_processes(f, app, area),
        Tab::Persistence => draw_persistence(f, app, area),
        Tab::Network     => draw_network(f, app, area),
        Tab::Connections => draw_connections(f, app, area),
        Tab::Alerts      => draw_alerts(f, app, area),
    }
}

// ─── Processes tab ─────────────────────────────────────────────────────────────

fn draw_processes(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(0)])
        .split(area);

    draw_sidebar(f, app, cols[0]);

    let show_detail = app.detail_open && app.selected_process().is_some();
    if show_detail {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(12)])
            .split(cols[1]);
        draw_process_table(f, app, rows[0]);
        draw_process_detail(f, app, rows[1]);
    } else {
        draw_process_table(f, app, cols[1]);
    }
}

fn draw_process_detail(f: &mut Frame, app: &App, area: Rect) {
    let proc = match app.selected_process() {
        Some(p) => p,
        None    => return,
    };
    let info = &proc.info;

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  Exe    ", Style::default().fg(C_HEADER)),
            Span::styled(
                info.exe_path.as_deref().unwrap_or("—"),
                Style::default().fg(C_NORMAL),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Cmdline", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {}", info.cmdline.as_deref().unwrap_or("—")),
                Style::default().fg(C_NORMAL),
            ),
        ]),
        Line::from(vec![
            Span::styled("  PID    ", Style::default().fg(C_HEADER)),
            Span::styled(
                format!(" {}   ", info.pid),
                Style::default().fg(C_NORMAL),
            ),
            Span::styled("PPID ", Style::default().fg(C_HEADER)),
            Span::styled(
                info.ppid.to_string(),
                Style::default().fg(C_NORMAL),
            ),
        ]),
    ];

    if let Some(ref user) = info.user {
        lines.push(Line::from(vec![
            Span::styled("  User   ", Style::default().fg(C_HEADER)),
            Span::styled(format!(" {}", user), Style::default().fg(C_NORMAL)),
        ]));
    }
    if let Some(ref started) = info.started_at {
        lines.push(Line::from(vec![
            Span::styled("  Started", Style::default().fg(C_HEADER)),
            Span::styled(format!(" {}", started), Style::default().fg(C_NORMAL)),
        ]));
    }
    if let Some(ref hash) = info.sha256 {
        lines.push(Line::from(vec![
            Span::styled("  SHA256 ", Style::default().fg(C_HEADER)),
            Span::styled(format!(" {}", hash), Style::default().fg(C_NORMAL)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "  Enter to close",
            Style::default().fg(C_DIM).add_modifier(Modifier::DIM),
        ),
    ]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Process Detail ", Style::default().fg(C_HEADER)));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn draw_sidebar(f: &mut Frame, app: &App, area: Rect) {
    let (crit, high, med, low) = app.counts();
    let normal = app.processes.len().saturating_sub(crit + high + med + low);

    let lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  OVERVIEW", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>4} ", crit), Style::default().fg(C_CRIT).add_modifier(Modifier::BOLD)),
            Span::styled("CRITICAL", Style::default().fg(C_CRIT)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>4} ", high), Style::default().fg(C_HIGH).add_modifier(Modifier::BOLD)),
            Span::styled("HIGH    ", Style::default().fg(C_HIGH)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>4} ", med), Style::default().fg(C_MED)),
            Span::styled("MEDIUM  ", Style::default().fg(C_MED)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>4} ", low), Style::default().fg(C_LOW)),
            Span::styled("LOW     ", Style::default().fg(C_LOW)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>4} ", normal), Style::default().fg(C_DIM)),
            Span::styled("NORMAL  ", Style::default().fg(C_DIM)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ─────────────", Style::default().fg(C_BORDER)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  PERSIST ", Style::default().fg(C_INFO).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("{} entries", app.persistence.len()),
                Style::default().fg(C_DIM),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ─────────────", Style::default().fg(C_BORDER)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  FILTER ", Style::default().fg(C_INFO).add_modifier(Modifier::BOLD)),
        ]),
        if app.filter.is_empty() {
            Line::from(vec![
                Span::styled("  Press /", Style::default().fg(C_DIM)),
            ])
        } else {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(&app.filter, Style::default().fg(Color::White)),
            ])
        },
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn draw_process_table(f: &mut Frame, app: &mut App, area: Rect) {
    if app.tree_mode {
        return draw_process_tree(f, app, area);
    }

    let rows_data = app.filtered_processes();

    // Build sort-indicator label: active column gets ▼/▲ in C_INFO, others use C_HEADER.
    let sort_indicator = match app.sort_dir {
        SortDir::Desc => "▼",
        SortDir::Asc  => "▲",
    };
    let col_label = |col: SortCol, base: &str| -> (String, Color) {
        if app.sort_col == col {
            (format!("{} {}", base.trim_end(), sort_indicator), C_INFO)
        } else {
            (base.to_string(), C_HEADER)
        }
    };

    let (pid_label,  pid_color)  = col_label(SortCol::Pid,  "  PID");
    let (risk_label, risk_color_h) = col_label(SortCol::Risk, "RISK     ");
    let (name_label, name_color) = col_label(SortCol::Name, "NAME                         ");
    let (path_label, path_color_h) = col_label(SortCol::Path, "PATH");

    let header_cells = vec![
        Cell::from(pid_label) .style(Style::default().fg(pid_color) .add_modifier(Modifier::BOLD)),
        Cell::from("PPID")    .style(Style::default().fg(C_HEADER)  .add_modifier(Modifier::BOLD)),
        Cell::from(risk_label).style(Style::default().fg(risk_color_h).add_modifier(Modifier::BOLD)),
        Cell::from("SCORE")   .style(Style::default().fg(C_HEADER)  .add_modifier(Modifier::BOLD)),
        Cell::from(name_label).style(Style::default().fg(name_color).add_modifier(Modifier::BOLD)),
        Cell::from(path_label).style(Style::default().fg(path_color_h).add_modifier(Modifier::BOLD)),
    ];
    let header = Row::new(header_cells)
        .height(1)
        .bottom_margin(1)
        .style(Style::default().bg(Color::Rgb(15, 25, 40)));

    let rows: Vec<Row> = rows_data
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let color  = risk_color(&r.risk);
            let is_sel = i == app.selected;
            let bg     = if is_sel { C_SELECTED } else { C_BG };

            let is_new      = app.new_pids.contains(&r.info.pid);
            let is_baseline = app.baseline.contains(&r.info.pid);

            let name_fg = if is_sel {
                Color::White
            } else if is_new {
                Color::Rgb(100, 255, 100)  // bright green for new processes
            } else if is_baseline {
                Color::Rgb(100, 200, 100)  // softer green for known-good
            } else {
                C_NORMAL
            };

            let name_prefix = if is_new {
                "⬤ "
            } else if is_baseline {
                "✓ "
            } else {
                ""
            };

            let bar = risk_bar(r.score);

            let (path_text, path_color) = match r.info.exe_path.as_deref() {
                Some(p) => {
                    let truncated = if p.len() > 45 {
                        format!("…{}", &p[p.len().saturating_sub(44)..])
                    } else {
                        p.to_string()
                    };
                    (truncated, C_DIM)
                }
                None => {
                    let (label, col) = process_path_cell(
                        r.info.pid,
                        &r.info.name,
                        None,
                        r.info.cmdline.as_deref(),
                    );
                    (label.to_string(), col)
                }
            };

            Row::new(vec![
                Cell::from(format!("  {}", r.info.pid))
                    .style(Style::default().fg(C_DIM).bg(bg)),
                Cell::from(r.info.ppid.to_string())
                    .style(Style::default().fg(C_DIM).bg(bg)),
                Cell::from(r.risk.label())
                    .style(Style::default().fg(color).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(bar)
                    .style(Style::default().fg(color).bg(bg)),
                Cell::from(format!("{}{}", name_prefix, r.info.name))
                    .style(Style::default().fg(name_fg).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(path_text)
                    .style(Style::default().fg(path_color).bg(bg)),
            ])
            .height(1)
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" {} results ", rows_data.len()),
            Style::default().fg(C_DIM),
        ));

    let table = Table::new(
        rows,
        &[
            Constraint::Length(8),  // PID
            Constraint::Length(7),  // PPID
            Constraint::Length(9),  // RISK
            Constraint::Length(8),  // SCORE bar
            Constraint::Length(30), // NAME
            Constraint::Min(20),    // PATH
        ],
    )
    .header(header)
    .block(block);

    f.render_stateful_widget(table, area, &mut app.proc_state);
}

// ─── Process tree view ─────────────────────────────────────────────────────────

fn draw_process_tree(f: &mut Frame, app: &mut App, area: Rect) {
    let tree_data: Vec<TreeRow<'_>> = app.tree_rows();
    let total = tree_data.len();

    let header_cells = vec![
        Cell::from("  PID")  .style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("PPID")   .style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("RISK     ").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("SCORE")  .style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("NAME                         ").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        Cell::from("PATH")   .style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
    ];
    let header = Row::new(header_cells)
        .height(1)
        .bottom_margin(1)
        .style(Style::default().bg(Color::Rgb(15, 25, 40)));

    let rows: Vec<Row> = tree_data
        .iter()
        .enumerate()
        .map(|(i, tr)| {
            let r      = tr.row;
            let color  = risk_color(&r.risk);
            let is_sel = i == app.selected;
            let bg     = if is_sel { C_SELECTED } else { C_BG };

            let is_new      = app.new_pids.contains(&r.info.pid);
            let is_baseline = app.baseline.contains(&r.info.pid);

            let name_fg = if is_sel {
                Color::White
            } else if is_new {
                Color::Rgb(100, 255, 100)
            } else if is_baseline {
                Color::Rgb(100, 200, 100)
            } else {
                C_NORMAL
            };

            let status_prefix = if is_new {
                "⬤ "
            } else if is_baseline {
                "✓ "
            } else {
                ""
            };

            // Build tree prefix
            let tree_prefix = if tr.depth == 0 {
                String::new()
            } else {
                format!(
                    "{}{}",
                    "  ".repeat(tr.depth - 1),
                    if tr.is_last { "└─ " } else { "├─ " }
                )
            };

            let full_name = format!("{}{}{}", tree_prefix, status_prefix, r.info.name);
            // Truncate to 28 chars to stay within the 30-char column
            let name_display = if full_name.chars().count() > 28 {
                full_name.chars().take(28).collect::<String>()
            } else {
                full_name
            };

            let bar = risk_bar(r.score);

            let (path_text, path_color) = match r.info.exe_path.as_deref() {
                Some(p) => {
                    let truncated = if p.len() > 45 {
                        format!("…{}", &p[p.len().saturating_sub(44)..])
                    } else {
                        p.to_string()
                    };
                    (truncated, C_DIM)
                }
                None => {
                    let (label, col) = process_path_cell(
                        r.info.pid,
                        &r.info.name,
                        None,
                        r.info.cmdline.as_deref(),
                    );
                    (label.to_string(), col)
                }
            };

            Row::new(vec![
                Cell::from(format!("  {}", r.info.pid))
                    .style(Style::default().fg(C_DIM).bg(bg)),
                Cell::from(r.info.ppid.to_string())
                    .style(Style::default().fg(C_DIM).bg(bg)),
                Cell::from(r.risk.label())
                    .style(Style::default().fg(color).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(bar)
                    .style(Style::default().fg(color).bg(bg)),
                Cell::from(name_display)
                    .style(Style::default().fg(name_fg).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(path_text)
                    .style(Style::default().fg(path_color).bg(bg)),
            ])
            .height(1)
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" {} processes (tree) ", total),
            Style::default().fg(C_DIM),
        ));

    let table = Table::new(
        rows,
        &[
            Constraint::Length(8),  // PID
            Constraint::Length(7),  // PPID
            Constraint::Length(9),  // RISK
            Constraint::Length(8),  // SCORE bar
            Constraint::Length(30), // NAME
            Constraint::Min(20),    // PATH
        ],
    )
    .header(header)
    .block(block);

    f.render_stateful_widget(table, area, &mut app.proc_state);
}

// ─── Persistence tab ───────────────────────────────────────────────────────────

fn draw_persistence(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["  KIND              ", "NAME                    ", "COMMAND", "LOCATION"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .height(1)
        .bottom_margin(1)
        .style(Style::default().bg(Color::Rgb(15, 25, 40)));

    let rows: Vec<Row> = app
        .persistence
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let is_sel = i == app.selected;
            let bg     = if is_sel { C_SELECTED } else { C_BG };
            let fg     = if is_sel { Color::White } else { C_NORMAL };
            Row::new(vec![
                Cell::from(format!("  {:?}", e.kind))
                    .style(Style::default().fg(C_INFO).bg(bg)),
                Cell::from(e.name.clone())
                    .style(Style::default().fg(fg).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(e.command.clone())
                    .style(Style::default().fg(fg).bg(bg)),
                Cell::from(e.location.clone())
                    .style(Style::default().fg(C_DIM).bg(bg)),
            ])
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Persistence Entries ", Style::default().fg(C_DIM)));

    let table = Table::new(
        rows,
        &[
            Constraint::Length(22),
            Constraint::Length(26),
            Constraint::Min(30),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(block);

    f.render_widget(table, area);
}

// ─── Network tab ───────────────────────────────────────────────────────────────

fn host_risk_color(r: &HostRisk) -> Color {
    match r {
        HostRisk::High   => C_HIGH,
        HostRisk::Medium => C_MED,
        HostRisk::Low    => C_LOW,
        HostRisk::Normal => C_DIM,
    }
}

fn draw_network(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(24), Constraint::Min(0)])
        .split(area);

    // ── Sidebar ──────────────────────────────────────────────────────────────
    let high   = app.net.hosts.iter().filter(|h| h.risk == HostRisk::High).count();
    let medium = app.net.hosts.iter().filter(|h| h.risk == HostRisk::Medium).count();
    let low    = app.net.hosts.iter().filter(|h| h.risk == HostRisk::Low).count();
    let normal = app.net.hosts.len().saturating_sub(high + medium + low);

    let local_str = app.net.subnet_label();

    let scan_hint = match &app.net.scan_state {
        ScanState::Idle        => "  auto-scan…   ",
        ScanState::Scanning{..}=> "  ◌ scanning…  ",
        ScanState::Done        => "  S  rescan now",
    };

    let sidebar_lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(vec![Span::styled("  NETWORK", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD))]),
        Line::from(""),
        Line::from(vec![Span::styled("  Subnet", Style::default().fg(C_DIM))]),
        Line::from(vec![Span::styled(format!("  {}", local_str), Style::default().fg(C_NORMAL))]),
        Line::from(""),
        Line::from(vec![Span::styled("  ─────────────────", Style::default().fg(C_BORDER))]),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>3} ", high), Style::default().fg(C_HIGH).add_modifier(Modifier::BOLD)),
            Span::styled("HIGH  ", Style::default().fg(C_HIGH)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>3} ", medium), Style::default().fg(C_MED)),
            Span::styled("MED   ", Style::default().fg(C_MED)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>3} ", low), Style::default().fg(C_LOW)),
            Span::styled("LOW   ", Style::default().fg(C_LOW)),
        ]),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>3} ", normal), Style::default().fg(C_DIM)),
            Span::styled("NORMAL", Style::default().fg(C_DIM)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("  ─────────────────", Style::default().fg(C_BORDER))]),
        Line::from(""),
        Line::from(vec![Span::styled(scan_hint, Style::default().fg(C_INFO).add_modifier(Modifier::BOLD))]),
    ];

    let sidebar = Paragraph::new(sidebar_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(sidebar, cols[0]);

    // ── Host table ───────────────────────────────────────────────────────────
    let header_cells = ["  IP               ", "RISK    ", "OS       ", "OPEN PORTS                    "]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .height(1)
        .bottom_margin(1)
        .style(Style::default().bg(Color::Rgb(15, 25, 40)));

    let rows: Vec<Row> = if app.net.hosts.is_empty() {
        let hint = match &app.net.scan_state {
            ScanState::Idle         => "  No scan yet — press S to discover hosts on your network",
            ScanState::Scanning{..} => "  Scanning… results appear as hosts respond",
            ScanState::Done         => "  No hosts found",
        };
        vec![Row::new(vec![
            Cell::from(hint).style(Style::default().fg(C_DIM)),
            Cell::from(""), Cell::from(""), Cell::from(""),
        ])]
    } else {
        app.net.hosts.iter().enumerate().map(|(i, h)| {
            let is_sel = i == app.selected;
            let bg     = if is_sel { C_SELECTED } else { C_BG };
            let color  = host_risk_color(&h.risk);

            let ports_str = if h.ports.is_empty() {
                "—".to_string()
            } else {
                h.ports.iter().map(|p| {
                    let svc = port_service(*p);
                    if svc.is_empty() { p.to_string() } else { format!("{}/{}", p, svc) }
                }).collect::<Vec<_>>().join("  ")
            };

            Row::new(vec![
                Cell::from(format!("  {}", h.ip))
                    .style(Style::default().fg(if is_sel { Color::White } else { C_NORMAL }).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(h.risk.label())
                    .style(Style::default().fg(color).bg(bg)),
                Cell::from(h.os.label())
                    .style(Style::default().fg(match h.os {
                        OsGuess::Windows => Color::Rgb(100, 180, 255),
                        OsGuess::Linux   => Color::Rgb(255, 165, 0),
                        OsGuess::Router  => Color::Rgb(100, 220, 100),
                        OsGuess::Unknown => C_DIM,
                    }).bg(bg)),
                Cell::from(ports_str)
                    .style(Style::default().fg(C_DIM).bg(bg)),
            ])
        }).collect()
    };

    let status_title = app.net.status_line();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(format!(" {} ", status_title), Style::default().fg(C_DIM)));

    let table = Table::new(
        rows,
        &[
            Constraint::Length(20),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(block);

    f.render_widget(table, cols[1]);
}

// ─── Connections tab ───────────────────────────────────────────────────────────

fn conn_risk_color(c: &sentinel_core::models::connection::ConnectionInfo) -> Option<Color> {
    use sentinel_core::models::connection::{ConnState, ListenRisk, listen_risk_severity, local_port};
    let port = local_port(c).unwrap_or(0);

    if c.state == ConnState::Listen {
        // Use firewall-aware scoring for lateral-movement and risky ports.
        if let Some(risk) = listen_risk_severity(c) {
            return match risk {
                ListenRisk::Critical => Some(C_CRIT),
                ListenRisk::Low      => Some(C_LOW),
                ListenRisk::None     => None,
            };
        }
        // Ports that are high-risk but not in the lateral-movement set and
        // don't go through firewall-aware scoring.
        if matches!(port, 1433 | 3306 | 5432) {
            return Some(C_HIGH);
        }
    }
    if c.state == ConnState::Established {
        let remote = c.remote_addr.as_deref().unwrap_or("");
        if is_external_ip(remote) && matches!(port, 80 | 21 | 23 | 4444 | 1337) {
            return Some(C_MED);
        }
    }
    None
}

/// Returns a short tag for the firewall column: "[FW]" when blocked, empty otherwise.
fn firewall_tag(c: &sentinel_core::models::connection::ConnectionInfo) -> &'static str {
    match c.firewall_blocked {
        Some(true) => "[FW]",
        _ => "",
    }
}

fn is_external_ip(addr: &str) -> bool {
    let ip = addr.rsplit(':').nth(1).unwrap_or(addr);
    !ip.starts_with("127.")
        && !ip.starts_with("192.168.")
        && !ip.starts_with("10.")
        && !ip.starts_with('[')       // IPv6 loopback / link-local
        && !ip.starts_with("169.254.")
        && !{
            // 172.16.0.0/12
            if let Some(b) = ip.strip_prefix("172.") {
                b.split('.').next()
                    .and_then(|n| n.parse::<u8>().ok())
                    .map(|n| (16..=31).contains(&n))
                    .unwrap_or(false)
            } else { false }
        }
}

fn draw_connections_sidebar(f: &mut Frame, app: &App, area: Rect) {
    use sentinel_core::models::connection::{ConnState as CS, Proto as P};

    let listen      = app.connections.iter().filter(|c| c.state == CS::Listen).count();
    let established = app.connections.iter().filter(|c| c.state == CS::Established).count();
    let other       = app.connections.len() - listen - established;
    let external    = app.connections.iter().filter(|c| {
        c.state == CS::Established
            && c.remote_addr.as_deref().map(is_external_ip).unwrap_or(false)
    }).count();
    let loopback    = app.connections.iter().filter(|c| {
        c.local_addr.starts_with("127.") || c.local_addr.starts_with("[::1]")
            || c.remote_addr.as_deref().map(|r| r.starts_with("127.") || r.starts_with("[::1]")).unwrap_or(false)
    }).count();
    let udp         = app.connections.iter().filter(|c| c.proto == P::Udp).count();
    let fw_blocked  = app.connections.iter().filter(|c| c.firewall_blocked == Some(true)).count();

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled("  CONNECTIONS", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", listen), Style::default().fg(C_INFO)),
            Span::styled("LISTEN", Style::default().fg(C_DIM)),
        ]),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", established), Style::default().fg(C_LOW)),
            Span::styled("ESTABLISHED", Style::default().fg(C_DIM)),
        ]),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", other), Style::default().fg(C_DIM)),
            Span::styled("OTHER", Style::default().fg(C_DIM)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  ─────────────", Style::default().fg(C_BORDER))),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", external),
                Style::default().fg(if external > 0 { C_MED } else { C_DIM })),
            Span::styled("EXTERNAL", Style::default().fg(C_DIM)),
        ]),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", loopback), Style::default().fg(C_DIM)),
            Span::styled("LOOPBACK", Style::default().fg(C_DIM)),
        ]),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", udp), Style::default().fg(C_MED)),
            Span::styled("UDP", Style::default().fg(C_DIM)),
        ]),
        Line::from(vec![
            Span::styled(format!("  {:>4} ", fw_blocked),
                Style::default().fg(if fw_blocked > 0 { C_LOW } else { C_DIM })),
            Span::styled("FW BLOCK", Style::default().fg(C_DIM)),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_connections(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(0)])
        .split(area);

    draw_connections_sidebar(f, app, cols[0]);

    let table_area = cols[1];

    if app.connections.is_empty() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER));
        let msg = Paragraph::new(Line::from(Span::styled(
            "No connections — press R to refresh",
            Style::default().fg(C_DIM),
        )))
        .block(block)
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(msg, table_area);
        return;
    }

    fn state_ord(s: &ConnState) -> u8 {
        match s {
            ConnState::Listen      => 0,
            ConnState::Established => 1,
            _                      => 2,
        }
    }

    let mut sorted: Vec<&sentinel_core::models::connection::ConnectionInfo> =
        app.filtered_connections();
    sorted.sort_by(|a, b| {
        state_ord(&a.state).cmp(&state_ord(&b.state)).then(a.pid.cmp(&b.pid))
    });

    let name_for_pid = |pid: u32| -> &str {
        app.processes.iter()
            .find(|r| r.info.pid == pid)
            .map(|r| r.info.name.as_str())
            .unwrap_or("—")
    };

    let title_count = format!(" {} connections ", sorted.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(title_count, Style::default().fg(C_DIM)));

    let header_cells = ["PROTO ", "PID    ", "PROCESS NAME          ", "LOCAL                  ", "REMOTE                 ", "STATE         ", "FW  "]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .height(1)
        .bottom_margin(1)
        .style(Style::default().bg(Color::Rgb(15, 25, 40)));

    let rows: Vec<Row> = sorted.iter().enumerate().map(|(i, c)| {
        let is_sel    = i == app.selected;
        let risk      = conn_risk_color(c);
        let crit_bg   = risk == Some(C_CRIT) && !is_sel;
        let bg = if is_sel { C_SELECTED }
                 else if crit_bg { Color::Rgb(40, 0, 0) }
                 else { C_BG };

        let proto_color = match c.proto {
            Proto::Tcp => C_NORMAL,
            Proto::Udp => C_MED,
        };
        let base_state_color = match c.state {
            ConnState::Established => C_LOW,
            ConnState::Listen      => C_INFO,
            ConnState::TimeWait |
            ConnState::CloseWait   => C_MED,
            _                      => C_DIM,
        };
        let state_color = risk.unwrap_or(base_state_color);

        let local_str  = annotate_addr(&c.local_addr);
        let remote_str = match c.state {
            ConnState::Listen => "—".to_string(),
            _ => c.remote_addr.as_deref()
                    .map(annotate_addr)
                    .unwrap_or_else(|| "—".to_string()),
        };

        // Dim remote if loopback
        let remote_color = if remote_str.starts_with("127.") || remote_str.starts_with("[::1]") {
            C_DIM
        } else {
            match c.state {
                ConnState::Established => C_NORMAL,
                _ => C_DIM,
            }
        };

        let fw = firewall_tag(c);
        let fw_color = if fw.is_empty() { C_DIM } else { C_LOW };

        Row::new(vec![
            Cell::from(c.proto.to_string()).style(Style::default().fg(proto_color).bg(bg)),
            Cell::from(c.pid.to_string()).style(Style::default().fg(C_DIM).bg(bg)),
            Cell::from(name_for_pid(c.pid))
                .style(Style::default().fg(if is_sel { Color::White } else { C_NORMAL })
                    .add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
            Cell::from(local_str).style(Style::default().fg(C_DIM).bg(bg)),
            Cell::from(remote_str).style(Style::default().fg(remote_color).bg(bg)),
            Cell::from(c.state.to_string()).style(Style::default().fg(state_color).bg(bg)),
            Cell::from(fw).style(Style::default().fg(fw_color).bg(bg)),
        ])
        .height(1)
    }).collect();

    let table = Table::new(
        rows,
        &[
            Constraint::Length(6),  // PROTO
            Constraint::Length(7),  // PID
            Constraint::Length(22), // PROCESS NAME
            Constraint::Length(23), // LOCAL
            Constraint::Length(23), // REMOTE
            Constraint::Length(14), // STATE
            Constraint::Length(5),  // FW
        ],
    )
    .header(header)
    .block(block);

    f.render_stateful_widget(table, table_area, &mut app.conn_state);
}

// ─── Status bar ────────────────────────────────────────────────────────────────

fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    let elapsed = app.last_refresh.elapsed().as_secs();
    let elapsed_str = if elapsed >= 60 {
        format!("{}m {}s ago", elapsed / 60, elapsed % 60)
    } else {
        format!("{}s ago", elapsed)
    };

    let mut spans: Vec<Span> = vec![
        Span::styled(" ↑↓",      Style::default().fg(C_HEADER)),
        Span::styled(" Navigate", Style::default().fg(C_DIM)),
        Span::styled("  Tab",     Style::default().fg(C_HEADER)),
        Span::styled(" Switch",   Style::default().fg(C_DIM)),
        Span::styled("  R",       Style::default().fg(C_HEADER)),
        Span::styled(" Refresh",  Style::default().fg(C_DIM)),
        Span::styled("  Q",       Style::default().fg(C_HIGH)),
        Span::styled(" Quit",     Style::default().fg(C_DIM)),
    ];

    match app.tab {
        Tab::Processes => {
            spans.extend([
                Span::styled("  Enter",    Style::default().fg(C_INFO)),
                Span::styled(" Detail",    Style::default().fg(C_DIM)),
                Span::styled("  /",        Style::default().fg(C_INFO)),
                Span::styled(" Filter",    Style::default().fg(C_DIM)),
                Span::styled("  F",        Style::default().fg(C_INFO)),
                Span::styled(" SortRisk",  Style::default().fg(C_DIM)),
                Span::styled("  P",        Style::default().fg(C_INFO)),
                Span::styled(" SortPID",   Style::default().fg(C_DIM)),
                Span::styled("  N",        Style::default().fg(C_INFO)),
                Span::styled(" SortName",  Style::default().fg(C_DIM)),
                Span::styled("  X",        Style::default().fg(C_INFO)),
                Span::styled(" SortPath",  Style::default().fg(C_DIM)),
                Span::styled("  W",        Style::default().fg(C_INFO)),
                Span::styled(" Whitelist", Style::default().fg(C_DIM)),
                Span::styled("  A",        Style::default().fg(C_INFO)),
                Span::styled(" Actions",   Style::default().fg(C_DIM)),
                Span::styled("  T",        Style::default().fg(C_INFO)),
                Span::styled(if app.tree_mode { " Flat" } else { " Tree" }, Style::default().fg(C_DIM)),
            ]);
        }
        Tab::Network => {
            spans.extend([
                Span::styled("  S",        Style::default().fg(C_INFO)),
                Span::styled(" Scan",      Style::default().fg(C_DIM)),
            ]);
        }
        Tab::Persistence => {}
        Tab::Connections => {
            spans.extend([
                Span::styled("  R",        Style::default().fg(C_INFO)),
                Span::styled(" Refresh",   Style::default().fg(C_DIM)),
            ]);
        }
        Tab::Alerts => {}
    }

    spans.push(Span::styled(
        format!("  — {}", elapsed_str),
        Style::default().fg(C_DIM),
    ));

    if !app.filter.is_empty() {
        spans.extend([
            Span::styled("  │ filter: ", Style::default().fg(C_DIM)),
            Span::styled(&app.filter,    Style::default().fg(Color::Yellow)),
        ]);
    }

    let bar = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(Color::Rgb(10, 10, 15)));
    f.render_widget(bar, area);
}

// ─── Filter popup ──────────────────────────────────────────────────────────────

fn draw_filter_popup(f: &mut Frame, app: &App, area: Rect) {
    let popup_area = centered_rect(50, 3, area);

    f.render_widget(Clear, popup_area);

    let text = Line::from(vec![
        Span::styled(" 🔍 ", Style::default().fg(C_INFO)),
        Span::styled(&app.filter, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("█", Style::default().fg(C_INFO).add_modifier(Modifier::SLOW_BLINK)),
        Span::styled("  (Esc to cancel)", Style::default().fg(C_DIM)),
    ]);

    let popup = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(C_HEADER))
            .title(Span::styled(" Filter ", Style::default().fg(C_INFO).add_modifier(Modifier::BOLD))),
    );

    f.render_widget(popup, popup_area);
}

// ─── Action menu popup ─────────────────────────────────────────────────────────

fn draw_action_menu(f: &mut Frame, app: &App, area: Rect) {
    let popup_area = centered_rect_fixed(52, 8, area);
    f.render_widget(Clear, popup_area);

    if let Some(ref result) = app.action_result {
        // Result view
        let lines: Vec<Line> = vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(result.as_str(), Style::default().fg(C_NORMAL)),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Esc / Enter / Space", Style::default().fg(C_HEADER)),
                Span::styled("  Dismiss", Style::default().fg(C_DIM)),
            ]),
        ];
        let popup = Paragraph::new(lines)
            .wrap(ratatui::widgets::Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(C_INFO))
                    .title(Span::styled(" Result ", Style::default().fg(C_INFO).add_modifier(Modifier::BOLD))),
            );
        f.render_widget(popup, popup_area);
    } else {
        // Action menu view
        let lines: Vec<Line> = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  K", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
                Span::styled("  Kill process", Style::default().fg(C_NORMAL)),
            ]),
            Line::from(vec![
                Span::styled("  H", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
                Span::styled("  Hash exe (SHA256)", Style::default().fg(C_NORMAL)),
            ]),
            Line::from(vec![
                Span::styled("  C", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
                Span::styled("  Copy path to clipboard", Style::default().fg(C_NORMAL)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Esc", Style::default().fg(C_DIM)),
                Span::styled("  Cancel", Style::default().fg(C_DIM)),
            ]),
        ];
        let popup = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(C_HEADER))
                .title(Span::styled(" Actions ", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD))),
        );
        f.render_widget(popup, popup_area);
    }
}

// ─── Alerts tab ────────────────────────────────────────────────────────────────

fn draw_alerts(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(area);

    draw_alert_sidebar(f, app, cols[0]);
    draw_alert_table(f, app, cols[1]);
}

fn draw_alert_sidebar(f: &mut Frame, app: &App, area: Rect) {
    let (crit, high, med, low, info) = app.alert_counts();
    let total = app.alerts.len();

    let lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ▓ ALERTS", Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("  CRIT  {}", crit),
                if crit > 0 {
                    Style::default().fg(C_CRIT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(C_CRIT)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  HIGH  {}", high),
                if high > 0 {
                    Style::default().fg(C_HIGH).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(C_HIGH)
                },
            ),
        ]),
        Line::from(vec![
            Span::styled(format!("  MED   {}", med), Style::default().fg(C_MED)),
        ]),
        Line::from(vec![
            Span::styled(format!("  LOW   {}", low), Style::default().fg(C_LOW)),
        ]),
        Line::from(vec![
            Span::styled(format!("  INFO  {}", info), Style::default().fg(C_INFO)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  Total  {}", total), Style::default().fg(C_NORMAL)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ● Live stream", Style::default().fg(C_LOW)),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_alert_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_cells = [
        Cell::from(" SEV    ").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("KIND                ").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("MESSAGE").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("RULE        ").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("TIME      ").style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    ];
    let header = Row::new(header_cells)
        .height(1)
        .bottom_margin(1)
        .style(Style::default().bg(Color::Rgb(15, 25, 40)));

    let selected_idx = app.alert_state.selected().unwrap_or(usize::MAX);

    let rows: Vec<Row> = app
        .alerts
        .iter()
        .enumerate()
        .map(|(i, alert)| {
            let is_sel = i == selected_idx;
            let bg     = if is_sel { C_SELECTED } else { C_BG };

            let sev_color = match alert.sev_ord {
                5 => C_CRIT,
                4 => C_HIGH,
                3 => C_MED,
                2 => C_LOW,
                _ => C_INFO,
            };

            let sev_label = match alert.sev_ord {
                5 => " CRIT ",
                4 => " HIGH ",
                3 => " MED  ",
                2 => " LOW  ",
                _ => " INFO ",
            };

            let kind_display = if alert.kind.chars().count() > 18 {
                alert.kind.chars().take(18).collect::<String>()
            } else {
                alert.kind.clone()
            };

            let rule_display = if alert.rule_id.is_empty() {
                "—".to_string()
            } else if alert.rule_id.chars().count() > 12 {
                alert.rule_id.chars().take(12).collect::<String>()
            } else {
                alert.rule_id.clone()
            };

            let time_display = alert
                .occurred_at
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string();

            Row::new(vec![
                Cell::from(sev_label).style(
                    Style::default()
                        .fg(sev_color)
                        .add_modifier(if is_sel || alert.sev_ord >= 4 { Modifier::BOLD } else { Modifier::empty() })
                        .bg(bg),
                ),
                Cell::from(kind_display).style(
                    Style::default()
                        .fg(if is_sel { Color::White } else { C_NORMAL })
                        .add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() })
                        .bg(bg),
                ),
                Cell::from(alert.message.clone()).style(
                    Style::default()
                        .fg(if is_sel { Color::White } else { C_DIM })
                        .bg(bg),
                ),
                Cell::from(rule_display).style(Style::default().fg(C_DIM).bg(bg)),
                Cell::from(time_display).style(Style::default().fg(C_DIM).bg(bg)),
            ])
            .height(1)
        })
        .collect();

    let title = format!(" {} alerts ", app.alerts.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(title, Style::default().fg(C_DIM)));

    let table = Table::new(
        rows,
        &[
            Constraint::Length(8),  // SEV
            Constraint::Length(20), // KIND
            Constraint::Min(0),     // MESSAGE
            Constraint::Length(12), // RULE
            Constraint::Length(10), // TIME
        ],
    )
    .header(header)
    .block(block);

    f.render_stateful_widget(table, area, &mut app.alert_state);
}

fn centered_rect(width_pct: u16, height: u16, area: Rect) -> Rect {
    let w = area.width * width_pct / 100;
    let x = area.x + (area.width - w) / 2;
    let y = area.y + area.height / 2;
    Rect::new(x, y, w, height)
}

fn centered_rect_fixed(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}
