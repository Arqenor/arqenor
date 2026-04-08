use crate::{
    app::{App, RiskLevel, ScanState, Tab},
    network::{HostRisk, OsGuess},
};
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

pub fn draw(f: &mut Frame, app: &App) {
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
    ];
    let selected = match app.tab {
        Tab::Processes   => 0,
        Tab::Persistence => 1,
        Tab::Network     => 2,
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

fn draw_body(f: &mut Frame, app: &App, area: Rect) {
    match app.tab {
        Tab::Processes   => draw_processes(f, app, area),
        Tab::Persistence => draw_persistence(f, app, area),
        Tab::Network     => draw_network(f, app, area),
    }
}

// ─── Processes tab ─────────────────────────────────────────────────────────────

fn draw_processes(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(0)])
        .split(area);

    draw_sidebar(f, app, cols[0]);
    draw_process_table(f, app, cols[1]);
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

fn draw_process_table(f: &mut Frame, app: &App, area: Rect) {
    let rows_data = app.filtered_processes();

    let header_cells = ["  PID", "PPID", "RISK     ", "SCORE", "NAME                         ", "PATH"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(C_HEADER).add_modifier(Modifier::BOLD)));
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

            let bar    = risk_bar(r.score);
            let path   = r.info.exe_path.as_deref().unwrap_or("—");
            // Truncate long paths from the left to fit
            let path_display = if path.len() > 45 {
                format!("…{}", &path[path.len().saturating_sub(44)..])
            } else {
                path.to_string()
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
                Cell::from(r.info.name.clone())
                    .style(Style::default().fg(if is_sel { Color::White } else { C_NORMAL }).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }).bg(bg)),
                Cell::from(path_display)
                    .style(Style::default().fg(C_DIM).bg(bg)),
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

    f.render_widget(table, area);
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

// ─── Status bar ────────────────────────────────────────────────────────────────

fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    let elapsed = app.last_refresh.elapsed().as_secs();
    let keys = Line::from(vec![
        Span::styled(" ↑↓", Style::default().fg(C_HEADER)),
        Span::styled(" Navigate", Style::default().fg(C_DIM)),
        Span::styled("  ←→/Tab", Style::default().fg(C_HEADER)),
        Span::styled(" Switch tab", Style::default().fg(C_DIM)),
        Span::styled("  /", Style::default().fg(C_HEADER)),
        Span::styled(" Filter", Style::default().fg(C_DIM)),
        Span::styled("  R", Style::default().fg(C_HEADER)),
        Span::styled(" Refresh", Style::default().fg(C_DIM)),
        Span::styled("  S", Style::default().fg(C_INFO)),
        Span::styled(" Net scan", Style::default().fg(C_DIM)),
        Span::styled("  Q", Style::default().fg(C_HIGH)),
        Span::styled(" Quit", Style::default().fg(C_DIM)),
        Span::styled(
            format!("  — {}s ago", elapsed),
            Style::default().fg(C_DIM),
        ),
    ]);

    let bar = Paragraph::new(keys)
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

fn centered_rect(width_pct: u16, height: u16, area: Rect) -> Rect {
    let w = area.width * width_pct / 100;
    let x = area.x + (area.width - w) / 2;
    let y = area.y + area.height / 2;
    Rect::new(x, y, w, height)
}
