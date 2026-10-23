use crate::proof::ProofRecord;
use crate::report::{ForensicReporter, ForensicStats};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Gauge, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Visual HUD Themes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HudTheme {
    TacticalTeal,
    DeepMidnight,
}

/// Contrast level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContrastLevel {
    Soft,
    Normal,
    High,
}

/// Active HUD State
pub struct HudState {
    pub log_path: PathBuf,
    pub theme: HudTheme,
    pub contrast: ContrastLevel,
    pub focus_mode: bool,
    pub panic_mode: bool,
    pub show_vectors: bool,
    pub show_gauges: bool,
    pub show_ledger: bool,
    pub table_scroll: usize,
    pub status_message: Option<(String, Instant)>,
    pub panic_scroll_offset: usize,
}

impl HudState {
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            theme: HudTheme::TacticalTeal,
            contrast: ContrastLevel::Normal,
            focus_mode: false,
            panic_mode: false,
            show_vectors: true,
            show_gauges: true,
            show_ledger: true,
            table_scroll: 0,
            status_message: None,
            panic_scroll_offset: 0,
        }
    }

    pub fn toggle_theme(&mut self) {
        self.theme = match self.theme {
            HudTheme::TacticalTeal => HudTheme::DeepMidnight,
            HudTheme::DeepMidnight => HudTheme::TacticalTeal,
        };
        self.set_status(format!("Theme: {:?}", self.theme));
    }

    pub fn cycle_contrast(&mut self) {
        self.contrast = match self.contrast {
            ContrastLevel::Soft => ContrastLevel::Normal,
            ContrastLevel::Normal => ContrastLevel::High,
            ContrastLevel::High => ContrastLevel::Soft,
        };
        self.set_status(format!("Contrast: {:?}", self.contrast));
    }

    pub fn toggle_focus(&mut self) {
        self.focus_mode = !self.focus_mode;
        self.set_status(format!(
            "Focus Mode: {}",
            if self.focus_mode { "ON" } else { "OFF" }
        ));
    }

    pub fn toggle_panic(&mut self) {
        self.panic_mode = !self.panic_mode;
    }

    pub fn set_status(&mut self, msg: String) {
        self.status_message = Some((msg, Instant::now()));
    }

    /// Color definitions based on current theme and contrast
    pub fn primary_color(&self) -> Color {
        match self.theme {
            HudTheme::TacticalTeal => match self.contrast {
                ContrastLevel::Soft => Color::Rgb(0, 160, 140),
                ContrastLevel::Normal => Color::Rgb(0, 215, 175),
                ContrastLevel::High => Color::Rgb(50, 255, 210),
            },
            HudTheme::DeepMidnight => match self.contrast {
                ContrastLevel::Soft => Color::Rgb(120, 100, 200),
                ContrastLevel::Normal => Color::Rgb(150, 125, 250),
                ContrastLevel::High => Color::Rgb(190, 160, 255),
            },
        }
    }

    pub fn secondary_color(&self) -> Color {
        match self.theme {
            HudTheme::TacticalTeal => Color::Rgb(34, 139, 100),
            HudTheme::DeepMidnight => Color::Rgb(75, 90, 140),
        }
    }

    pub fn bg_color(&self) -> Color {
        match self.theme {
            HudTheme::TacticalTeal => Color::Rgb(16, 22, 24),
            HudTheme::DeepMidnight => Color::Rgb(18, 16, 28),
        }
    }

    pub fn text_color(&self) -> Color {
        match self.theme {
            HudTheme::TacticalTeal => Color::Rgb(220, 240, 235),
            HudTheme::DeepMidnight => Color::Rgb(200, 205, 230),
        }
    }

    pub fn alert_color(&self) -> Color {
        Color::Rgb(255, 80, 80)
    }

    pub fn warning_color(&self) -> Color {
        Color::Rgb(255, 180, 50)
    }

    pub fn success_color(&self) -> Color {
        match self.theme {
            HudTheme::TacticalTeal => Color::Rgb(50, 220, 130),
            HudTheme::DeepMidnight => Color::Rgb(100, 220, 160),
        }
    }
}

pub struct CommandCenterHud;

impl CommandCenterHud {
    /// Launches the interactive Ratatui Command Center HUD.
    pub fn run(log_path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut state = HudState::new(log_path.to_path_buf());
        let res = Self::event_loop(&mut terminal, &mut state);

        // Clean up terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        res
    }

    fn event_loop(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        state: &mut HudState,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tick_rate = Duration::from_millis(250);
        let mut last_tick = Instant::now();

        loop {
            // Read latest telemetry & records from disk
            let stats = ForensicReporter::analyze_log(&state.log_path).unwrap_or_default();
            let records = Self::read_recent_records(&state.log_path, 100);

            // Compute live Tarpit metrics (atomic or inferred from forensic audit)
            let mut metrics = crate::tarpit::TarpitMetrics::current();
            if metrics.active_sockets == 0 && stats.tarpitted_sessions > 0 {
                metrics.drained_cpu_seconds = metrics
                    .drained_cpu_seconds
                    .max(stats.tarpitted_sessions * 180);
                metrics.bytes_drained = metrics.bytes_drained.max(stats.tarpitted_sessions * 4096);
                metrics.json_sinks_active = stats.json_sinks_engaged as usize;
                metrics.html_sinks_active = stats.html_sinks_engaged as usize;
            }

            terminal.draw(|f| {
                if state.panic_mode {
                    Self::render_panic_screen(f, state);
                } else {
                    Self::render_hud(f, state, &stats, &records, &metrics);
                }
            })?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            // Panic button
                            KeyCode::Esc => state.toggle_panic(),

                            // If in panic mode, only Esc returns to HUD
                            _ if state.panic_mode => {
                                state.panic_scroll_offset = (state.panic_scroll_offset + 1) % 50;
                            }

                            KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                            KeyCode::Char('t') | KeyCode::Char('T') => state.toggle_theme(),
                            KeyCode::Char('c') | KeyCode::Char('C') => state.cycle_contrast(),
                            KeyCode::Char('f') | KeyCode::Char('F') => state.toggle_focus(),
                            KeyCode::Char('1') => state.show_vectors = !state.show_vectors,
                            KeyCode::Char('2') => state.show_gauges = !state.show_gauges,
                            KeyCode::Char('3') => state.show_ledger = !state.show_ledger,

                            KeyCode::Up | KeyCode::Char('k') => {
                                if state.table_scroll > 0 {
                                    state.table_scroll -= 1;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if state.table_scroll + 1 < records.len() {
                                    state.table_scroll += 1;
                                }
                            }

                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                let out = PathBuf::from(format!(
                                    "/tmp/soc_report_{}.md",
                                    chrono::Utc::now().format("%Y%m%d_%H%M%S")
                                ));
                                let content = ForensicReporter::generate_markdown_report(
                                    &stats,
                                    &state.log_path,
                                );
                                let _ = std::fs::write(&out, content);
                                state.set_status(format!("Report saved: {}", out.display()));
                            }

                            _ => {}
                        }
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }
        }
    }

    /// Renders the complete Tactical / Deep Midnight HUD.
    fn render_hud(
        f: &mut Frame,
        state: &HudState,
        stats: &ForensicStats,
        records: &[ProofRecord],
        metrics: &crate::tarpit::TarpitMetrics,
    ) {
        let size = f.area();

        // Background filler
        let bg_block = Block::default().style(Style::default().bg(state.bg_color()));
        f.render_widget(bg_block, size);

        // Master vertical layout: Header (3), Main Area (min 0), Status Footer (3)
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(size);

        Self::render_header(f, state, main_chunks[0], stats);
        Self::render_main_area(f, state, main_chunks[1], stats, records, metrics);
        Self::render_footer(f, state, main_chunks[2], stats);
    }

    fn render_header(f: &mut Frame, state: &HudState, area: Rect, stats: &ForensicStats) {
        let theme_label = match state.theme {
            HudTheme::TacticalTeal => "TACTICAL TEAL",
            HudTheme::DeepMidnight => "DEEP MIDNIGHT",
        };
        let mode_label = if state.focus_mode { "FOCUS" } else { "GRID" };

        let integrity_text = if stats.chain_verified {
            Span::styled(
                "🛡️ CHAIN VERIFIED",
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "⚠️ HASH MISMATCH",
                Style::default()
                    .fg(state.alert_color())
                    .add_modifier(Modifier::BOLD),
            )
        };

        let title_line = Line::from(vec![
            Span::styled(
                " JFP-PARADOX COMMAND CENTER HUD ",
                Style::default()
                    .fg(state.text_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("[{}] ", theme_label),
                Style::default().fg(state.primary_color()),
            ),
            Span::styled(
                format!("[MODE: {}] ", mode_label),
                Style::default().fg(state.secondary_color()),
            ),
            integrity_text,
        ]);

        let time_str = chrono::Utc::now().format("%H:%M:%S UTC").to_string();
        let subtitle_line = Line::from(vec![
            Span::styled("Engine: ", Style::default().fg(state.secondary_color())),
            Span::styled(
                "v0.4.3 Deep Tarpit Economy  ",
                Style::default().fg(state.text_color()),
            ),
            Span::styled("Ingress: ", Style::default().fg(state.secondary_color())),
            Span::styled("0.0.0.0:8080  ", Style::default().fg(state.primary_color())),
            Span::styled("Live Time: ", Style::default().fg(state.secondary_color())),
            Span::styled(time_str, Style::default().fg(state.text_color())),
        ]);

        let header = Paragraph::new(vec![title_line, subtitle_line]).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(state.primary_color())),
        );

        f.render_widget(header, area);
    }

    fn render_main_area(
        f: &mut Frame,
        state: &HudState,
        area: Rect,
        stats: &ForensicStats,
        records: &[ProofRecord],
        metrics: &crate::tarpit::TarpitMetrics,
    ) {
        if state.focus_mode {
            // Fullscreen table mode
            Self::render_ledger_table(f, state, area, records);
            return;
        }

        // Split top and bottom
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10), Constraint::Min(8)])
            .split(area);

        // Top Row: Split Left (Vectors) and Right (Deep Tarpit Economy Live Panel)
        let top_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[0]);

        if state.show_vectors {
            Self::render_vectors_panel(f, state, top_cols[0], stats);
        }
        if state.show_gauges {
            Self::render_tarpit_panel(f, state, top_cols[1], stats, metrics);
        }

        // Bottom Row: Threat Ledger Table
        if state.show_ledger {
            Self::render_ledger_table(f, state, rows[1], records);
        }
    }

    fn render_vectors_panel(f: &mut Frame, state: &HudState, area: Rect, stats: &ForensicStats) {
        let mut lines = Vec::new();
        let mut sorted_vectors: Vec<_> = stats.vector_distribution.iter().collect();
        sorted_vectors.sort_by(|a, b| b.1.cmp(a.1));

        if sorted_vectors.is_empty() {
            lines.push(Line::from(Span::styled(
                "  No threat signatures detected yet.",
                Style::default().fg(state.secondary_color()),
            )));
        } else {
            let max_val = sorted_vectors.first().map(|v| *v.1).unwrap_or(1).max(1);
            for (vec, count) in sorted_vectors.iter().take(5) {
                let bar_len = ((**count as f64 / max_val as f64) * 16.0).round() as usize;
                let bar = "█".repeat(bar_len);
                let empty = "░".repeat(16usize.saturating_sub(bar_len));

                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" {:<20} ", truncate_str(vec, 20)),
                        Style::default().fg(state.text_color()),
                    ),
                    Span::styled(
                        format!("[{}{}] ", bar, empty),
                        Style::default().fg(state.primary_color()),
                    ),
                    Span::styled(
                        format!("{:>4}", count),
                        Style::default().fg(state.warning_color()),
                    ),
                ]));
            }
        }

        let block = Block::default()
            .title(" 🎯 [1] INGRESS THREAT VECTORS ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(state.primary_color()));

        let p = Paragraph::new(lines).block(block);
        f.render_widget(p, area);
    }

    pub fn render_tarpit_panel(
        f: &mut Frame,
        state: &HudState,
        area: Rect,
        _stats: &ForensicStats,
        metrics: &crate::tarpit::TarpitMetrics,
    ) {
        let block = Block::default()
            .title(" ⚡ [2] DEEP TARPIT ECONOMY (LIVE) ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(state.primary_color()));

        let inner = block.inner(area);
        f.render_widget(block, area);

        // Split vertically: Upper (Two columns of metrics), Lower (Concurrency Guard Bar)
        let v_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(3)])
            .split(inner);

        // Subdivide upper into Left (Active Sockets & Sinks) and Right (Botnet Resource Waste)
        let h_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(v_chunks[0]);

        // Panel 1: Aktywne sockety i sockety w pułapkach
        let active_text = vec![
            Line::from(vec![
                Span::styled(
                    "Active Sockets:  ",
                    Style::default().fg(state.secondary_color()),
                ),
                Span::styled(
                    format!("{}", metrics.active_sockets),
                    Style::default()
                        .fg(state.primary_color())
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "JSON Sinks (C2): ",
                    Style::default().fg(state.secondary_color()),
                ),
                Span::styled(
                    format!("{}", metrics.json_sinks_active),
                    Style::default().fg(state.text_color()),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "HTML DOM Sinks:  ",
                    Style::default().fg(state.secondary_color()),
                ),
                Span::styled(
                    format!("{}", metrics.html_sinks_active),
                    Style::default().fg(state.text_color()),
                ),
            ]),
        ];
        let left_widget =
            Paragraph::new(active_text).block(Block::default().borders(Borders::NONE));

        // Panel 2: Straty zasobów botnetu
        let drained_mins = metrics.drained_cpu_seconds / 60;
        let drained_secs = metrics.drained_cpu_seconds % 60;
        let waste_time_str = if drained_mins > 0 {
            format!("{}m {}s", drained_mins, drained_secs)
        } else {
            format!("{}s", drained_secs)
        };

        let waste_text = vec![
            Line::from(vec![
                Span::styled(
                    "Bot CPU Drained: ",
                    Style::default().fg(state.secondary_color()),
                ),
                Span::styled(
                    waste_time_str,
                    Style::default()
                        .fg(state.warning_color())
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "Bytes Drained:   ",
                    Style::default().fg(state.secondary_color()),
                ),
                Span::styled(
                    format!("{} KB", metrics.bytes_drained / 1024),
                    Style::default().fg(state.text_color()),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "Concurrency Cap: ",
                    Style::default().fg(state.secondary_color()),
                ),
                Span::styled(
                    format!("{}/{}", metrics.active_sockets, metrics.max_concurrency),
                    Style::default().fg(state.success_color()),
                ),
            ]),
        ];
        let right_widget =
            Paragraph::new(waste_text).block(Block::default().borders(Borders::NONE));

        f.render_widget(left_widget, h_chunks[0]);
        f.render_widget(right_widget, h_chunks[1]);

        // Lower: Concurrency Guard Bar Gauge
        let ratio =
            (metrics.active_sockets as f64 / metrics.max_concurrency as f64).clamp(0.0, 1.0);
        let guard_gauge = Gauge::default()
            .block(Block::default().title(" 🛡️ CONCURRENCY GUARD "))
            .gauge_style(
                Style::default()
                    .fg(if ratio > 0.8 {
                        state.alert_color()
                    } else {
                        state.primary_color()
                    })
                    .bg(state.bg_color()),
            )
            .ratio(ratio)
            .label(format!(
                "{}/{} Sockets (Bound)",
                metrics.active_sockets, metrics.max_concurrency
            ));

        f.render_widget(guard_gauge, v_chunks[1]);
    }

    fn render_ledger_table(f: &mut Frame, state: &HudState, area: Rect, records: &[ProofRecord]) {
        let selected_style = Style::default()
            .fg(state.bg_color())
            .bg(state.primary_color());
        let header_cells = [
            "TIMESTAMP",
            "ATTACKER IP",
            "ACTION",
            "PAYLOAD / RECON SIGNATURE",
        ]
        .iter()
        .map(|h| {
            Span::styled(
                *h,
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            )
        });
        let header = Row::new(header_cells).height(1).bottom_margin(1);

        let rows = records
            .iter()
            .skip(state.table_scroll)
            .take(area.height as usize)
            .map(|r| {
                let time_short = r.timestamp.chars().skip(11).take(8).collect::<String>();
                let action_color = if r.event_type.contains("BLOCKED") {
                    state.alert_color()
                } else if r.event_type.contains("TARPIT") {
                    state.warning_color()
                } else {
                    state.primary_color()
                };

                let summary = r
                    .payload_summary
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or(r.event_type.as_str());

                Row::new(vec![
                    Span::styled(time_short, Style::default().fg(state.secondary_color())),
                    Span::styled(r.ip.clone(), Style::default().fg(state.text_color())),
                    Span::styled(
                        r.event_type.clone(),
                        Style::default()
                            .fg(action_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        truncate_str(summary, 50),
                        Style::default().fg(state.text_color()),
                    ),
                ])
            });

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Length(22),
                Constraint::Min(20),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(" 🚨 [3] REAL-TIME PROOF CHAIN LEDGER (Use ↑/↓ or j/k to scroll) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(state.primary_color())),
        )
        .row_highlight_style(selected_style);

        f.render_widget(table, area);
    }

    fn render_footer(f: &mut Frame, state: &HudState, area: Rect, _stats: &ForensicStats) {
        let status_text = if let Some((msg, time)) = &state.status_message {
            if time.elapsed() < Duration::from_secs(4) {
                Span::styled(
                    format!(" ℹ️ {} ", msg),
                    Style::default()
                        .fg(state.warning_color())
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw("")
            }
        } else {
            Span::raw("")
        };

        let footer_lines = vec![Line::from(vec![
            Span::styled(
                " [T] ",
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Theme ", Style::default().fg(state.text_color())),
            Span::styled(
                "[C] ",
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Contrast ", Style::default().fg(state.text_color())),
            Span::styled(
                "[F] ",
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Focus ", Style::default().fg(state.text_color())),
            Span::styled(
                "[1-3] ",
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Panels ", Style::default().fg(state.text_color())),
            Span::styled(
                "[R] ",
                Style::default()
                    .fg(state.primary_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Export Report ", Style::default().fg(state.text_color())),
            Span::styled(
                "[ESC] ",
                Style::default()
                    .fg(state.alert_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "PANIC BUTTON ",
                Style::default()
                    .fg(state.alert_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "[Q] ",
                Style::default()
                    .fg(state.secondary_color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Quit ", Style::default().fg(state.text_color())),
            status_text,
        ])];

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(state.secondary_color()));

        let p = Paragraph::new(footer_lines)
            .block(block)
            .alignment(Alignment::Center);
        f.render_widget(p, area);
    }

    /// Renders the stealth Panic Screen (Fake Linux kernel build output)
    fn render_panic_screen(f: &mut Frame, _state: &HudState) {
        let size = f.area();
        f.render_widget(Clear, size);

        let kernel_logs = [
            "make[1]: Entering directory '/usr/src/linux-6.10.4'",
            "  HOSTCC  scripts/basic/fixdep",
            "  HOSTCC  scripts/kconfig/conf.o",
            "  HOSTLD  scripts/kconfig/conf",
            "  UPD     include/config/kernel.release",
            "  CC      arch/x86/kernel/process_64.o",
            "  CC      arch/x86/kernel/signal.o",
            "  CC      arch/x86/kernel/traps.o",
            "  CC      arch/x86/kernel/entry_64.o",
            "  CC      kernel/sched/core.o",
            "  CC      kernel/sched/fair.o",
            "  CC      kernel/sched/topology.o",
            "  CC      mm/page_alloc.o",
            "  CC      mm/vmscan.o",
            "  CC      mm/slub.o",
            "  CC      fs/namei.o",
            "  CC      fs/buffer.o",
            "  CC      net/core/dev.o",
            "  CC      net/ipv4/tcp.o",
            "  CC      drivers/pci/pci.o",
            "  AR      arch/x86/lib/lib.a",
            "  LD      vmlinux.o",
            "  OBJCOPY arch/x86/boot/vmlinuz",
            "  BUILD   arch/x86/boot/bzImage",
            "Kernel: arch/x86/boot/bzImage is ready  (#1 SMP PREEMPT Thu Oct 23 07:22:00 UTC 2026)",
            "  SYNC    include/generated/compile.h",
            "  MODPOST Module.symvers",
            "  CC [M]  drivers/net/ethernet/intel/e1000e/netdev.o",
            "  LD [M]  drivers/net/ethernet/intel/e1000e/e1000e.o",
        ];

        let mut lines = Vec::new();
        for &line in &kernel_logs {
            lines.push(Line::from(Span::styled(
                line,
                Style::default().fg(Color::Gray),
            )));
        }

        let p =
            Paragraph::new(lines).block(Block::default().style(Style::default().bg(Color::Black)));
        f.render_widget(p, size);
    }

    fn read_recent_records(log_path: &Path, limit: usize) -> Vec<ProofRecord> {
        let file = match File::open(log_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(rec) = serde_json::from_str::<ProofRecord>(trimmed) {
                records.push(rec);
            }
        }

        // Return latest events in reverse chronological order
        records.reverse();
        records.truncate(limit);
        records
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hud_state_transitions() {
        let mut state = HudState::new(PathBuf::from("/tmp/test_proof.jsonl"));
        assert_eq!(state.theme, HudTheme::TacticalTeal);

        state.toggle_theme();
        assert_eq!(state.theme, HudTheme::DeepMidnight);

        state.cycle_contrast();
        assert_eq!(state.contrast, ContrastLevel::High);

        state.toggle_focus();
        assert!(state.focus_mode);

        state.toggle_panic();
        assert!(state.panic_mode);
        state.toggle_panic();
        assert!(!state.panic_mode);
    }

    #[test]
    fn test_hud_tarpit_panel_rendering() {
        use ratatui::backend::TestBackend;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        let state = HudState::new(PathBuf::from("/tmp/nonexistent_proof.jsonl"));
        let stats = ForensicStats::default();
        let records = Vec::new();
        let metrics = crate::tarpit::TarpitMetrics {
            active_sockets: 42,
            json_sinks_active: 28,
            html_sinks_active: 14,
            drained_cpu_seconds: 3600,
            bytes_drained: 1048576,
            max_concurrency: 512,
        };

        terminal
            .draw(|f| {
                CommandCenterHud::render_hud(f, &state, &stats, &records, &metrics);
            })
            .unwrap();
    }
}
