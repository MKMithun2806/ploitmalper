//! Interactive terminal UI helpers built on ratatui + crossterm.
//!
//! Everything in here is optional: commands fall back to the classic
//! line-oriented output when the terminal is not interactive, so `--json` and
//! piped invocations keep working unchanged.

use std::io::{self, IsTerminal};

use crossterm::cursor as cur;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::{Frame, Terminal};

use crate::error::Result;

type Backend = CrosstermBackend<io::Stdout>;
type Term = Terminal<Backend>;

/// True when the current stdin/stdout pair can host an interactive picker.
/// Never auto-launches inside a pipe or non-tty context (tests, `--json`).
pub fn interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// Acquire raw mode + an alternate screen so the picker is self-contained.
fn enter_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture, cur::Hide)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    terminal.clear()?;
    Ok(terminal)
}

/// Restore the terminal after an interactive session, swallowing any error so
/// the caller's real error is what surfaces.
fn leave_terminal(mut terminal: Term) {
    let _ = terminal.show_cursor();
    let _ = terminal.flush();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        Clear(ClearType::All),
        cur::Show
    );
    let _ = disable_raw_mode();
}

/// Blocking read of the next *press* key event (auto-repeat safe).
fn read_key() -> Result<KeyEvent> {
    loop {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                return Ok(key);
            }
        }
    }
}

/// Number of `ListItem` rows that fit between the top/bottom borders.
fn list_height(rect: &Rect) -> u16 {
    rect.height.saturating_sub(2).max(1)
}

/// Advance the picker cursor around a circular ring of `len` items.
fn step_cursor(direction: isize, cursor: usize, len: usize) -> usize {
    debug_assert!(len > 0);
    ((cursor as isize + direction).rem_euclid(len as isize)) as usize
}

/// One row in the interactive selector.
pub struct PickerRow {
    /// Primary label, rendered with the selection marker circle.
    pub text: String,
    /// Optional secondary line (module rank / host); shown dim after `text`.
    pub detail: Option<String>,
    /// Whether the row starts selected.
    pub selected: bool,
}

/// Interactive multi-select picker used by the exploit command. Renders the
/// modules as a circular list: arrow keys (or j/k) move the cursor between the
/// circles, `space` toggles the current one, `a` selects all and `n` clears
/// selection, `enter` confirms and advances, `q`/`Esc` aborts.
///
/// Returns `Some(indices)` of the rows selected at confirm time, or `None`
/// when the user aborted.
pub fn pick(title: &str, rows: Vec<PickerRow>, first: usize) -> Result<Option<Vec<usize>>> {
    if rows.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let cursor = if first < rows.len() { first } else { 0 };
    let mut terminal = enter_terminal()?;
    let result = run_picker(&mut terminal, title, rows, cursor);
    leave_terminal(terminal);
    result
}

fn run_picker(
    terminal: &mut Term,
    title: &str,
    mut rows: Vec<PickerRow>,
    mut cursor: usize,
) -> Result<Option<Vec<usize>>> {
    loop {
        terminal.draw(|frame| draw_picker(frame, title, &rows, cursor))?;
        let key = read_key()?;

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
            KeyCode::Char('j') | KeyCode::Down => {
                cursor = step_cursor(1, cursor, rows.len());
            }
            KeyCode::Char('k') | KeyCode::Up => {
                cursor = step_cursor(-1, cursor, rows.len());
            }
            KeyCode::Char(' ') => {
                rows[cursor].selected = !rows[cursor].selected;
            }
            KeyCode::Char('a') => {
                for row in rows.iter_mut() {
                    row.selected = true;
                }
            }
            KeyCode::Char('n') => {
                for row in rows.iter_mut() {
                    row.selected = false;
                }
            }
            KeyCode::Enter => {
                let chosen: Vec<usize> = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.selected)
                    .map(|(i, _)| i)
                    .collect();
                return Ok(Some(chosen));
            }
            _ => {}
        }
    }
}

fn draw_picker(frame: &mut Frame<'_>, title: &str, rows: &[PickerRow], cursor: usize) {
    let outer = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            title,
            Style::default().add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(outer);
    frame.render_widget(block, outer);

    let height = list_height(&inner);
    let visible = (height as usize).min(rows.len());
    let scroll = cursor
        .saturating_sub(visible / 2)
        .min(rows.len().saturating_sub(visible));

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, row)| {
            let marker = if row.selected { "●" } else { "○" };
            let marker_style = if row.selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let mut spans = vec![Span::styled(marker, marker_style), Span::raw(" ")];
            if i == cursor {
                spans.push(Span::styled(
                    row.text.clone(),
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ));
            } else {
                spans.push(Span::raw(row.text.clone()));
            }
            if let Some(detail) = &row.detail {
                spans.push(Span::styled(
                    format!(
                        "  {}",
                        crate::frontend::truncate(detail, inner.width.saturating_sub(6) as usize)
                    ),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let list_area = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height,
    };
    frame.render_widget(List::new(items), list_area);

    let footer = format!(
        " {}/{}  ↑/k move ↓/j · space toggle · a all · n none · enter continue · q quit ",
        cursor + 1,
        rows.len()
    );
    frame.render_widget(
        Paragraph::new(Span::styled(footer, Style::default().fg(Color::DarkGray)))
            .alignment(Alignment::Center),
        Rect {
            x: inner.x,
            y: inner.y + inner.height - 2,
            width: inner.width,
            height: 1,
        },
    );
}

/// One row in the tabular viewer (equal `length`-wise to `columns`).
pub struct ViewerRow {
    pub cells: Vec<String>,
}

impl ViewerRow {
    pub fn new(cells: Vec<String>) -> Self {
        ViewerRow { cells }
    }
}

/// Interactive single-select viewer for tabular data (runs / findings). Shows
/// a scrollable list of rows with a detail pane beneath the cursor row.
/// `enter` returns `Some(index)`, `q`/`Esc` returns `None`.
pub fn view_table(title: &str, columns: &[&str], rows: Vec<ViewerRow>) -> Result<Option<usize>> {
    if rows.is_empty() {
        return Ok(None);
    }
    let mut terminal = enter_terminal()?;
    let result = run_viewer(&mut terminal, title, columns, rows, 0);
    leave_terminal(terminal);
    result
}

fn run_viewer(
    terminal: &mut Term,
    title: &str,
    columns: &[&str],
    rows: Vec<ViewerRow>,
    mut cursor: usize,
) -> Result<Option<usize>> {
    loop {
        terminal.draw(|frame| draw_viewer(frame, title, columns, &rows, cursor))?;
        let key = read_key()?;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
            KeyCode::Char('j') | KeyCode::Down => {
                if cursor + 1 < rows.len() {
                    cursor += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                cursor = cursor.saturating_sub(1);
            }
            KeyCode::PageDown => cursor = (cursor + 10).min(rows.len() - 1),
            KeyCode::PageUp => cursor = cursor.saturating_sub(10),
            KeyCode::Home => cursor = 0,
            KeyCode::End => cursor = rows.len() - 1,
            KeyCode::Enter => return Ok(Some(cursor)),
            _ => {}
        }
    }
}

fn draw_viewer(
    frame: &mut Frame<'_>,
    title: &str,
    columns: &[&str],
    rows: &[ViewerRow],
    cursor: usize,
) {
    let outer = frame.area();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            title,
            Style::default().add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center)
        .border_style(Style::default().fg(Color::Magenta));

    let inner = block.inner(outer);
    frame.render_widget(block, outer);

    let list_height = inner.height.saturating_sub(3).max(1);
    let visible_rows = (list_height as usize).min(rows.len());
    let scroll = cursor
        .saturating_sub(visible_rows / 2)
        .min(rows.len().saturating_sub(visible_rows));
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible_rows)
        .map(|(i, row)| {
            let mut line = String::new();
            for (k, value) in row.cells.iter().enumerate() {
                if k == 0 {
                    line.push_str(&crate::frontend::truncate(value, 24));
                } else if columns
                    .get(k)
                    .map(|c| matches!(*c, "RANK" | "CONF" | "PORT"))
                    .unwrap_or(false)
                {
                    line.push_str(&format!("  {value:>8}"));
                } else {
                    line.push_str(&format!("  {}", crate::frontend::truncate(value, 22)));
                }
            }
            let prefix = if i == cursor { "❯ " } else { "  " };
            let styled_line = if i == cursor {
                Line::from(vec![
                    Span::styled(
                        prefix,
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(line.clone(), Style::default().fg(Color::Cyan)),
                ])
            } else {
                Line::from(vec![
                    Span::raw(prefix),
                    Span::styled(line.clone(), Style::default().fg(Color::White)),
                ])
            };
            let _ = &line;
            ListItem::new(styled_line)
        })
        .collect();

    let list_area = Rect {
        x: inner.x + 1,
        y: inner.y + 1,
        width: inner.width.saturating_sub(2),
        height: list_height,
    };
    frame.render_widget(List::new(items).highlight_symbol("▶ "), list_area);

    // Detail pane for the current row.
    let selected = &rows[cursor];
    let detail_y = inner.y + list_height + 1;
    let detail_height = outer.y + outer.height - 1 - detail_y;
    let detail_text = columns
        .iter()
        .enumerate()
        .map(|(k, name)| {
            let value = selected.cells.get(k).cloned().unwrap_or_default();
            format!("{name}: {}", crate::frontend::truncate(&value, 120))
        })
        .collect::<Vec<_>>()
        .join("\n");
    frame.render_widget(
        Paragraph::new(detail_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled("detail", Style::default().fg(Color::DarkGray))),
            )
            .style(Style::default().fg(Color::Gray)),
        Rect {
            x: inner.x + 1,
            y: detail_y,
            width: inner.width.saturating_sub(2),
            height: detail_height,
        },
    );

    let footer = format!(
        " {}/{}  ↑/k up ↓/j down  PageUp/PageDown  Enter select  q quit ",
        cursor + 1,
        rows.len()
    );
    frame.render_widget(
        Paragraph::new(Span::styled(footer, Style::default().fg(Color::DarkGray)))
            .alignment(Alignment::Center),
        Rect {
            x: inner.x,
            y: inner.y + inner.height - 2,
            width: inner.width,
            height: 1,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::step_cursor;

    #[test]
    fn cursor_wraps_forward() {
        assert_eq!(step_cursor(1, 0, 3), 1);
        assert_eq!(step_cursor(1, 2, 3), 0);
        assert_eq!(step_cursor(1, 5, 6), 0);
    }

    #[test]
    fn cursor_wraps_backward() {
        assert_eq!(step_cursor(-1, 0, 3), 2);
        assert_eq!(step_cursor(-1, 2, 3), 1);
        assert_eq!(step_cursor(-1, 0, 1), 0);
    }

    #[test]
    fn cursor_is_stable_for_single_item() {
        assert_eq!(step_cursor(1, 0, 1), 0);
        assert_eq!(step_cursor(-1, 0, 1), 0);
    }
}
