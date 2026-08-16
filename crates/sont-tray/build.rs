//! Сборка окна: фронтенд, иконки и Tauri.
//!
//! Фронтенд собирается отсюда намеренно. Иначе команд становится две — `npm
//! run build` и `cargo build`, — и рано или поздно кто-нибудь соберёт бинарь
//! со вчерашней разметкой и полдня будет искать несуществующую ошибку. Одна
//! команда, `cargo app`, делает всё.
//!
//! Иконки выводятся из тех же `assets/idle.svg` и `assets/offline.svg`, что
//! рисует дизайнер: и `.ico` для окна, и растр для трея. Правка SVG меняет
//! обе — расходиться им неоткуда.
//!
//! Адреса сервера разработки в `tauri.conf.json` нет намеренно. Стоял бы он
//! там — отладочная сборка предпочла бы его готовым файлам, и запущенное без
//! `vite` окно показывало бы «localhost отказано в подключении» вместо
//! интерфейса. Фронтенд собирается здесь, окно всегда берёт собранное.

use std::path::{Path, PathBuf};
use std::process::Command;

mod pixels {
    //! Разбор пиксельного SVG и растеризация без сглаживания.
    //!
    //! Обе иконки нарисованы прямоугольниками по целым координатам. Такую
    //! графику нельзя масштабировать интерполяцией: именно она превращает
    //! чёткие пиксели в мыло. Здесь только целые множители и выборка
    //! «ближайшего», а при уменьшении — объединение: если в исходную клетку
    //! попал хоть один закрашенный пиксель, закрашивается и результат. Так
    //! силуэт остаётся читаемым даже в 16 пикселей.

    /// Пиксельный рисунок: маска закрашенных клеток.
    pub struct Art {
        pub width: u32,
        pub height: u32,
        pub lit: Vec<bool>,
    }

    impl Art {
        fn at(&self, x: u32, y: u32) -> bool {
            self.lit[(y * self.width + x) as usize]
        }

        /// Обрезает пустые поля вокруг рисунка.
        ///
        /// # Зачем
        ///
        /// В `idle.svg` рисунок начинается с шестой строки: сверху пять
        /// пустых. Холст размечен по `viewBox`, поэтому центрирование считало
        /// эту пустоту частью рисунка — и маскот в трее сидел заметно ниже
        /// середины, рядом с чужими значками это бросалось в глаза.
        ///
        /// Границы полей — дело художника и меняются при каждой правке SVG.
        /// Считать их по факту надёжнее, чем договариваться о них.
        fn trimmed(self) -> Art {
            let (mut x0, mut y0) = (self.width, self.height);
            let (mut x1, mut y1) = (0u32, 0u32);

            for y in 0..self.height {
                for x in 0..self.width {
                    if !self.at(x, y) {
                        continue;
                    }
                    x0 = x0.min(x);
                    y0 = y0.min(y);
                    x1 = x1.max(x + 1);
                    y1 = y1.max(y + 1);
                }
            }

            // Пустой рисунок обрезать не во что — отдаём как есть.
            if x1 <= x0 || y1 <= y0 {
                return self;
            }

            let (width, height) = (x1 - x0, y1 - y0);
            let mut lit = Vec::with_capacity((width * height) as usize);
            for y in y0..y1 {
                for x in x0..x1 {
                    lit.push(self.at(x, y));
                }
            }

            Art { width, height, lit }
        }

        /// Растеризует в квадрат `size`×`size` с прозрачным фоном.
        pub fn rasterize(&self, size: u32) -> Vec<bool> {
            let mut out = vec![false; (size * size) as usize];

            let fits = size / self.width.max(1) >= 1 && size / self.height.max(1) >= 1;
            if fits {
                // Увеличение: только целый множитель, рисунок по центру.
                let k = (size / self.width).min(size / self.height);
                let ox = (size - self.width * k) / 2;
                let oy = (size - self.height * k) / 2;

                for y in 0..self.height {
                    for x in 0..self.width {
                        if !self.at(x, y) {
                            continue;
                        }
                        for dy in 0..k {
                            for dx in 0..k {
                                let px = ox + x * k + dx;
                                let py = oy + y * k + dy;
                                out[(py * size + px) as usize] = true;
                            }
                        }
                    }
                }
                return out;
            }

            // Уменьшение: рисунок шире холста. Усреднение дало бы серую кашу,
            // поэтому берём объединение — тонкие линии не пропадают.
            let scale = (size as f32 / self.width.max(self.height) as f32).min(1.0);
            let w = ((self.width as f32 * scale).round() as u32).max(1);
            let h = ((self.height as f32 * scale).round() as u32).max(1);
            let ox = (size - w) / 2;
            let oy = (size - h) / 2;

            for dy in 0..h {
                for dx in 0..w {
                    let sx0 = dx * self.width / w;
                    let sx1 = (((dx + 1) * self.width) / w).max(sx0 + 1).min(self.width);
                    let sy0 = dy * self.height / h;
                    let sy1 = (((dy + 1) * self.height) / h).max(sy0 + 1).min(self.height);

                    let mut lit = false;
                    for sy in sy0..sy1 {
                        for sx in sx0..sx1 {
                            lit |= self.at(sx, sy);
                        }
                    }
                    if lit {
                        out[((oy + dy) * size + ox + dx) as usize] = true;
                    }
                }
            }

            out
        }
    }

    /// Читает SVG, состоящий из прямоугольных путей вида `M11 5H4V6H11V5Z`.
    pub fn parse(source: &str) -> Art {
        let (width, height) = viewbox(source);
        let mut lit = vec![false; (width * height) as usize];

        for path in source.split("<path d=\"").skip(1) {
            let d = path.split('"').next().unwrap_or_default();
            let Some((x, y, w, h)) = rect(d) else {
                continue;
            };
            for py in y..(y + h).min(height) {
                for px in x..(x + w).min(width) {
                    lit[(py * width + px) as usize] = true;
                }
            }
        }

        Art { width, height, lit }.trimmed()
    }

    fn viewbox(source: &str) -> (u32, u32) {
        let raw = source
            .split("viewBox=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("0 0 16 16");

        let mut parts = raw.split_whitespace().skip(2).filter_map(|n| n.parse().ok());
        (parts.next().unwrap_or(16), parts.next().unwrap_or(16))
    }

    /// Достаёт прямоугольник из пути. `None` — путь не прямоугольный.
    fn rect(d: &str) -> Option<(u32, u32, u32, u32)> {
        let numbers: Vec<i64> = d
            .split(|c: char| !c.is_ascii_digit() && c != '-')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();

        // M x y H x2 V y2 H x3 V y3 Z — шесть чисел до замыкания.
        if numbers.len() < 4 {
            return None;
        }
        let (x_a, y_a, x_b, y_b) = (numbers[0], numbers[1], numbers[2], numbers[3]);

        let x = x_a.min(x_b).max(0) as u32;
        let y = y_a.min(y_b).max(0) as u32;
        let w = (x_a - x_b).unsigned_abs() as u32;
        let h = (y_b - y_a).unsigned_abs() as u32;

        (w > 0 && h > 0).then_some((x, y, w, h))
    }
}

mod ico {
    //! Сборка многоразмерного `.ico`.
    //!
    //! Размеров несколько не для красоты: оболочка просит 16 и 32 для панели
    //! задач, 48 и больше для проводника. Один размер она масштабирует сама —
    //! интерполяцией, то есть в мыло.

    use super::pixels::Art;

    /// Цвет рисунка — тот же кремовый, что и в макете.
    const COLOR: [u8; 3] = [244, 237, 229];

    pub fn build(art: &Art, sizes: &[u32]) -> Vec<u8> {
        let images: Vec<Vec<u8>> = sizes.iter().map(|&s| bitmap(art, s)).collect();

        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes()); // зарезервировано
        out.extend_from_slice(&1u16.to_le_bytes()); // тип: иконка
        out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());

        let mut offset = 6 + 16 * sizes.len() as u32;
        for (&size, image) in sizes.iter().zip(&images) {
            // 256 записывается нулём — так устроен формат.
            out.push(if size >= 256 { 0 } else { size as u8 });
            out.push(if size >= 256 { 0 } else { size as u8 });
            out.push(0); // палитры нет
            out.push(0);
            out.extend_from_slice(&1u16.to_le_bytes()); // плоскостей
            out.extend_from_slice(&32u16.to_le_bytes()); // бит на пиксель
            out.extend_from_slice(&(image.len() as u32).to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            offset += image.len() as u32;
        }

        for image in images {
            out.extend_from_slice(&image);
        }
        out
    }

    /// Одно изображение: заголовок, пиксели снизу вверх и пустая маска.
    fn bitmap(art: &Art, size: u32) -> Vec<u8> {
        let lit = art.rasterize(size);

        let mut out = Vec::with_capacity((40 + size * size * 4 + size * 4) as usize);
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&(size as i32).to_le_bytes());
        // Высота удвоена: формат ждёт цвет и маску одной картинкой.
        out.extend_from_slice(&((size * 2) as i32).to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // без сжатия
        out.extend_from_slice(&(size * size * 4).to_le_bytes());
        out.extend_from_slice(&[0; 16]); // разрешение и палитра

        for y in (0..size).rev() {
            for x in 0..size {
                let on = lit[(y * size + x) as usize];
                out.extend_from_slice(&[COLOR[2], COLOR[1], COLOR[0], if on { 255 } else { 0 }]);
            }
        }

        // Маска прозрачности не нужна — она задана альфа-каналом, — но место
        // под неё формат требует.
        out.extend_from_slice(&vec![0u8; (size * 4) as usize]);
        out
    }
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ui = root.join("ui");
    let assets = ui.join("assets");

    println!("cargo:rerun-if-changed={}", ui.join("src").display());
    println!("cargo:rerun-if-changed={}", ui.join("index.html").display());
    println!("cargo:rerun-if-changed={}", ui.join("package.json").display());
    println!("cargo:rerun-if-changed={}", ui.join("vite.config.js").display());
    println!("cargo:rerun-if-changed={}", assets.join("idle.svg").display());
    println!("cargo:rerun-if-changed={}", assets.join("offline.svg").display());

    let idle = read_art(&assets.join("idle.svg"));
    let offline = read_art(&assets.join("offline.svg"));

    write_icon(&root, &idle);
    write_art_source(&idle, &offline);

    build_frontend(&ui);
    tauri_build::build();
}

fn read_art(path: &Path) -> pixels::Art {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("не удалось прочитать {}: {e}", path.display()));
    pixels::parse(&source)
}

/// Пишет `.ico` для окна и исполняемого файла.
fn write_icon(root: &Path, art: &pixels::Art) {
    let dir = root.join("icons");
    std::fs::create_dir_all(&dir).expect("не удалось создать каталог иконок");

    let data = ico::build(art, &[16, 24, 32, 48, 64, 128, 256]);
    std::fs::write(dir.join("icon.ico"), data).expect("не удалось записать icon.ico");
}

/// Отдаёт рисунки в код: трей меняет иконку на ходу, файлом это не сделать.
fn write_art_source(idle: &pixels::Art, offline: &pixels::Art) {
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("нет OUT_DIR"));

    let mut source = String::from(
        "// Создано build.rs из assets/idle.svg и assets/offline.svg.\n\
         // Правится не здесь, а в исходных SVG.\n",
    );
    for (name, art) in [("IDLE", idle), ("OFFLINE", offline)] {
        let lit = art
            .lit
            .iter()
            .map(|&on| if on { "1" } else { "0" })
            .collect::<Vec<_>>()
            .join(",");
        source.push_str(&format!(
            "const {name}: TrayArt = TrayArt {{ width: {}, height: {}, lit: &[{lit}] }};\n",
            art.width, art.height
        ));
    }

    std::fs::write(out.join("icons.rs"), source).expect("не удалось записать icons.rs");
}

fn build_frontend(ui: &Path) {
    if !ui.join("node_modules").exists() {
        run(ui, &["ci", "--no-audit", "--no-fund"])
            .or_else(|| run(ui, &["install", "--no-audit", "--no-fund"]))
            .unwrap_or_else(|| panic!("не удалось установить зависимости окна в {}", ui.display()));
    }

    run(ui, &["run", "build"])
        .unwrap_or_else(|| panic!("не удалось собрать окно в {}", ui.display()));
}

/// Запускает npm и возвращает `None`, если он отсутствует или отказал.
///
/// На Windows npm — это `npm.cmd`, и запустить его напрямую как исполняемый
/// файл нельзя: нужен интерпретатор команд.
fn run(dir: &Path, args: &[&str]) -> Option<()> {
    let mut command = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/c").arg("npm");
        c
    } else {
        Command::new("npm")
    };

    let status = command.args(args).current_dir(dir).status().ok()?;
    status.success().then_some(())
}
