// Связь с демоном и всё состояние окна.
//
// Своего состояния у окна нет: оно спрашивает демон и рисует ответ. Это
// инвариант проекта — истина живёт в демоне. Любая попытка запомнить здесь
// положение переключателя даёт окно, которое расходится с действительностью
// после первой же команды из CLI.

import { writable, derived } from "svelte/store";

const invoke = window.__TAURI__?.core?.invoke;
const listen = window.__TAURI__?.event?.listen;

/** Образец для просмотра в браузере, без Tauri: `npm run dev`. */
const PREVIEW = {
  status: {
    // `kind` — плоский дискриминант состояния, его добавляет команда `status`
    // на стороне Rust: в самом снимке состояние лежит под тегом `state`.
    kind: "connected",
    state: {
      state: "connected",
      since_unix_ms: Date.now() - (5 * 86400 + 23 * 3600 + 59 * 60 + 30) * 1000,
    },
    server_name: "🇳🇱 Netherlands, Amsterdam #3",
    rtt_ms: 25,
    // Подписок две: переключение между ключами на одном ключе не проверяется
    // никак, а именно оно тут и разложено.
    subscriptions: [
      {
        id: "8f2a",
        masked_url: "htt…8f2a",
        info: {
          server_count: 12,
          upload: 5e9,
          download: 20e9,
          total: 100e9,
          expires_at_unix: Math.floor(Date.now() / 1000) + 6 * 86400,
        },
      },
      {
        id: "c41b",
        masked_url: "htt…c41b",
        info: {
          server_count: 4,
          upload: 1e9,
          download: 2e9,
          total: 0,
          expires_at_unix: Math.floor(Date.now() / 1000) + 40 * 86400,
        },
      },
    ],
    server_count: 12,
  },
  settings: {
    mode: "tunnel",
    auto_connect: true,
    tray_autostart: true,
    auto_select_server: true,
    probe_interval_secs: 60,
    auto_switch: true,
    switch_threshold_ms: 30,
    allow_lan: true,
    firewall: "auto",
    preferred_transports: [],
    language: "ru",
    system_accent: false,
    theme: "system",
    dns: { mode: "tunnel", block_plain_dns: true, fake_ip: false },
    split_tunnel: { mode: "off", apps: [], sites: [] },
  },
  info: { daemon_version: "0.1.0", protocol_version: 4, core_version: "Xray 26.3.27" },
};

export const status = writable(null);
export const settings = writable(null);
export const info = writable(null);
export const notice = writable(null);

/** Язык интерфейса берётся из настроек демона: CLI и окно говорят одинаково. */
export const language = derived(settings, ($s) => $s?.language ?? "ru");

/**
 * Что писать поверх акцентной заливки: тёмное или светлое.
 *
 * Цвет системы у пользователя бывает любым — от почти белого до почти
 * чёрного, — и одна и та же надпись поверх него то читается, то нет. Порог
 * взят по относительной яркости из WCAG: выше — кладём тёмный текст, ниже —
 * светлый.
 */
const DARK_TEXT = "rgb(33, 33, 33)";
const LIGHT_TEXT = "rgb(244, 237, 229)";

function readableOn(hex) {
  const channel = (i) => {
    const v = parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  const luminance = 0.2126 * channel(0) + 0.7152 * channel(1) + 0.0722 * channel(2);
  return luminance > 0.4 ? DARK_TEXT : LIGHT_TEXT;
}

/**
 * Красит акцентные элементы цветом системы — или возвращает свой.
 *
 * Цвет спрашивается у системы при каждом применении, а не запоминается:
 * пользователь может сменить его в параметрах Windows, не трогая окно, и
 * запомненное значение осталось бы висеть до перезапуска приложения.
 */
export async function applyAccent(enabled) {
  const root = document.documentElement;
  const hex = enabled ? await call("system_accent") : null;

  // Не вышло узнать цвет — остаёмся при своём. Подставлять «примерно такой
  // же синий» хуже, чем не менять ничего: пользователь включил настройку и
  // увидел бы цвет, которого в системе нет.
  if (!hex) {
    for (const name of ACCENTED) root.style.removeProperty(name);
    return;
  }

  const on = readableOn(hex);
  root.style.setProperty("--accent", hex);
  root.style.setProperty("--on-accent", on);

  /*
   * Плашки и маскот красятся заодно — иначе настройка перестала бы делать то,
   * что обещает подписью под ней.
   *
   * В тёмной теме они и так повторяют акцент, а вот в светлой по умолчанию
   * расходятся с ним: там плашка остаётся белой, чтобы не спорить с полосой
   * под собой. Включённый цвет системы возвращает их к акценту.
   */
  root.style.setProperty("--raised", hex);
  root.style.setProperty("--on-raised", on);
  root.style.setProperty("--mascot", hex);
  // Закрашенной плашке край не нужен: её и так видно.
  root.style.setProperty("--raised-edge", "transparent");

  /*
   * Светлая надпись на тёмной заливке кажется жирнее тёмной на светлой при
   * одном и том же начертании: светлое пятно на тёмном фоне «растекается» —
   * иррадиация. Компенсируем ступенью начертания вниз, чтобы обе выглядели
   * одинаково плотными. Величина не выведена формулой, а подобрана: пятьдесят
   * — одна ступень переменной оси Segoe UI Variable.
   */
  const light = on !== DARK_TEXT;
  root.style.setProperty("--on-accent-weight", light ? "-50" : "0");
  root.style.setProperty("--on-raised-weight", light ? "-50" : "0");
}

/**
 * Всё, что подменяет цвет системы.
 *
 * Списком, а не перечислением по месту: снимать надо ровно то, что ставилось,
 * и разъедься эти два набора — выключенная настройка оставила бы половину окна
 * покрашенной, причём в теме, которую забыли открыть.
 */
const ACCENTED = [
  "--accent",
  "--on-accent",
  "--on-accent-weight",
  "--raised",
  "--on-raised",
  "--on-raised-weight",
  "--mascot",
  "--raised-edge",
];

/**
 * Ставит тему окна: светлую, тёмную или ту, что выбрана в системе.
 *
 * «Как в системе» разрешается здесь, а не в CSS, и берётся из параметров
 * Windows, а не у движка.
 *
 * Причина в том, что это разные настройки. Медиазапрос `prefers-color-scheme`
 * отвечает по теме окон приложений, а окно Sont стоит в ряду с панелью задач и
 * равняется на неё — у Windows это отдельное значение, и «тёмная система со
 * светлыми окнами» ставится в ней одним щелчком. Спрашиваем реестр, к
 * медиазапросу обращаемся только там, где спросить некого: в браузере
 * предпросмотра и на системах без такого понятия.
 */
export async function applyTheme(theme) {
  const resolved =
    theme === "light" || theme === "dark" ? theme : (await call("system_theme")) ?? preferred();

  document.documentElement.dataset.theme = resolved;
}

/** Что считает светлой темой сам движок. Запасной ответ, когда системы нет. */
function preferred() {
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/**
 * Перечитывает тему у системы и применяет заново.
 *
 * Вызывается при показе окна — и это единственный надёжный момент. Тема панели
 * задач живёт в реестре, и её смена не поднимает `prefers-color-scheme`:
 * медиазапрос следит за темой окон приложений, то есть за соседним значением.
 * Опрашивать реестр постоянно незачем — окно трея живёт секунды, и спросить
 * достаточно тогда, когда его открывают.
 */
export async function resyncTheme() {
  let chosen;
  settings.subscribe((s) => (chosen = s?.theme))();
  // Явный выбор пользователя перечитывать не надо: он не в системе, а в
  // настройках демона, и сам собой не меняется.
  if (!chosen || chosen === "system") await applyTheme("system");
}

/**
 * Следит за сменой темы системы, пока окно открыто.
 *
 * Ловит случай, когда пользователь меняет оформление, не закрывая окно.
 * Медиазапрос здесь — не источник значения, а только сигнал «пора спросить
 * заново»: сработает он лишь на смене темы приложений, но её обычно переключают
 * вместе с темой Windows.
 */
function watchSystemTheme() {
  const media = window.matchMedia?.("(prefers-color-scheme: light)");
  media?.addEventListener?.("change", resyncTheme);
}

let previewPick = false;
let noticeTimer;

/** Показывает короткое сообщение внизу окна. */
export function say(text, isError = false) {
  notice.set({ text, isError });
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => notice.set(null), 2600);
}

async function call(command, args) {
  if (!invoke) {
    if (command === "status") return structuredClone(PREVIEW.status);
    if (command === "settings") return structuredClone(PREVIEW.settings);
    // Патч в предпросмотре применяется по-настоящему, иначе переключатель
    // возвращается обратно и проверить его нечем.
    if (command === "patch") {
      Object.assign(PREVIEW.settings, args?.patch ?? {});
      return structuredClone(PREVIEW.settings);
    }
    if (command === "daemon_info") return structuredClone(PREVIEW.info);
    if (command === "reveal_subscription") return "https://panel.example/sub/DEMO";
    // В браузере системного цвета нет — берём узнаваемый синий Windows,
    // чтобы настройку было на чём проверить.
    if (command === "system_accent") return "#0078D4";
    // Своей системы у браузера предпросмотра нет: пусть тема решается
    // медиазапросом, как она решается на системах без такого понятия.
    if (command === "system_theme") return null;
    // В предпросмотре чередуем: первый выбор — сайт, второй — программа.
    if (command === "pick_app_by_click") {
      previewPick = !previewPick;
      return previewPick
        ? { kind: "site", host: "bank.example", url: "https://bank.example/login" }
        : {
            kind: "app",
            path: "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            name: "firefox.exe",
          };
    }
    return null;
  }
  return invoke(command, args);
}

export async function refresh() {
  try {
    const [s, cfg, i] = await Promise.all([
      call("status"),
      call("settings"),
      call("daemon_info"),
    ]);
    status.set(s);
    settings.set(cfg);
    info.set(i);
    await applyAccent(cfg?.system_accent);
    await applyTheme(cfg?.theme);
  } catch (e) {
    status.set(null);
    say(String(e), true);
  }
}

/** Отправляет частичное изменение настроек и принимает ответ как истину. */
export async function patch(fields) {
  try {
    const updated = await call("patch", { patch: fields });
    settings.set(updated);
    await applyAccent(updated?.system_accent);
    await applyTheme(updated?.theme);
  } catch (e) {
    say(String(e), true);
  }
}

/** Вызов команды с последующим обновлением состояния. */
export async function act(command, args) {
  try {
    const result = await call(command, args);
    await refresh();
    return result;
  } catch (e) {
    say(String(e), true);
    return null;
  }
}

export const ask = call;

/** Подписывается на события демона и делает первое чтение. */
export async function start() {
  watchSystemTheme();
  await refresh();
  if (listen) await listen("sont://event", refresh);
}
