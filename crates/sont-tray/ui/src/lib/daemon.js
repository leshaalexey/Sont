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
    reconnect_attempts: 3,
    allow_lan: true,
    firewall: "auto",
    preferred_transports: [],
    language: "ru",
    system_accent: false,
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
    root.style.removeProperty("--accent");
    root.style.removeProperty("--on-accent");
    root.style.removeProperty("--on-accent-weight");
    return;
  }

  const on = readableOn(hex);
  root.style.setProperty("--accent", hex);
  root.style.setProperty("--on-accent", on);

  /*
   * Светлая надпись на тёмной заливке кажется жирнее тёмной на светлой при
   * одном и том же начертании: светлое пятно на тёмном фоне «растекается» —
   * иррадиация. Компенсируем ступенью начертания вниз, чтобы обе выглядели
   * одинаково плотными. Величина не выведена формулой, а подобрана: пятьдесят
   * — одна ступень переменной оси Segoe UI Variable.
   */
  const light = on !== DARK_TEXT;
  root.style.setProperty("--on-accent-weight", light ? "-50" : "0");
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
  await refresh();
  if (listen) await listen("sont://event", refresh);
}
