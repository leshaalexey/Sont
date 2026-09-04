// Словарь интерфейса.
//
// Английские строки — из макета. Русские написаны заново, а не переведены
// дословно: у макета свой тон, и калька с него читается как инструкция к
// прибору.

import { derived } from "svelte/store";
import { language } from "./daemon.js";

const DICT = {
  ru: {
    "tab.conductor": "Поведение дирижёра",
    "tab.keys": "Подписки",
    "tab.system": "Настройки приложения",

    "sec.latency": "Задержка",
    "sec.connection": "Соединение",
    "sec.ondrop": "При обрыве",
    "sec.saved": "Сохранённые ключи",
    "sec.interface": "Интерфейс",
    "sec.data": "Версии и данные",

    "autoSwitch.title": "Переходить на сервер с меньшей задержкой",
    "autoSwitch.hint": "Смена сервера рвёт все соединения, поэтому только при заметной разнице",
    "threshold.title": "Насколько новый сервер должен быть быстрее",
    "interval.title": "Как часто мерить задержку",
    "interval.hint": "Замер нужен заранее: в момент падения мерить уже поздно",

    "autoConnect.title": "Подключаться при запуске",
    "autoConnect.hint": "Служба поднимает соединение вместе с системой",
    "mode.title": "Режим",
    "mode.hint": "Туннель — весь трафик, прокси — только приложения, знающие о нём",
    "protocol.title": "Предпочитаемый протокол",
    "protocol.hint": "Если такого сервера в подписке нет, предпочтение игнорируется",
    "split.title": "Раздельное туннелирование",
    "split.hint": "Какие программы ходят мимо туннеля, а какие через него",
    "split.back": "Назад",
    "split.count": "в списке",
    "split.mode": "Правило",
    "split.off": "Выкл",
    "split.exclude": "Мимо туннеля",
    "split.include": "Только эти",
    "split.excludeHint": "Перечисленные программы идут напрямую, всё остальное — через туннель",
    "split.includeHint": "Через туннель идут только перечисленные, всё остальное — напрямую",
    "split.add": "Указать программу или сайт",
    "split.addHint": "Щёлкните по окну программы или по открытому сайту",
    "split.empty": "Список пуст — правило ни на что не влияет",
    "split.unsupported": "На этой системе ядро не умеет различать программы, правило не применится",

    "allowLan.title": "Пускать локальную сеть напрямую",
    "allowLan.hint": "Принтеры, NAS и веб-интерфейс роутера отвечают быстрее, минуя туннель",
    "attempts.title": "Попыток до смены сервера",
    "killSwitch.title": "Обрывать всё, пока туннеля нет",
    "killSwitch.hint": "Обрыв соединения не выпустит трафик наружу: пока связь восстанавливается, из машины не уходит ничего. Жёсткий режим держит запрет и после падения демона — снять его можно командой sontd firewall reset",
    "fw.off": "Выкл",
    "fw.auto": "Обычный",
    "fw.lockdown": "Жёсткий",

    "traffic.title": "Трафик за период",
    "key.placeholder": "Ссылка подписки",

    "theme.title": "Тема",
    "theme.system": "Как в системе",
    "theme.light": "Светлая",
    "theme.dark": "Тёмная",
    "accent.title": "Цвет системы",
    "accent.hint": "Плашки, вкладки и переключатели красятся тем же цветом, что выбран в параметрах Windows",
    "lang.title": "Язык",
    "dns.title": "Блокировать открытый DNS",
    "dns.hint": "Иначе резолвер провайдера видит, куда вы ходите",

    "btn.copy": "Копировать",
    "btn.copied": "Скопировано",
    "btn.refresh": "Обновить",
    "btn.close": "Закрыть",
    "btn.add": "Добавить",
    "btn.logs": "Журналы",
    "btn.check": "Замерить",
    "btn.quit": "Выход",
    "btn.remove": "Убрать",

    "state.connected": "Подключено",
    "state.connecting": "Подключаюсь",
    "state.reconnecting": "Восстанавливаю",
    "state.disconnecting": "Отключаюсь",
    "state.disconnected": "Отключено",
    "state.failed": "Разорвано",

    "msg.added": "Подписка добавлена",
    "msg.removed": "Подписка удалена",
    "msg.none": "—",
    "msg.unlimited": "без лимита",
    "msg.forever": "бессрочно",
    "msg.keys": "ключей",
    "msg.noKeys": "Подписок нет — вставьте ссылку ниже",
  },

  en: {
    "tab.conductor": "Conductor behaviour",
    "tab.keys": "Subscriptions manager",
    "tab.system": "Application settings",

    "sec.latency": "Latency",
    "sec.connection": "Connection",
    "sec.ondrop": "On disconnect",
    "sec.saved": "Saved keys",
    "sec.interface": "Interface",
    "sec.data": "Versions & data",

    "autoSwitch.title": "Switch to a server with lower latency",
    "autoSwitch.hint": "Switching drops every open connection, so only when the gain is real",
    "threshold.title": "Ping difference value",
    "interval.title": "Ping check interval",
    "interval.hint": "Measured in advance — once a server drops it is too late to measure",

    "autoConnect.title": "Open the tunnel on launch",
    "autoConnect.hint": "The service connects as soon as the system starts",
    "mode.title": "Mode",
    "mode.hint": "Tunnel covers everything, proxy only apps that read the setting",
    "protocol.title": "Preferred protocol",
    "protocol.hint": "Ignored when the subscription has no such server",
    "split.title": "Split tunnelling",
    "split.hint": "Which apps go around the tunnel and which go through it",
    "split.back": "Back",
    "split.count": "listed",
    "split.mode": "Rule",
    "split.off": "Off",
    "split.exclude": "Around it",
    "split.include": "Only these",
    "split.excludeHint": "Listed apps go direct, everything else goes through the tunnel",
    "split.includeHint": "Only the listed apps go through the tunnel, everything else goes direct",
    "split.add": "Point at an app or a site",
    "split.addHint": "Click an app window, or a site open in a browser",
    "split.empty": "The list is empty — the rule does nothing",
    "split.unsupported": "On this system the core cannot tell apps apart, the rule will not apply",

    "allowLan.title": "Send local traffic direct",
    "allowLan.hint": "Printers, NAS and the router page answer faster, skipping the tunnel",
    "attempts.title": "Retry attempts",
    "killSwitch.title": "Cut everything while the tunnel is down",
    "killSwitch.hint": "A dropped link no longer leaks: nothing leaves the machine while it is being restored. Lockdown holds the block even if the daemon dies — lift it with sontd firewall reset",
    "fw.off": "Off",
    "fw.auto": "Auto",
    "fw.lockdown": "Lockdown",

    "traffic.title": "Traffic this period",
    "key.placeholder": "Paste a subscription link",

    "theme.title": "Theme",
    "theme.system": "System",
    "theme.light": "Light",
    "theme.dark": "Dark",
    "accent.title": "System colour",
    "accent.hint": "Pills, tabs and switches take the accent colour chosen in Windows settings",
    "lang.title": "Language",
    "dns.title": "Block plain DNS",
    "dns.hint": "Otherwise your provider's resolver sees where you go",

    "btn.copy": "Copy",
    "btn.copied": "Copied",
    "btn.refresh": "Refresh",
    "btn.close": "Close",
    "btn.add": "Add key",
    "btn.logs": "Open logs folder",
    "btn.check": "Check now",
    "btn.quit": "Quit Sont",
    "btn.remove": "Remove",

    "state.connected": "Tunnel up",
    "state.connecting": "Connecting",
    "state.reconnecting": "Reconnecting",
    "state.disconnecting": "Disconnecting",
    "state.disconnected": "Tunnel down",
    "state.failed": "Dropped",

    "msg.added": "Subscription added",
    "msg.removed": "Subscription removed",
    "msg.none": "—",
    "msg.unlimited": "unlimited",
    "msg.forever": "no expiry",
    "msg.keys": "keys",
    "msg.noKeys": "No subscriptions — paste a link below",
  },
};

/** Переводчик, меняющийся вместе с настройкой языка. */
export const t = derived(language, ($lang) => {
  const table = DICT[$lang] ?? DICT.ru;
  return (key) => table[key] ?? DICT.ru[key] ?? key;
});
