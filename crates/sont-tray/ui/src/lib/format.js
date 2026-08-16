// Форматирование чисел и сроков для шапки и списка ключей.

/** «6 d 04:11» из макета: сколько подписке осталось жить. */
export function remaining(expiresAtUnix, forever = "—") {
  if (!expiresAtUnix) return forever;

  const left = expiresAtUnix * 1000 - Date.now();
  if (left <= 0) return "0:00";

  const days = Math.floor(left / 86400_000);
  const hours = Math.floor((left % 86400_000) / 3600_000);
  const minutes = Math.floor((left % 3600_000) / 60_000);
  // Не `clock` — так зовётся функция выше, и локальная переменная с тем же
  // именем закрыла бы её на всю область видимости.
  const hm = `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;

  return days > 0 ? `${days} d ${hm}` : hm;
}

export function bytes(value) {
  if (value == null) return "—";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = value;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit += 1;
  }

  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[unit]}`;
}

/** Доля израсходованного трафика, 0…100. */
export function usedPercent(info) {
  const total = info?.total ?? 0;
  if (total <= 0) return null;

  const used = (info.upload ?? 0) + (info.download ?? 0);
  return Math.min(100, Math.round((used / total) * 100));
}
