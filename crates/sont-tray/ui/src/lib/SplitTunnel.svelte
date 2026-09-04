<!--
  Отдельная страница раздельного туннелирования.

  Страница, а не всплывающий список: правило состоит из режима и списка путей,
  и список растёт. Втиснуть его в строку настроек значило бы получить строку
  переменной высоты, распирающую соседние.

  Живёт внутри вкладки дирижёра — там же, откуда сюда приходят. Возврат
  кнопкой в шапке, а не переключением вкладки: вкладка не менялась.
-->
<script>
  import Section from "./Section.svelte";
  import Row from "./Row.svelte";
  import Segmented from "./Segmented.svelte";
  import Button from "./Button.svelte";
  import { settings, patch, ask } from "./daemon.js";
  import { t } from "./i18n.js";

  let { onback } = $props();

  const MODES = $derived([
    { value: "off", label: $t("split.off") },
    { value: "exclude", label: $t("split.exclude") },
    { value: "include", label: $t("split.include") },
  ]);

  const rules = $derived($settings?.split_tunnel ?? { mode: "off", apps: [], sites: [] });
  const apps = $derived(rules.apps ?? []);
  const sites = $derived(rules.sites ?? []);

  /*
   * Программы и сайты в одном списке.
   *
   * Для ядра это разные правила — по имени процесса и по домену, — но для
   * человека список один: «что ходит мимо туннеля». Разводить их по двум
   * разделам значило бы заставлять помнить, в каком из них искать.
   */
  const entries = $derived([
    ...sites.map((host) => ({ key: `site:${host}`, kind: "site", title: host, detail: host })),
    ...apps.map((path) => ({ key: `app:${path}`, kind: "app", title: name(path), detail: path })),
  ]);

  // Пояснение зависит от режима: «мимо туннеля» и «только эти» — правила
  // противоположные, и одна общая фраза не описывает ни одно из них.
  const hint = $derived(
    rules.mode === "include"
      ? $t("split.includeHint")
      : rules.mode === "exclude"
        ? $t("split.excludeHint")
        : $t("split.hint"),
  );

  /** Имя файла без пути: путь целиком в строку не влезает и не нужен. */
  function name(path) {
    return path.split(/[\\/]/).pop() || path;
  }

  function save(next) {
    patch({ split_tunnel: { ...rules, ...next } });
  }

  /**
   * Программа указывается тычком в её окно, а не поиском файла.
   *
   * Окно на это время прячется и возвращается само — этим занимается
   * команда на стороне Rust: она же меняет курсор и ждёт щелчка.
   */
  async function add() {
    const picked = await ask("pick_app_by_click");
    if (!picked) return;

    /*
     * Первая запись включает правило.
     *
     * При выключенном правиле список ни на что не влияет: демон считает такую
     * настройку неактивной и не пишет её в конфигурацию ядра вовсе. Дать
     * пополнять список, который ничего не делает, и промолчать об этом —
     * ловушка: человек добавляет сайт в исключения, видит его в списке и
     * получает тот же туннель, не понимая почему.
     *
     * Включаем «мимо туннеля»: это то, за чем сюда приходят в девяти случаях
     * из десяти, и ровно то слово, которым это называют, — «исключения».
     */
    const mode = rules.mode === "off" ? "exclude" : rules.mode;

    // Повторы отбрасываем: одно и то же в списке дважды ничего не меняет в
    // правиле, но делает список нечитаемым.
    if (picked.kind === "site") {
      save({ mode, sites: [...new Set([...sites, picked.host])] });
    } else if (picked.path) {
      save({ mode, apps: [...new Set([...apps, picked.path])] });
    }
  }

  function drop(entry) {
    if (entry.kind === "site") {
      save({ sites: sites.filter((s) => s !== entry.detail) });
    } else {
      save({ apps: apps.filter((a) => a !== entry.detail) });
    }
  }
</script>

<header class="head">
  <Button variant="ghost" roomy onclick={onback}>{$t("split.back")}</Button>
  <h2>{$t("split.title")}</h2>
</header>

<Row title={$t("split.mode")} {hint}>
  <Segmented options={MODES} value={rules.mode} onselect={(v) => save({ mode: v })} />
</Row>

<Section title={$t("sec.saved")} aside={entries.length > 0 ? String(entries.length) : null} />

{#if entries.length === 0}
  <p class="empty">{$t("split.empty")}</p>
{:else}
  <div class="list">
    {#each entries as entry (entry.key)}
      <div class="item">
        <span class="text">
          <span class="name">{entry.title}</span>
          <!-- У сайта имя и адрес совпадают — второй строкой её не дублируем. -->
          {#if entry.detail !== entry.title}<span class="path">{entry.detail}</span>{/if}
        </span>
        <button class="drop outlined" onclick={() => drop(entry)}>{$t("btn.remove")}</button>
      </div>
    {/each}
  </div>
{/if}

<div class="add">
  <Button onclick={add}>{$t("split.add")}</Button>
</div>
<p class="addHint">{$t("split.addHint")}</p>

<style>
  /*
   * Шапка живёт в обычных полях страницы, как всё остальное, и отделена от
   * содержимого волосяной линией — тем же приёмом, которым разделены разделы
   * настроек. Иначе заголовок страницы висел бы над списком сам по себе.
   *
   * Выравнивание по базовой линии, а не по центру: у кнопки есть рамка, у
   * заголовка нет, и по центру они совпадали коробками, а не буквами — глаз
   * же считает строкой именно буквы.
   */
  .head {
    display: flex;
    align-items: baseline;
    gap: 9px;
    padding: 2px 0 10px;
    margin-bottom: 12px;
    border-bottom: 1px solid var(--line-weak);
  }

  h2 {
    margin: 0;
    font-size: 10px;
    font-weight: 500;
    line-height: 125%;
    color: var(--fg);
  }

  .empty {
    margin: 4px 0 0;
    font-size: 9px;
    font-weight: 350;
    line-height: 130%;
    color: var(--dim-4);
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    border: 0.5px solid var(--line-strong);
    border-radius: 5px;
    padding: 7px 7px 7px 9px;
  }

  .text {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
    min-width: 0;
  }

  .name {
    font-size: 9px;
    font-weight: 500;
    line-height: 125%;
    color: var(--fg);
  }

  /* Путь целиком не влезает, и обрезать его надо с начала: различаются такие
     пути хвостом, а не общим для всех «C:\Program Files». */
  .path {
    direction: rtl;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 7px;
    font-weight: 350;
    line-height: 125%;
    color: rgba(var(--fg-rgb), 0.45);
  }

  .drop {
    flex: none;
    padding: 4px 6px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    box-shadow: inset 0 0 0 0.5px rgba(var(--fg-rgb), 0.4);
    color: var(--dim-1);
    font-family: inherit;
    font-size: 8px;
    font-weight: 500;
    line-height: 100%;
    white-space: nowrap;
    cursor: pointer;
  }

  .add {
    display: flex;
    padding-top: 10px;
  }

  .addHint {
    margin: 6px 0 0;
    font-size: 7px;
    font-weight: 350;
    line-height: 135%;
    color: var(--dim-4);
    text-wrap: pretty;
  }
</style>
