<!--
  Панель вкладок. Активная растягивается и показывает название, остальные
  сжимаются до иконки — как в макете.
-->
<script>
  import MascotIdle from "./MascotIdle.svelte";
  import IconKey from "./IconKey.svelte";
  import IconSettings from "./IconSettings.svelte";
  import { t } from "./i18n.js";

  let { active = "conductor", onselect } = $props();

  const TABS = [
    { id: "conductor", label: "tab.conductor", icon: MascotIdle },
    { id: "keys", label: "tab.keys", icon: IconKey },
    { id: "system", label: "tab.system", icon: IconSettings },
  ];
</script>

<nav class="tabs">
  {#each TABS as tab (tab.id)}
    {@const Icon = tab.icon}
    <button class="tab" class:active={tab.id === active} onclick={() => onselect?.(tab.id)}>
      <span class="icon"><Icon /></span>
      {#if tab.id === active}<span class="label">{$t(tab.label)}</span>{/if}
    </button>
  {/each}
</nav>

<style>
  .tabs {
    position: absolute;
    left: 6px;
    right: 6px;
    top: 6px;
    height: 24px;
    border-radius: 6px;
    background: var(--bg-sunken);
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 3px;
    /*
     * Рамка постоянная, и её наличие решает тема — см. `--sunken-edge`.
     *
     * На наведение панель не отвечает вовсе. Отвечать ей нечем: обводку вокруг
     * отдельной вкладки рисовать негде — кнопка в 18 точек лежит в полосе
     * 24-х, — а подсветка всей панели превращалась в мигание, которое идёт
     * вдогонку курсору, перебегающему с вкладки на вкладку. Вкладки и так
     * читаются как вкладки: активная закрашена, остальные нет.
     */
    box-shadow: inset 0 0 0 0.5px var(--sunken-edge);
  }

  /*
   * Растягивается вкладка через `flex-grow`, а не через сокращение `flex`.
   *
   * Сокращение переключало заодно и `flex-basis` — с `auto` на нуль, а между
   * ними браузеру нечего интерполировать. Переход то срабатывал, то замирал
   * на полпути, и при быстром щёлканье по вкладкам панель оставалась с двумя
   * растянутыми кнопками сразу: сумма ширин переставала помещаться в строку.
   * `flex-grow` — обычное число, оно интерполируется всегда.
   */
  .tab {
    position: relative;
    flex: 0 0 auto;
    width: 21px;
    height: 18px;
    padding: 0;
    border: 0;
    border-radius: 4px;
    background: var(--raised);
    color: var(--on-raised);
    font-family: inherit;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    transition: flex-grow 180ms var(--ease);
  }

  .active {
    flex-grow: 1;
    cursor: default;
  }

  /*
   * У свёрнутой вкладки значок стоит по центру: кнопка 18 точек шириной,
   * значок 10, и прижатый к левому краю он выглядел съехавшим.
   *
   * У развёрнутой он прижимается влево — там рядом название, и центрировать
   * его вместе с текстом означало бы двигать значок при каждой смене языка.
   */
  /* Цвет значок берёт у кнопки — тот же `--on-raised`, что и подпись рядом. */
  .icon {
    display: flex;
  }
  .active .icon {
    position: absolute;
    left: 8px;
  }

  .label {
    font-size: 10px;
    /* Светлое на тёмном кажется жирнее — ступень вниз выравнивает. */
    font-weight: calc(500 + var(--on-raised-weight));
    line-height: 120%;
  }
</style>
