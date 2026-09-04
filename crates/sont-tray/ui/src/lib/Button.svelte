<!--
  Кнопка макета в трёх видах: сплошная, контурная и приглушённая.

  Отдельно — «просторная»: у кнопок, стоящих в ряду с другими, поля макетные и
  тесные, а у одиночной, вроде возврата со страницы, они читаются как
  случайный обрубок. Размер тут не украшение: одиночная кнопка сама себе
  задаёт масштаб, и подпирать её нечему.
-->
<script>
  let { variant = "solid", roomy = false, onclick, children } = $props();
</script>

<!--
  `outlined` — метка для общего правила наведения: у контурных кнопок всё тело
  и есть рамка, и обводка под курсором должна от неё отличаться. Класс не
  описан в этом файле намеренно, он живёт в общих стилях.
-->
<button
  class="btn {variant}"
  class:roomy
  class:outlined={variant !== "solid"}
  {onclick}
>{@render children?.()}</button>

<style>
  .btn {
    padding: 3px 6px;
    border: 0;
    border-radius: 3px;
    font-family: inherit;
    font-size: 9px;
    font-weight: 500;
    line-height: 100%;
    white-space: nowrap;
    cursor: pointer;
  }

  /*
   * Сплошная кнопка — плашка, а не акцентная заливка.
   *
   * В тёмной теме это одно и то же. В светлой чернильная кнопка среди белого
   * окна весит больше, чем стоящее за ней действие: «Добавить» рядом с полем
   * ввода выглядит главным, что есть на странице. Белая плашка на своей серой
   * подложке остаётся кнопкой, не притязая на большее.
   */
  .solid {
    background: var(--raised);
    color: var(--on-raised);
    /* Край нужен там, где плашка совпала с подложкой окна, — см. токен. */
    box-shadow: inset 0 0 0 0.5px var(--raised-edge);
    /* Светлое на тёмном кажется жирнее — ступень вниз выравнивает. */
    font-weight: calc(500 + var(--on-raised-weight));
  }

  .ghost {
    background: transparent;
    color: var(--fg);
    box-shadow: inset 0 0 0 0.5px rgba(var(--fg-rgb), 0.4);
  }

  .quiet {
    background: transparent;
    color: var(--dim-4);
    box-shadow: inset 0 0 0 0.5px rgba(var(--fg-rgb), 0.22);
  }

  .roomy {
    padding: 5px 9px;
    border-radius: 4px;
  }
</style>
