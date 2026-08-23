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

<button class="btn {variant}" class:roomy {onclick}>{@render children?.()}</button>

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

  .solid {
    background: var(--accent);
    color: var(--on-accent);
    /* Светлое на тёмном кажется жирнее — ступень вниз выравнивает. */
    font-weight: calc(500 + var(--on-accent-weight));
  }

  .ghost {
    background: transparent;
    color: var(--cream);
    box-shadow: inset 0 0 0 0.5px rgba(244, 237, 229, 0.4);
  }

  .quiet {
    background: transparent;
    color: var(--dim-4);
    box-shadow: inset 0 0 0 0.5px rgba(244, 237, 229, 0.22);
  }

  .roomy {
    padding: 5px 9px;
    border-radius: 4px;
  }
</style>
