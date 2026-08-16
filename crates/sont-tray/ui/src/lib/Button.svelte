<!-- Кнопка макета в трёх видах: сплошная, контурная и приглушённая. -->
<script>
  let { variant = "solid", onclick, children } = $props();
</script>

<button class="btn {variant}" {onclick}>{@render children?.()}</button>

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
</style>
