<!--
  Переключатель из нескольких значений. Варианты приходят парами
  «значение — подпись»: подпись переводится, значение уходит демону как есть.
-->
<script>
  let { options = [], value, onselect } = $props();
</script>

<div class="segmented">
  {#each options as option (option.value)}
    <button
      class="seg"
      class:active={option.value === value}
      onclick={() => onselect?.(option.value)}
    >
      {option.label}
    </button>
  {/each}
</div>

<style>
  .segmented {
    display: flex;
    gap: 2px;
    padding: 2px;
    border-radius: 5px;
    background: var(--bg-sunken);
    box-shadow: inset 0 0 0 0.5px var(--line-strong);
  }

  .seg {
    padding: 2.5px 6px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    color: rgba(244, 237, 229, 0.62);
    font-family: inherit;
    font-size: 9px;
    font-weight: 500;
    line-height: 100%;
    white-space: nowrap;
    cursor: pointer;
  }

  .active {
    background: var(--accent);
    color: var(--on-accent);
  }
</style>
