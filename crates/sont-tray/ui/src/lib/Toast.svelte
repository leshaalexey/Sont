<!-- Короткое сообщение внизу окна: «ключ скопирован», ошибка запроса. -->
<script>
  import { notice } from "./daemon.js";
</script>

{#if $notice}
  <div class="toast" class:error={$notice.isError}>{$notice.text}</div>
{/if}

<style>
  .toast {
    position: absolute;
    left: 11px;
    right: 11px;
    bottom: 6px;
    padding: 4px 6px;
    border-radius: 4px;
    background: var(--accent);
    color: var(--on-accent);
    font-size: 9px;
    font-weight: 500;
    line-height: 120%;
    text-align: center;
  }

  .error {
    background: var(--alarm);
  }
</style>
