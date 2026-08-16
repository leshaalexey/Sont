<!-- Заголовок раздела. Справа необязательная приписка вроде «3 ключей». -->
<script>
  let { title, aside = null, rule = false } = $props();
</script>

{#if rule}<hr />{/if}
<div class="head" class:spaced={aside != null}>
  <h2>{title}</h2>
  {#if aside != null}<span class="aside">{aside}</span>{/if}
</div>

<style>
  hr {
    height: 1px;
    margin: 0;
    border: 0;
    background: var(--line-weak);
  }

  /*
   * Заголовок раздела, идущий не первым, отодвигается сверху — с линейкой
   * или без неё. Раньше отступ давала только линейка, и раздел без неё
   * прилипал к предыдущему блоку: «Сохранённые ключи» начинались вплотную к
   * карточке подписки и читались её частью.
   */
  .head {
    padding: 2px 0 8px;
  }
  .head:not(:first-child),
  hr + .head {
    padding-top: 16px;
  }
  .spaced {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
  }

  h2 {
    margin: 0;
    font-size: 8px;
    font-weight: 500;
    letter-spacing: 0.7px;
    line-height: 100%;
    text-transform: uppercase;
    color: var(--dim-5);
  }

  .aside {
    font-size: 8px;
    font-weight: 300;
    line-height: 100%;
    color: rgba(244, 237, 229, 0.4);
  }
</style>
