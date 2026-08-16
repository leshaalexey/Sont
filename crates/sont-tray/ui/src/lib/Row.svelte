<!--
  Строка настройки: заголовок, пояснение и контрол справа.

  Пояснение необязательно — в макете часть строк без него, и лишний пустой
  отступ там был бы заметен.
-->
<script>
  let { title, hint = null, children } = $props();
</script>

<div class="row">
  <div class="text">
    <span class="title">{title}</span>
    {#if hint}<span class="hint">{hint}</span>{/if}
  </div>
  {@render children?.()}
</div>

<style>
  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 0 0 12px;
  }

  /*
   * Текст занимает всё свободное место и жмётся сам, а контрол справа —
   * нет: `min-width: 0` снимает неявный минимум flex-элемента, без которого
   * длинное пояснение распирало бы строку вместо того, чтобы перенестись.
   */
  .text {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 3px;
    min-width: 0;
  }

  .title {
    font-size: 10px;
    font-weight: 400;
    line-height: 125%;
    color: var(--cream);
  }

  /*
   * Пояснение переносится по словам. Раньше оно было однострочным и на
   * узком окне просто обрывалось — фраза «Смена сервера рвёт все соединения,
   * поэтому только при заметной разнице» доходила до «Смена сервера рвёт».
   * Пояснение, из которого не видно главного, хуже отсутствующего.
   *
   * Начертание — чуть плотнее прежних трёхсот, но легче заголовка строки:
   * сравнявшись с ним в четырёхстах, пояснение перестаёт читаться
   * пояснением. Segoe UI Variable возьмёт промежуточное начертание, шрифт
   * без переменной оси округлит до ближайшего.
   */
  .hint {
    font-size: 8px;
    font-weight: 350;
    line-height: 135%;
    color: var(--dim-3);
    text-wrap: pretty;
  }
</style>
