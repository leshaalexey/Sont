<!--
  Строка в рамке: подпись слева, содержимое справа.

  Нажимаемый вариант — настоящая кнопка, а не `div` с ролью: так он сам
  получает фокус, клавиатуру и правильное чтение вслух.
-->
<script>
  let { label = "", dashed = false, clickable = false, onclick, children } = $props();
</script>

{#if clickable}
  <button class="boxed as-button outlined" class:dashed {onclick}>
    {#if label}<span class="label">{label}</span>{/if}
    {@render children?.()}
  </button>
{:else}
  <div class="boxed" class:dashed>
    {#if label}<span class="label">{label}</span>{/if}
    {@render children?.()}
  </div>
{/if}

<style>
  /*
   * Высота не задана, задан минимум и поля.
   *
   * Раньше стояло жёсткое число, и содержимое, которому не хватило строки,
   * упиралось в рамку: строка с версиями — «Xray 26.3.27 (Xray, Penetrates
   * Everything.) d2758a0 (go1.26.1 windows/amd64)» — переносилась на две
   * строки и вылезала за коробку. Коробка обязана расти под своё содержимое,
   * а не наоборот.
   */
  .boxed {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    width: 100%;
    min-height: 26px;
    border: 0.5px solid var(--line-strong);
    border-radius: 5px;
    padding: 7px 9px 7px 11px;
    margin-bottom: 8px;
    background: transparent;
    font-family: inherit;
    text-align: left;
  }

  /*
   * Пунктир штатный.
   *
   * До этого он рисовался отдельной фигурой ради управления длиной штриха —
   * получилось точнее, но заметно жирнее и суше соседних рамок. Обычный
   * `dashed` в одну точку встаёт в один ряд с ними, а шаг штриха браузер
   * выбирает сам и одинаково на всех четырёх сторонах.
   */
  .dashed {
    border: 1px dashed var(--line-strong);
    margin-top: 8px;
    padding-right: 7px;
  }

  /*
   * Нажимаемая строка светлее неподвижных.
   *
   * Раньше она выглядела ровно как соседние — «насколько быстрее» и «попыток
   * до смены сервера», — но те менялись на месте, а эта уводит на отдельную
   * страницу. Одинаковый вид у строки, которую нажимают, и у строки, которую
   * не нажимают, — это предложение выяснять разницу опытным путём.
   *
   * Ярче и рамка, и подпись, и стрелка справа: по отдельности каждый признак
   * слаб, вместе читаются сразу.
   */
  .as-button {
    cursor: pointer;
    padding-right: 11px;
    border-color: rgba(var(--fg-rgb), 0.45);
  }

  .as-button .label {
    color: var(--fg);
  }

  .label {
    font-size: 9px;
    font-weight: 400;
    line-height: 130%;
    color: var(--dim-2);
  }
</style>
