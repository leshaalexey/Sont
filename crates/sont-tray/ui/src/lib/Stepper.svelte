<!-- Счётчик «минус — значение — плюс» из макета. -->
<script>
  let { value, step = 1, min = 1, max = 99, suffix = "", onchange } = $props();

  const clamp = (v) => Math.min(max, Math.max(min, v));
</script>

<!--
  Знак минус — «−» (U+2212), а не тире.

  Тире рисуется по высоте строчных букв и рядом с плюсом сидит заметно ниже
  него; минус в любом шрифте нарисован на той же высоте, что и перекладина
  плюса, — именно ради пары с ним он и заведён.
-->
<span class="stepper">
  <button onclick={() => onchange?.(clamp(value - step))} disabled={value <= min}>−</button>
  <span class="value tnum">{value}{suffix}</span>
  <button onclick={() => onchange?.(clamp(value + step))} disabled={value >= max}>+</button>
</span>

<style>
  .stepper {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  /*
   * Знак центрируется флексом, а не подобранной высотой строки.
   *
   * Раньше стояло `line-height` в точках — число, верное ровно для одного
   * размера шрифта. От первой же его правки минус уезжал вверх, а плюс, у
   * которого другая высота знака, — вниз, и кнопки переставали выглядеть
   * парой.
   */
  button {
    width: 14px;
    height: 14px;
    padding: 0;
    border: 0;
    border-radius: 3px;
    background: rgba(244, 237, 229, 0.12);
    color: var(--cream);
    font-family: inherit;
    font-size: 10px;
    line-height: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }
  button:disabled {
    opacity: 0.35;
    cursor: default;
  }

  .value {
    min-width: 28px;
    text-align: center;
    font-size: 10px;
    font-weight: 500;
    line-height: 130%;
    color: var(--cream);
  }
</style>
