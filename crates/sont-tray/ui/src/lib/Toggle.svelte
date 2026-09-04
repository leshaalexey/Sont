<!-- Переключатель из макета: 19×10, кружок ездит влево-вправо. -->
<script>
  // Подпись не рисуется — она уже стоит слева в строке. Нужна она
  // программам чтения с экрана: иначе переключатель для них безымянный.
  let { on = false, label = "", onchange } = $props();
</script>

<button
  class="toggle"
  class:on
  role="switch"
  aria-checked={on}
  aria-label={label}
  onclick={() => onchange?.(!on)}
>
  <span class="track"></span>
  <span class="knob"></span>
</button>

<style>
  /*
   * Размеры — 27 × 15 вместо макетных 19 × 10.
   *
   * Макет рисовался под просмотр в двойном увеличении, а окно живёт в
   * полуторном: переключатель выходил мельче всего, во что в нём тычут, и
   * промахнуться по нему было проще, чем попасть. Ход кружка при этом
   * считается от габаритов, а не задан отдельным числом, — иначе он снова
   * разъедется с рамкой при первой же правке размера.
   */
  .toggle {
    position: relative;
    flex: none;
    width: 27px;
    height: 15px;
    padding: 0;
    border: 0;
    border-radius: 9px;
    background: transparent;
    overflow: hidden;
    cursor: pointer;
  }

  .track {
    position: absolute;
    left: 1px;
    top: 1px;
    width: 25px;
    height: 13px;
    border-radius: 8px;
    background: rgba(var(--fg-rgb), 0.1);
    transition: background 180ms var(--ease);
  }

  .knob {
    position: absolute;
    /*
     * Кружок вписан в наружный контур: зазор одинаков со всех сторон, и его
     * окружность получается тем же скруглением корпуса, отступившим внутрь.
     *
     * Отсюда и тройка. Корпус 27 × 15, радиус наружного контура — половина
     * высоты, 7,5; кружок девять точек, радиус 4,5. Разница 3 — это и есть
     * зазор, и он обязан быть таким же по бокам, иначе кружок перестаёт быть
     * соосным контуру и начинает болтаться внутри пилюли.
     */
    left: 3px;
    top: 3px;
    width: 9px;
    height: 9px;
    border-radius: 6px;
    background: rgba(var(--fg-rgb), 0.55);
    transition: transform 180ms var(--ease), background 180ms var(--ease);
  }

  .on .track {
    background: var(--accent);
  }
  .on .knob {
    background: var(--on-accent);
    /* 27 − 3 слева − 9 ширина кружка − 3 справа. */
    transform: translateX(12px);
  }
</style>
