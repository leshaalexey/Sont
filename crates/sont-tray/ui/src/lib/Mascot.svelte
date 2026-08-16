<!--
  Маскот из макета, экспорт из Figma. Цвет берётся от `currentColor`, поэтому
  один и тот же рисунок годится и для тёмной шапки, и для светлой вкладки.
-->
<script>
  let { size = 15 } = $props();
</script>

<svg
  class="mascot"
  width={size}
  height={(size / 15) * 13}
  viewBox="0 0 15 13"
  fill="currentColor"
  shape-rendering="crispEdges"
>
  <path d="M5 3H3V4H5V3Z" /><path d="M12 3H10V4H12V3Z" />
  <path d="M3 4H2V5H3V4Z" /><path d="M13 4H12V5H13V4Z" />
  <path d="M2 5H1V6H2V5Z" /><path d="M14 5H13V6H14V5Z" />
  <path d="M2 6H1V7H2V6Z" /><path d="M11 6H4V7H11V6Z" /><path d="M14 6H13V7H14V6Z" />
  <path d="M2 7H1V8H2V7Z" /><path d="M12 7H3V8H12V7Z" /><path d="M14 7H13V8H14V7Z" />
  <path d="M14 8H1V9H14V8Z" />
  <path d="M4 9H1V10H4V9Z" /><path d="M10 9H5V10H10V9Z" /><path d="M14 9H11V10H14V9Z" />
  <path d="M14 10H1V11H14V10Z" />
  <path d="M13 11H2V12H13V11Z" />
  <path d="M4 12H2V13H4V12Z" /><path d="M7 12H5V13H7V12Z" />
  <path d="M10 12H8V13H10V12Z" /><path d="M13 12H11V13H13V12Z" />
  <path d="M5 2V1L6 1V2H5Z" /><path d="M6 1V0L7 0V1L6 1Z" />
  <path d="M7 2V1L8 1V2H7Z" /><path d="M8 2V1L9 1V2H8Z" /><path d="M9 2V1L10 1V2H9Z" />
  <path d="M8 3V2H9V3H8Z" /><path d="M6 3V2H7V3H6Z" />
</svg>

<style>
  .mascot {
    display: block;
  }
</style>
