<!--
  Рисунок для оборванного соединения. Тот же экспорт из Figma, что и у
  маскота, и так же красится currentColor.
-->
<script>
  let { size = 21 } = $props();
</script>

<svg
  class="offline"
  width={size}
  height={(size / 21) * 7}
  viewBox="0 0 21 7"
  fill="currentColor"
  shape-rendering="crispEdges"
>
  <path d="M14 0H7V1H14V0Z" />
  <path d="M15 1H6V2H15V1Z" />
  <path d="M16 2H5V3H16V2Z" />
  <path d="M7 3H5V4H7V3Z" />
  <path d="M13 3H8V4H13V3Z" />
  <path d="M16 3H14V4H16V3Z" />
  <path d="M16 4H5V5H16V4Z" />
  <path d="M16 5H5V6H16V5Z" />
  <path d="M7 6H1V7H7V6Z" />
  <path d="M10 6H8V7H10V6Z" />
  <path d="M13 6H11V7H13V6Z" />
  <path d="M19 6H14V7H19V6Z" />
</svg>

<style>
  .offline {
    display: block;
  }
</style>
