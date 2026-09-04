<!--
  Вкладка «поведение дирижёра»: чем демон руководствуется, выбирая сервер и
  удерживая соединение.
-->
<script>
  import Section from "../Section.svelte";
  import Row from "../Row.svelte";
  import BoxedRow from "../BoxedRow.svelte";
  import Toggle from "../Toggle.svelte";
  import Segmented from "../Segmented.svelte";
  import Stepper from "../Stepper.svelte";
  import SplitTunnel from "../SplitTunnel.svelte";
  import { settings, patch } from "../daemon.js";
  import { t } from "../i18n.js";

  // Раздельное туннелирование живёт отдельной страницей этой же вкладки:
  // правило состоит из режима и растущего списка путей, и в строку настроек
  // такое не убирается.
  let page = $state("main");

  const INTERVALS = [
    { value: 30, label: "30 s" },
    { value: 60, label: "1 m" },
    { value: 300, label: "5 m" },
  ];

  const MODES = [
    { value: "tunnel", label: "Tunnel" },
    { value: "proxy", label: "Proxy" },
  ];

  // Пустое значение — «любой протокол»: демон трактует пустой список как «все».
  const PROTOCOLS = [
    { value: "", label: "Auto" },
    { value: "vless", label: "VLESS" },
    { value: "vmess", label: "VMess" },
    { value: "shadowsocks", label: "SS" },
  ];

  // Подписи переводятся, значения уходят демону как есть — это варианты
  // `FirewallMode`.
  const FIREWALL = $derived([
    { value: "off", label: $t("fw.off") },
    { value: "auto", label: $t("fw.auto") },
    { value: "lockdown", label: $t("fw.lockdown") },
  ]);

  // Считаем и программы, и сайты: строка — вход на страницу, и число в ней
  // должно совпадать с тем, что там лежит. Пока считались одни программы,
  // список из трёх сайтов показывался как «0».
  const listed = $derived(
    ($settings?.split_tunnel?.apps?.length ?? 0) + ($settings?.split_tunnel?.sites?.length ?? 0),
  );
</script>

{#if page === "split"}
  <SplitTunnel onback={() => (page = "main")} />
{:else}
  <Section title={$t("sec.latency")} />

  <Row title={$t("autoSwitch.title")} hint={$t("autoSwitch.hint")}>
    <Toggle label={$t("autoSwitch.title")} on={$settings.auto_switch} onchange={(v) => patch({ auto_switch: v })} />
  </Row>

  <BoxedRow label={$t("threshold.title")}>
    <Stepper
      value={$settings.switch_threshold_ms}
      step={10}
      min={10}
      max={500}
      suffix=" ms"
      onchange={(v) => patch({ switch_threshold_ms: v })}
    />
  </BoxedRow>

  <Row title={$t("interval.title")} hint={$t("interval.hint")}>
    <Segmented
      options={INTERVALS}
      value={$settings.probe_interval_secs}
      onselect={(v) => patch({ probe_interval_secs: v })}
    />
  </Row>

  <Section title={$t("sec.connection")} rule />

  <Row title={$t("autoConnect.title")} hint={$t("autoConnect.hint")}>
    <Toggle label={$t("autoConnect.title")} on={$settings.auto_connect} onchange={(v) => patch({ auto_connect: v })} />
  </Row>

  <Row title={$t("mode.title")} hint={$t("mode.hint")}>
    <Segmented options={MODES} value={$settings.mode} onselect={(v) => patch({ mode: v })} />
  </Row>

  <Row title={$t("protocol.title")} hint={$t("protocol.hint")}>
    <Segmented
      options={PROTOCOLS}
      value={$settings.preferred_transports[0] ?? ""}
      onselect={(v) => patch({ preferred_transports: v ? [v] : [] })}
    />
  </Row>

  <!--
    Локальная сеть стоит рядом с режимом, а не в разделе про обрыв: это правило
    маршрутизации — куда пускать трафик, пока туннель работает. Ниже, в «при
    обрыве», живёт запрет — что делать, когда туннеля нет. Раньше они стояли
    вместе и читались как одна настройка, сказанная дважды.
  -->
  <Row title={$t("allowLan.title")} hint={$t("allowLan.hint")}>
    <Toggle label={$t("allowLan.title")} on={$settings.allow_lan} onchange={(v) => patch({ allow_lan: v })} />
  </Row>

  <BoxedRow label={$t("split.title")} clickable onclick={() => (page = "split")}>
    <span class="aside">{listed} {$t("split.count")} ›</span>
  </BoxedRow>

  <Section title={$t("sec.ondrop")} rule />

  <Row title={$t("killSwitch.title")} hint={$t("killSwitch.hint")}>
    <Segmented
      options={FIREWALL}
      value={$settings.firewall}
      onselect={(v) => patch({ firewall: v })}
    />
  </Row>

  <BoxedRow label={$t("attempts.title")}>
    <Stepper
      value={$settings.reconnect_attempts}
      min={1}
      max={9}
      onchange={(v) => patch({ reconnect_attempts: v })}
    />
  </BoxedRow>

{/if}

<style>
  /* Приписка нажимаемой строки — той же яркости, что и её подпись: гасить
     половину строки, которую предлагают нажать, незачем. */
  .aside {
    font-size: 9px;
    font-weight: 400;
    line-height: 130%;
    white-space: nowrap;
    color: var(--dim-2);
  }
</style>
