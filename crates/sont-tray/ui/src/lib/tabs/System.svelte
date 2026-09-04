<!--
  Вкладка настроек приложения: интерфейс, версии и данные.

  Раздела «запуск» здесь больше нет. В нём стоял один переключатель —
  автозапуск агента сеанса, — и он был ловушкой: выключенный, он тихо ломал
  режим прокси (настройки системы становилось некому обновлять), а включённый
  не давал ничего сверх того, что и так происходит само. Настройка, у которой
  одно осмысленное положение, а второе портит работу, интерфейсу не нужна;
  агентом по-прежнему можно управлять из CLI — `sontd agent install`.
-->
<script>
  import Section from "../Section.svelte";
  import Row from "../Row.svelte";
  import BoxedRow from "../BoxedRow.svelte";
  import Toggle from "../Toggle.svelte";
  import Segmented from "../Segmented.svelte";
  import Button from "../Button.svelte";
  import { settings, info, patch, act } from "../daemon.js";
  import { t } from "../i18n.js";

  const LANGS = [
    { value: "ru", label: "RU" },
    { value: "en", label: "EN" },
  ];

  // Порядок не алфавитный: «как в системе» стоит первым, потому что это
  // значение по умолчанию, и с него начинается выбор. Дальше — от светлого к
  // тёмному, как в самих параметрах Windows.
  const THEMES = $derived([
    { value: "system", label: $t("theme.system") },
    { value: "light", label: $t("theme.light") },
    { value: "dark", label: $t("theme.dark") },
  ]);
</script>

<Section title={$t("sec.interface")} />

<Row title={$t("lang.title")}>
  <Segmented options={LANGS} value={$settings.language} onselect={(v) => patch({ language: v })} />
</Row>

<Row title={$t("theme.title")}>
  <Segmented
    options={THEMES}
    value={$settings.theme ?? "system"}
    onselect={(v) => patch({ theme: v })}
  />
</Row>

<Row title={$t("accent.title")} hint={$t("accent.hint")}>
  <Toggle
    label={$t("accent.title")}
    on={$settings.system_accent}
    onchange={(v) => patch({ system_accent: v })}
  />
</Row>

<Row title={$t("dns.title")} hint={$t("dns.hint")}>
  <Toggle
    label={$t("dns.title")}
    on={$settings.dns.block_plain_dns}
    onchange={(v) => patch({ dns: { ...$settings.dns, block_plain_dns: v } })}
  />
</Row>

<Section title={$t("sec.data")} rule />

<!--
  Между именем и версией неразрывный пробел: «Sont 0.1.0» — одно целое, и
  перенос посреди него превращал короткую подпись в две строки-огрызка.
-->
<BoxedRow label={$info ? `Sont ${$info.daemon_version}` : "—"}>
  <span class="aside">{$info?.core_version ?? "—"}</span>
</BoxedRow>

<div class="buttons">
  <Button variant="ghost" onclick={() => act("open_logs")}>{$t("btn.logs")}</Button>
  <Button variant="ghost" onclick={() => act("probe")}>{$t("btn.check")}</Button>
  <span class="spacer"></span>
  <Button variant="quiet" onclick={() => act("quit")}>{$t("btn.quit")}</Button>
</div>

<style>
  .buttons {
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .spacer {
    margin-left: auto;
  }
  /*
   * Строка версий переносится по словам и выравнивается по правому краю.
   *
   * Ядро представляется целой фразой — «Xray 26.3.27 (Xray, Penetrates
   * Everything.) d2758a0 (go1.26.1 windows/amd64)», — и в одну строку она не
   * встанет ни при какой ширине окна.
   */
  .aside {
    font-size: 9px;
    font-weight: 400;
    line-height: 140%;
    text-align: right;
    text-wrap: pretty;
    color: var(--dim-4);
  }
</style>
